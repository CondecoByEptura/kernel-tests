#!/usr/bin/python
#
# Copyright 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from errno import * # pylint: disable=wildcard-import
from socket import *  # pylint: disable=wildcard-import
import ctypes
import fcntl
import os
import random
import select
import termios
import threading
import time
from scapy import all as scapy

import multinetwork_base
import net_test
import packets

SOL_TCP = net_test.SOL_TCP

TEST_PORT = 5555

TCP_REPAIR_OFF =0
TCP_REPAIR_ON = 1

TCP_REPAIR = 19
TCP_REPAIR_QUEUE = 20
TCP_QUEUE_SEQ = 21
TCP_REPAIR_OPTIONS = 22

TCP_NO_QUEUE=0
TCP_RECV_QUEUE=1
TCP_SEND_QUEUE=2
TCP_QUEUES_NR=3

SIOCINQ = termios.FIONREAD
SIOCOUTQ = termios.TIOCOUTQ

class TcpRepairTest(multinetwork_base.MultiNetworkBaseTest):

  def assertSocketNotConnected(self, sock):
    self.assertRaisesErrno(ENOTCONN, sock.getpeername)

  def assertSocketConnected(self, sock):
    sock.getpeername()  # No errors? Socket is alive and connected.

  def createConnectedSocket(self, version, netid):
    ip_layer = {4: scapy.IP, 6: scapy.IPv6}[version]
    s = net_test.TCPSocket(net_test.GetAddressFamily(version))
    net_test.DisableFinWait(s)
    self.SelectInterface(s, netid, "mark")

    remoteaddr = self.GetRemoteAddress(version)
    with self.assertRaisesErrno(EINPROGRESS):
      s.connect((remoteaddr, TEST_PORT))
    self.assertSocketNotConnected(s)

    myaddr = self.MyAddress(version, netid)
    port = s.getsockname()[1]
    self.assertNotEqual(0, port)

    desc, expect_syn = packets.SYN(TEST_PORT, version, myaddr, remoteaddr, port, seq=None)
    msg = "socket connect: expected %s" % desc
    syn = self.ExpectPacketOn(netid, msg, expect_syn)
    synack_desc, synack = packets.SYNACK(version, remoteaddr, myaddr, syn)
    synack.getlayer("TCP").seq = random.getrandbits(32)
    synack.getlayer("TCP").window=14400
    self.ReceivePacketOn(netid, synack)
    desc, ack = packets.ACK(version, myaddr, remoteaddr, synack)
    msg = "socket connect: got SYN+ACK, expected %s" % desc
    ack = self.ExpectPacketOn(netid, msg, ack)
    self.last_sent = ack;
    self.last_received = synack
    return s

  def receiveFin(self, netid, version, sock):
    self.assertSocketConnected(sock)
    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)
    desc, fin = packets.FIN(version, remoteaddr, myaddr, self.last_sent)
    self.ReceivePacketOn(netid, fin)
    self.last_received = fin

  def sendData(self, netid, version, sock, payload):
    sock.send(payload)

    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)
    desc, send = packets.ACK(version, myaddr, remoteaddr,
                             self.last_received, payload)
    self.last_sent = send

  def receiveData(self, netid, version, payload):
    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)

    desc, received = packets.ACK(version, remoteaddr, myaddr,
                                 self.last_sent, payload)
    ack_desc, ack = packets.ACK(version, myaddr, remoteaddr, received)
    self.ReceivePacketOn(netid, received)
    time.sleep(0.1)
    self.ExpectPacketOn(netid, "expecting %s" % ack_desc, ack)
    self.last_sent = ack
    self.last_received = received

  def testTcpRepairWithNoQueue(self):
    print "testTcpRepairWithNoQueue"
    self.tcpRepairWithNoQueue(4)
    self.tcpRepairWithNoQueue(6)

  def tcpRepairWithNoQueue(self, version):
    netid = self.RandomNetid()
    sock = self.createConnectedSocket(version, netid)
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)

    # In repair mode with NO_QUEUE, writes fail...
    with self.assertRaisesErrno(EINVAL):
      sock.send("write test")

    # remote data is coming.
    TEST_RECEIVED = net_test.UDP_PAYLOAD
    self.receiveData(netid, version, TEST_RECEIVED)

    # In repair mode with NO_QUEUE, read fail...
    with self.assertRaisesErrno(EPERM):
      data = sock.recv(4096)

    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_OFF)
    readData = sock.recv(4096)
    self.assertEquals(readData, TEST_RECEIVED)

  def testGetSequenceNumber(self):
    print "testGetSequenceNumber"
    self.GetSequenceNumberTestByVersion(4)
    self.GetSequenceNumberTestByVersion(6)

  def GetSequenceNumberTestByVersion(self, version):
    netid = self.RandomNetid()
    sock = self.createConnectedSocket(version, netid)
    # test write queue sequnce number
    sequence_before = self.GetWriteSequenceNumberByQueueSeq(version, sock)
    expect_sequence = self.last_sent.getlayer("TCP").seq
    self.assertEquals(sequence_before & 0xffffffff, expect_sequence)
    TEST_SEND = net_test.UDP_PAYLOAD
    self.sendData(netid, version, sock, TEST_SEND)
    sequence_after = self.GetWriteSequenceNumberByQueueSeq(version, sock)
    self.assertEquals(sequence_before + len(TEST_SEND), sequence_after)

    # test read queue sequnce number
    sequence_before = self.GetReadSequenceNumberByQueueSeq(version, sock)
    expect_sequence = self.last_received.getlayer("TCP").seq + 1
    self.assertEquals(sequence_before & 0xffffffff, expect_sequence)
    TEST_READ = net_test.UDP_PAYLOAD
    self.receiveData(netid, version, TEST_READ)
    sequence_after = self.GetReadSequenceNumberByQueueSeq(version, sock)
    self.assertEquals(sequence_before + len(TEST_READ), sequence_after)

  def GetWriteSequenceNumberByQueueSeq(self, version, sock):
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)
    sock.setsockopt(SOL_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
    sequence = sock.getsockopt(SOL_TCP, TCP_QUEUE_SEQ)
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_OFF)
    return sequence

  def GetReadSequenceNumberByQueueSeq(self, version, sock):
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)
    sock.setsockopt(SOL_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
    sequence = sock.getsockopt(SOL_TCP, TCP_QUEUE_SEQ)
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_OFF)
    return sequence

  def testPollWhenShutdown(self):
    print "testPollWhenShutdown"
    self.multiPollWhenShutdown(4)
    self.multiPollWhenShutdown(6)

  def setupRepairSocketWithPoll(self, netid, version, expected):
    sock = self.createConnectedSocket(version, netid)
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)

    multiThreads = []
    for i in range(0, 2):
      thread = SocketExceptionThread(sock, lambda sk: self.fdSelect(sock, expected))
      thread.start()
      thread.join(1)
      self.assertTrue(thread.is_alive())
      multiThreads.append(thread)

    return sock, multiThreads

  def multiPollWhenShutdown(self, version):
    netid = self.RandomNetid()
    expected = select.POLLIN
    sock, multiThreads = self.setupRepairSocketWithPoll(netid, version, expected)
    # Test shdown RD.
    sock.shutdown(net_test.SHUT_RD)
    time.sleep(0.1)
    for thread in multiThreads:
      if (thread.is_alive()):
        thread.stop()
        raise AssertionError("poll fail in SHUT_RD")

    expected = select.POLLOUT
    sock, multiThreads = self.setupRepairSocketWithPoll(netid, version, expected)
    # Test shdown WR.
    sock.shutdown(net_test.SHUT_WR)
    time.sleep(0.1)
    for thread in multiThreads:
      if (thread.is_alive()):
        thread.stop()
      else :
        raise AssertionError("poll fail in SHUT_WR")

    expected = select.POLLIN | select.POLLHUP
    sock, multiThreads = self.setupRepairSocketWithPoll(netid, version, expected)
    # Test shdown RDWR.
    sock.shutdown(net_test.SHUT_RDWR)
    time.sleep(0.1)
    for thread in multiThreads:
      if (thread.is_alive()):
        thread.stop()
        raise AssertionError("poll fail in SHUT_RDWR")


  def testMultiThreadPollWhenFin(self):
    print "testMultiThreadPollWhenFin"
    self.multiPollWhenFin(4)
    self.multiPollWhenFin(6)

  def multiPollWhenFin(self, version):
    netid = self.RandomNetid()
    expected = select.POLLIN
    sock, multiThreads = self.setupRepairSocketWithPoll(netid, version, expected)
    self.receiveFin(netid, version, sock)
    time.sleep(0.1)
    for thread in multiThreads:
      if (thread.is_alive()):
        thread.stop()
        raise AssertionError("poll fail in FIN")

  def testSocketIdle(self):
    print "testSocketIdle"
    self.readQueueIdleTest(4)
    self.readQueueIdleTest(6)
    self.writeQueueIdleTest(4)
    self.writeQueueIdleTest(6)

  def readQueueIdleTest(self, version):
    netid = self.RandomNetid()
    sock = self.createConnectedSocket(version, netid)

    buf = ctypes.c_int()
    fcntl.ioctl(sock, SIOCINQ, buf)
    self.assertEquals(buf.value, 0)

    TEST_RECEIVED = net_test.UDP_PAYLOAD
    self.receiveData(netid, version, TEST_RECEIVED)
    fcntl.ioctl(sock, SIOCINQ, buf)
    self.assertEquals(buf.value, len(TEST_RECEIVED))

  def writeQueueIdleTest(self, version):
    netid = self.RandomNetid()
    # Setup a connected socket, write queue is empty.
    sock = self.createConnectedSocket(version, netid)
    buf = ctypes.c_int()
    fcntl.ioctl(sock, SIOCOUTQ, buf)
    self.assertEquals(buf.value, 0)
    # Change to repair mode with SEND_QUEUE, writing some data to the queue.
    sock.setsockopt(SOL_TCP, TCP_REPAIR, TCP_REPAIR_ON)
    TEST_SEND = net_test.UDP_PAYLOAD
    sock.setsockopt(SOL_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
    self.sendData(netid, version, sock, TEST_SEND)
    fcntl.ioctl(sock, SIOCOUTQ, buf)
    self.assertEquals(buf.value, len(TEST_SEND))

    # Setup a connected socket again.
    netid = self.RandomNetid()
    sock = self.createConnectedSocket(version, netid)
    # Send out some data and don't receive ACK yet.
    self.sendData(netid, version, sock, TEST_SEND)
    fcntl.ioctl(sock, SIOCOUTQ, buf)
    self.assertEquals(buf.value, len(TEST_SEND))
    # Receive response ACK.
    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)
    desc_ack, ack = packets.ACK(version, remoteaddr, myaddr, self.last_sent)
    self.ReceivePacketOn(netid, ack)
    fcntl.ioctl(sock, SIOCOUTQ, buf)
    self.assertEquals(buf.value, 0)


  def fdSelect(self, sock, expected):
    READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR | select.POLLNVAL
    p = select.poll()
    p.register(sock, READ_ONLY)
    events = p.poll()
    for fd,event in events:
      if fd == sock.fileno():
        self.assertEquals(event, expected)
      else:
        raise AssertionError("unexpected poll fd")

class SocketExceptionThread(threading.Thread):

  def __init__(self, sock, operation):
    self.exception = None
    super(SocketExceptionThread, self).__init__()
    self.daemon = True
    self.sock = sock
    self.operation = operation

  def stop(self):
    self._Thread__stop()

  def run(self):
    try:
      self.operation(self.sock)
    except (IOError, AssertionError), e:
      self.exception = e

if __name__ == '__main__':
  unittest.main()
