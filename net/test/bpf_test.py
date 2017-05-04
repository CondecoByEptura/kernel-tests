#!/usr/bin/python
#
# Copyright 2016 The Android Open Source Project
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

import ctypes
import errno
import os
import socket
import struct
import unittest

from bpf import *  # pylint: disable=wildcard-import
import csocket
import net_test
import sock_diag

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)
HAVE_CGROUP_HELPER_SUPPORT = net_test.LINUX_VERSION >= (4, 9, 0)
KEY_SIZE = 8;
VALUE_SIZE = 4;
TOTAL_ENTRIES = 20;

@unittest.skipUnless(HAVE_EBPF_SUPPORT,
                     "eBPF function not fully supported")
class BpfTest(net_test.NetworkTest):


  def setUp(self):
    self.map_fd = -1
    self.prog_fd = -1

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    if hasattr(self, 'sock'):
      self.sock.close()

  # A dummy loopback function to generate traffic through a socket.
  def socketLoopBackWithFilter(self, packet_count, version):
    family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
    self.sock = socket.socket(family, socket.SOCK_DGRAM, 0)
    BpfProgAttachSocket(self.sock.fileno(), self.prog_fd)
    net_test.SetNonBlocking(self.sock)
    addr = {4: "127.0.0.1", 6: "::1"}[version]
    self.sock.bind((addr, 0))
    addr = self.sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    for i in xrange(packet_count):
      self.sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(self.sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)

  def testCreateMap(self):
    key, value = 1, 1
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    UpdateMap(self.map_fd, key, value)
    self.assertEquals(LookupMap(self.map_fd, key).value, value)
    DeleteMap(self.map_fd, key)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, key)

  def testIterateMap(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    value = 1024
    for key in xrange(1, TOTAL_ENTRIES):
      UpdateMap(self.map_fd, key, value)
    for key in xrange(1, TOTAL_ENTRIES):
      self.assertEquals(LookupMap(self.map_fd, key).value, value)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, 101)
    key = 0
    count = 0
    while 1:
      if count == TOTAL_ENTRIES - 1:
        self.assertRaisesErrno(errno.ENOENT, GetNextKey, self.map_fd, key)
        break
      else:
        result = GetNextKey(self.map_fd, key)
        key = result.value
        self.assertGreater(key, 0)
        self.assertEquals(LookupMap(self.map_fd, key).value, value)
        count += 1

  def testProgLoad(self):
    # Move skb to BPF_REG_6 for further usage
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    ]
    instructions += insSkFilterAccept
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    self.socketLoopBackWithFilter(1, 4)
    self.socketLoopBackWithFilter(1, 6)

  def testPacketBlock(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, insBpfExitBlock)
    self.assertRaisesErrno(errno.EAGAIN, self.socketLoopBackWithFilter, 1, 4)
    self.assertRaisesErrno(errno.EAGAIN, self.socketLoopBackWithFilter, 1, 6)

  def testPacketCount(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    key = 0xf0f0
    # Set up instruction block with key loaded at BPF_REG_0.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfMov64Imm(BPF_REG_0, key)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insSkFilterAccept
                     + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    self.socketLoopBackWithFilter(packet_count, 4)
    self.socketLoopBackWithFilter(packet_count, 6)
    self.assertEquals(LookupMap(self.map_fd, key).value, packet_count*2)

  @unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                       "BPF helper function is not fully supported")
  def testGetSocketCookie(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_cookie)
    ]
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insSkFilterAccept
                     + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10;
    # Test the program with IPv4.
    self.socketLoopBackWithFilter(packet_count, 4)
    self.sock_diag = sock_diag.SockDiag()
    real_cookie = self.sock_diag.FindSockDiagFromFd(self.sock).id.cookie
    cookie = struct.unpack('=Q', real_cookie)[0]
    self.assertEquals(LookupMap(self.map_fd, cookie).value, packet_count)
    self.sock.close()
    # Test the program with IPv6, it uses a different socket to do the loopback
    # so the socket cookie will be different.
    self.socketLoopBackWithFilter(packet_count, 6)
    self.sock_diag = sock_diag.SockDiag()
    real_cookie = self.sock_diag.FindSockDiagFromFd(self.sock).id.cookie
    cookie = struct.unpack('=Q', real_cookie)[0]
    self.assertEquals(LookupMap(self.map_fd, cookie).value, packet_count)

  @unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                       "BPF helper function is not fully supported")
  def testGetSocketUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # Set up the instruction with uid at BPF_REG_0.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_uid)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insSkFilterAccept
                     + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10;
    self.socketLoopBackWithFilter(packet_count, 4)
    uid = os.getuid()
    self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count)
    self.socketLoopBackWithFilter(packet_count, 6)
    self.assertEquals(LookupMap(self.map_fd, uid).value, 2*packet_count)

@unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                     "Cgroup BPF is not fully supported")
class BpfCgroupTest(net_test.NetworkTest):

  def setUp(self):
    if not os.path.isdir("/tmp"):
      os.mkdir('/tmp')
    os.system('mount -t cgroup2 cg_bpf /tmp')
    self.prog_fd = -1
    self.map_fd = -1
    self.cg_fd = os.open('/tmp', os.O_DIRECTORY | os.O_RDONLY)

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_EGRESS)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)
    os.close(self.cg_fd)
    os.system('umount cg_bpf')

  # a similiar loopback helper without sk filter attached.
  def socketLoopBack(self, packet_count, version):
    family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
    sock = socket.socket(family, socket.SOCK_DGRAM, 0)
    net_test.SetNonBlocking(sock)
    addr = {4: "127.0.0.1", 6: "::1"}[version]
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    for i in xrange(packet_count):
      sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)
    sock.close()

  def testCgBpfAttach(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)

  def testCgroupIngress(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    self.assertRaisesErrno(errno.EAGAIN, self.socketLoopBack, 1, 4)
    self.assertRaisesErrno(errno.EAGAIN, self.socketLoopBack, 1, 6)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)
    self.socketLoopBack(1, 4)
    self.socketLoopBack(1, 6)

  def testCgroupEgress(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_EGRESS)
    self.assertRaisesErrno(errno.EPERM, self.socketLoopBack, 1, 4)
    self.assertRaisesErrno(errno.EPERM, self.socketLoopBack, 1, 6)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_EGRESS)
    self.socketLoopBack( 1, 4)
    self.socketLoopBack( 1, 6)

  def testCgroupBpfUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # The same eBPF program used in socket uid test. 
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_uid)
    ]
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insCgroupAccept
                     + insPackCountUpdate + insCgroupAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructions)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    uid = os.getuid()
    packet_count = 20
    self.socketLoopBack(packet_count, 4)
    self.socketLoopBack(packet_count, 6)
    self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count*2)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)

if __name__ == "__main__":
  unittest.main()
