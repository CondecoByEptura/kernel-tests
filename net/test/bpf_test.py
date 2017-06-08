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
import random
from scapy import all as scapy
import socket
import struct
import time
import unittest

from bpf import *  # pylint: disable=wildcard-import
import csocket
import multinetwork_base
import net_test
import packets
import sock_diag
import tcp_test

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)
HAVE_EBPF_ACCOUNTING = net_test.LINUX_VERSION >= (4, 9, 0)
KEY_SIZE = 8
VALUE_SIZE = 4
TOTAL_ENTRIES = 100

TYPE_COOKIE_INGRESS = 1
TYPE_COOKIE_EGRESS = 2
TYPE_IFACE_INGRESS = 3
TYPE_IFACE_EGRESS = 4
TYPE_PROTOCOL_INGRESS = 5
TYPE_PROTOCOL_EGRESS = 6


# Debug usage only.
def PrintMapInfo(map_fd):
  key = 10086
  while 1:
    try:
      nextKey = GetNextKey(map_fd, key).value
      value = LookupMap(map_fd, nextKey)
      print repr(nextKey) + " : " + repr(value.value)
      key = nextKey
    except:
      print "no value"
      break


# A dummy loopback function to generate traffic through a socket.
def SocketLoopBackWithFilter(packet_count, version, prog_fd):
  family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
  sock = socket.socket(family, socket.SOCK_DGRAM, 0)
  if prog_fd is not None:
    BpfProgAttachSocket(sock.fileno(), prog_fd)
  net_test.SetNonBlocking(sock)
  addr = {4: "127.0.0.1", 6: "::1"}[version]
  sock.bind((addr, 0))
  addr = sock.getsockname()
  sockaddr = csocket.Sockaddr(addr)
  for i in xrange(packet_count):
    sock.sendto("foo", addr)
    data, retaddr = csocket.Recvfrom(sock, 4096, 0)
    assert "foo" == data
    assert sockaddr == retaddr
  return sock


# The main code block for eBPF packet counting program. It takes a preloaded key
# from BPF_REG_0 and use it to look up the bpf map, if the element does not
# exist in the map yet, the program will update the map with a new <key, 1>
# pair. Otherwise it will jump to next code block to handle it.
def BpfFuncCountPacketInit(map_fd):
  key_pos = BPF_REG_7
  insPackCountStart = [
      # Get a preloaded key from BPF_REG_0 and store it at BPF_REG_7
      BpfMov64Reg(key_pos, BPF_REG_10),
      BpfAlu64Imm(BPF_ADD, key_pos, -8),
      # Load map fd and look up the key in the map
      BpfLoadMapFd(map_fd, BPF_REG_1),
      BpfMov64Reg(BPF_REG_2, key_pos),
      BpfFuncCall(BPF_FUNC_map_lookup_elem),
      # if the map element already exist, jump out of this
      # code block and let next part to handle it
      BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10),
      BpfLoadMapFd(map_fd, BPF_REG_1),
      BpfMov64Reg(BPF_REG_2, key_pos),
      # Initial a new <key, value> pair with value equal to 1 and update to map
      BpfStMem(BPF_W, BPF_REG_10, -16, 1),
      BpfMov64Reg(BPF_REG_3, BPF_REG_10),
      BpfAlu64Imm(BPF_ADD, BPF_REG_3, -16),
      BpfMov64Imm(BPF_REG_4, 0),
      BpfFuncCall(BPF_FUNC_map_update_elem)
  ]
  return insPackCountStart



insBpfExitBlock = [
    BpfMov64Imm(BPF_REG_0, 0),
    BpfExitInsn()
]

# Bpf instruction for cgroup bpf filter to accept a packet and exit.
insCgroupAccept = [
    # Set return value to 1 and exit.
    BpfMov64Imm(BPF_REG_0, 1),
    BpfExitInsn()
]

# Bpf instruction for socket bpf filter to accept a packet and exit.
insSkFilterAccept = [
    # Precondition: BPF_REG_6 = sk_buff context
    # Load the packet length from BPF_REG_6 and store it in BPF_REG_0 as the
    # return value.
    BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0),
    BpfExitInsn()
]

# Update a existing map element with +1.
insPackCountUpdate = [
    # Precondition: BPF_REG_0 = Value retrieved from BPF maps
    # Add one to the corresponding eBPF value field for a specific eBPF key.
    BpfMov64Reg(BPF_REG_2, BPF_REG_0),
    BpfMov64Imm(BPF_REG_1, 1),
    BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1, 0, 0),
]

insBpfParamStore = [
    BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
]


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
    SocketLoopBackWithFilter(1, 4, self.prog_fd)
    SocketLoopBackWithFilter(1, 6, self.prog_fd)

  def testPacketBlock(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, insBpfExitBlock)
    self.assertRaisesErrno(errno.EAGAIN, SocketLoopBackWithFilter, 1, 4, self.prog_fd)
    self.assertRaisesErrno(errno.EAGAIN, SocketLoopBackWithFilter, 1, 6, self.prog_fd)

  def testPacketCount(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    key = 0xf0f0
    # Set up instruction block with key loaded at BPF_REG_0.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfMov64Imm(BPF_REG_0, key)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insSkFilterAccept + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    SocketLoopBackWithFilter(packet_count, 4, self.prog_fd)
    SocketLoopBackWithFilter(packet_count, 6, self.prog_fd)
    self.assertEquals(LookupMap(self.map_fd, key).value, packet_count*2)

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                       "BPF helper function is not fully supported")
  def testGetSocketCookie(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_cookie)
    ]
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insSkFilterAccept + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    def PacketCountByCookie(version):
      self.sock = SocketLoopBackWithFilter(packet_count, version, self.prog_fd)
      self.sock_diag = sock_diag.SockDiag()
      real_cookie = self.sock_diag.FindSockDiagFromFd(self.sock).id.cookie
      cookie = struct.unpack('=Q', real_cookie)[0]
      self.assertEquals(LookupMap(self.map_fd, cookie).value, packet_count)
      self.sock.close()
    PacketCountByCookie(4)
    PacketCountByCookie(6)

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                       "BPF helper function is not fully supported")
  def testGetSocketUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # Set up the instruction with uid at BPF_REG_0.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_uid)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insSkFilterAccept + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    uid = 12345
    with net_test.RunAsUid(uid):
      self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, uid)
      SocketLoopBackWithFilter(packet_count, 4, self.prog_fd)
      self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count)
      SocketLoopBackWithFilter(packet_count, 6, self.prog_fd)
      self.assertEquals(LookupMap(self.map_fd, uid).value, 2*packet_count)

@unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                     "Cgroup BPF is not fully supported")
class BpfCgroupTest(net_test.NetworkTest):

  @classmethod
  def setUpClass(cls):
    if not os.path.isdir("/tmp"):
      os.mkdir('/tmp')
    os.system('mount -t cgroup2 cg_bpf /tmp')
    cls._cg_fd = os.open('/tmp', os.O_DIRECTORY | os.O_RDONLY)

  @classmethod
  def tearDownClass(cls):
    os.close(cls._cg_fd)
    os.system('umount cg_bpf')

  def setUp(self):
    self.prog_fd = -1
    self.map_fd = -1

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    try:
      BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_EGRESS)
    except socket.error:
      pass
    try:
      BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)
    except socket.error:
      pass

  def testCgroupBpfAttach(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)

  def testCgroupIngress(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    self.assertRaisesErrno(errno.EAGAIN, SocketLoopBackWithFilter, 1, 4, None)
    self.assertRaisesErrno(errno.EAGAIN, SocketLoopBackWithFilter, 1, 6, None)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)
    SocketLoopBackWithFilter(1, 4, None)
    SocketLoopBackWithFilter(1, 6, None)

  def testCgroupEgress(self):
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, insBpfExitBlock)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_EGRESS)
    self.assertRaisesErrno(errno.EPERM, SocketLoopBackWithFilter, 1, 4, None)
    self.assertRaisesErrno(errno.EPERM, SocketLoopBackWithFilter, 1, 6, None)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_EGRESS)
    SocketLoopBackWithFilter( 1, 4, None)
    SocketLoopBackWithFilter( 1, 6, None)

  def testCgroupBpfUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # Similar to the program used in testGetSocketUid.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_uid)
    ]
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insCgroupAccept + insPackCountUpdate + insCgroupAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructions)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    uid = os.getuid()
    packet_count = 20
    SocketLoopBackWithFilter(packet_count, 4, None)
    SocketLoopBackWithFilter(packet_count, 6, None)
    self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count * 2)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)

@unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                     "Cgroup BPF is not fully supported")
class BpfCgroupMultinetworkTest(tcp_test.TcpBaseTest):

  @classmethod
  def setUpClass(cls):
    if not os.path.isdir("/tmp"):
      os.mkdir('/tmp')
    os.system('mount -t cgroup2 cg_bpf /tmp')
    cls._cg_fd = os.open('/tmp', os.O_DIRECTORY | os.O_RDONLY)
    super(BpfCgroupMultinetworkTest, cls).setUpClass()

  @classmethod
  def tearDownClass(cls):
    os.close(cls._cg_fd)
    os.system('umount cg_bpf')
    super(BpfCgroupMultinetworkTest, cls).tearDownClass()

  def setUp(self):
    self.prog_fd = -1
    self.map_fd = -1

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    try:
      BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_EGRESS)
    except socket.error:
      pass
    try:
      BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)
    except socket.error:
      pass

  # Miscellaneous helper function
  # TODO: replace it with new added SO_COOKIE socketopt
  def GetSocketCookie(self, s):
    self.sock_diag = sock_diag.SockDiag()
    real_cookie = self.sock_diag.FindSockDiagFromFd(s).id.cookie
    return struct.unpack('=Q', real_cookie)[0]

  def CheckUDPEgressTraffic(self, version, netid, routing_mode, dstaddr,
                            packet_count, map_key):
    self.s = self.BuildSocket(version, net_test.UDPSocket, netid, routing_mode)
    if map_key == -1:
      map_key = self.GetSocketCookie(self.s)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, map_key)
    myaddr = self.MyAddress(version, netid)
    for _ in xrange(packet_count):
      desc, expected = packets.UDP(version, myaddr, dstaddr, sport=None)
      msg = "IPv%s UDP %%s: expected %s on %s" % (
          version, desc, self.GetInterfaceName(netid))
      self.s.sendto(net_test.UDP_PAYLOAD, (dstaddr, 53))
      self.ExpectPacketOn(netid, msg % "sendto", expected)
    self.assertEquals(LookupMap(self.map_fd, map_key).value,
                      packet_count)
    DeleteMap(self.map_fd, map_key)

  def CheckTCPEgressTraffic(self, version, netid, routing_mode, dstaddr,
                            packet_count, map_key):
    self.s = self.BuildSocket(version, net_test.TCPSocket, netid, routing_mode)
    myaddr = self.MyAddress(version, netid)
    for _ in xrange(packet_count):
      desc, expected = packets.SYN(53, version, myaddr, dstaddr,
                                   sport=None, seq=None)
      # Non-blocking TCP connects always return EINPROGRESS.
      self.assertRaisesErrno(errno.EINPROGRESS, self.s.connect, (dstaddr, 53))
      msg = "IPv%s TCP connect: expected %s on %s" % (
          version, desc, self.GetInterfaceName(netid))
      self.ExpectPacketOn(netid, msg, expected)
    if map_key == -1:
      map_key = self.GetSocketCookie(self.s)
    self.assertEquals(LookupMap(self.map_fd, map_key).value,
                        packet_count)
    DeleteMap(self.map_fd, map_key)

  def TcpFullStateCheck(self, version, netid, packet_count, map_key, testType):
    self.s = self.OpenListenSocket(version, netid)
    remoteaddr = self.remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.myaddr = self.MyAddress(version, netid)
    is_cookie = False
    if map_key == -1:
      is_cookie = True;

    for i in xrange (0, packet_count):
      desc, syn = packets.SYN(self.port, version, remoteaddr, myaddr)
      self.ReceivePacketOn(netid, syn)
      desc, syn = packets.SYN(self.port, version, remoteaddr, myaddr)
      synack_desc, synack = packets.SYNACK(version, myaddr, remoteaddr, syn)
      msg = "Received %s, expected to see reply %s" % (desc, synack_desc)
      reply = self._ReceiveAndExpectResponse(netid, syn, synack, msg)
      establishing_ack = packets.ACK(version, remoteaddr, myaddr, reply)[1]
      self.ReceivePacketOn(netid, establishing_ack)
      self.accepted, _ = self.s.accept()
      net_test.DisableFinWait(self.accepted)
      desc, data = packets.ACK(version, myaddr, remoteaddr, establishing_ack,
                               payload=net_test.UDP_PAYLOAD)
      self.accepted.send(net_test.UDP_PAYLOAD)
      self.ExpectPacketOn(netid, msg + ": expecting %s" % desc, data)
      desc, fin = packets.FIN(version, remoteaddr, myaddr, data)
      fin = packets._GetIpLayer(version)(str(fin))
      ack_desc, ack = packets.ACK(version, myaddr, remoteaddr, fin)
      msg = "Received %s, expected to see reply %s" % (desc, ack_desc)
      self.ReceivePacketOn(netid, fin)
      time.sleep(0.1)
      self.ExpectPacketOn(netid, msg + ": expecting %s" % ack_desc, ack)
      # check the packet counting on accepted socket if the key is socket cookie.
      if is_cookie:
        map_key = self.GetSocketCookie(self.accepted)
        if testType == TYPE_COOKIE_INGRESS:
          self.assertEquals(LookupMap(self.map_fd, map_key).value,
                            1 if version==4 else 2)
        else:
          self.assertEquals(LookupMap(self.map_fd, map_key).value, 2)

    # Check the total packet recorded after a iterations.
    if testType == TYPE_COOKIE_INGRESS:
      map_key = self.GetSocketCookie(self.s)
      self.assertEquals(LookupMap(self.map_fd, map_key).value,
                        packet_count*2 if version==4 else packet_count*2*2)
    elif testType == TYPE_IFACE_INGRESS:
      self.assertEquals(LookupMap(self.map_fd, map_key).value, packet_count*3)
    elif testType == TYPE_PROTOCOL_EGRESS:
      self.assertEquals(LookupMap(self.map_fd, map_key).value,
                        packet_count*5 if version==4 else packet_count*3)
    elif testType == TYPE_PROTOCOL_INGRESS:
      self.assertEquals(LookupMap(self.map_fd, map_key).value,
                        packet_count*3 if version==4 else packet_count*3*2)
    elif testType == TYPE_IFACE_EGRESS:
      self.assertEquals(LookupMap(self.map_fd, map_key).value,
                        packet_count*4 if version==4 else packet_count*4*2)

    DeleteMap(self.map_fd, map_key)

  def ReceiveUDPPacketOn(self, version, netid, packet_count, map_key):
    srcaddr = {4: self.IPV4_ADDR, 6: self.IPV6_ADDR}[version]
    dstaddr = self.MyAddress(version, netid)
    family = {4: net_test.AF_INET, 6: net_test.AF_INET6}[version]
    self.s = net_test.Socket(family, net_test.SOCK_DGRAM, 0)
    self.s.bind((dstaddr, 0))
    dstport = self.s.getsockname()[1]
    srcport = 53
    if map_key == -1:
      map_key = self.GetSocketCookie(self.s)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, map_key)
    for _ in xrange(packet_count):
      if version == 4:
        incoming = (scapy.IP(src=srcaddr, dst=dstaddr) /
                    scapy.UDP(sport=srcport, dport=dstport) /
                    net_test.UDP_PAYLOAD)
      else:
        incoming = (scapy.IPv6(src=srcaddr, dst=dstaddr) /
                    scapy.UDP(sport=srcport, dport=dstport) /
                    net_test.UDP_PAYLOAD)
      self.ReceivePacketOn(netid, incoming)
    self.assertEquals(LookupMap(self.map_fd, map_key).value, packet_count)
    DeleteMap(self.map_fd, map_key)

  def testCgroupCookieIPEgress(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # The same eBPF program used in socket cookie test.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_cookie)
    ]
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insCgroupAccept + insPackCountUpdate + insCgroupAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructions)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_EGRESS)
    uid = os.getuid()
    packet_count = 5
    v4addr = self.IPV4_ADDR
    v6addr = self.IPV6_ADDR
    for netid in self.NETIDS:
      self.CheckUDPEgressTraffic(4, netid, "mark", v4addr, packet_count, -1)
      self.CheckUDPEgressTraffic(6, netid, "mark", v6addr, packet_count, -1)
      self.CheckUDPEgressTraffic(4, netid, "uid", v4addr, packet_count, -1)
      self.CheckUDPEgressTraffic(6, netid, "uid", v6addr, packet_count, -1)
      self.CheckUDPEgressTraffic(4, netid, "oif", v4addr, packet_count, -1)
      self.CheckUDPEgressTraffic(6, netid, "oif", v6addr, packet_count, -1)
      self.CheckUDPEgressTraffic(4, netid, "ucast_oif", v4addr, packet_count, -1)
      self.CheckUDPEgressTraffic(6, netid, "ucast_oif", v6addr, packet_count, -1)
      # only the first connect request can be seen at the output interface, so
      # we can only test with packet_count = 1.
      self.CheckTCPEgressTraffic(4, netid, "mark", v4addr, 1, -1)
      self.CheckTCPEgressTraffic(6, netid, "mark", v6addr, 1, -1)
      self.CheckTCPEgressTraffic(4, netid, "uid", v4addr, 1, -1)
      self.CheckTCPEgressTraffic(6, netid, "uid", v6addr, 1, -1)
      self.CheckTCPEgressTraffic(4, netid, "oif", v4addr, 1, -1)
      self.CheckTCPEgressTraffic(6, netid, "oif", v6addr, 1, -1)
      # Use this function to test a accepted socket sending packet out.
      self.TcpFullStateCheck(4, netid, packet_count, -1, TYPE_COOKIE_EGRESS)
      self.TcpFullStateCheck(6, netid, packet_count, -1, TYPE_COOKIE_EGRESS)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_EGRESS)

  def testCgroupBpfCookieIngress(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    # The same eBPF program used in socket cookie test.
    instructions = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfFuncCall(BPF_FUNC_get_socket_cookie)
    ]
    instructions += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insCgroupAccept + insPackCountUpdate + insCgroupAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructions)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    packet_count = 10
    for netid in self.NETIDS:
      self.TcpFullStateCheck(4, netid, packet_count, -1, TYPE_COOKIE_INGRESS)
      self.TcpFullStateCheck(6, netid, packet_count, -1, TYPE_COOKIE_INGRESS)
      self.ReceiveUDPPacketOn(4, netid, packet_count, -1)
      self.ReceiveUDPPacketOn(6, netid, packet_count, -1)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)

  def testCheckPacketiface(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    sk_buff = BpfSkBuff((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    # The BPF program get skb portocol and iface index of each packet.
    BpfInsn1 = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, sk_buff.offset("protocol")),
        BpfJumpImm(BPF_JEQ, BPF_REG_0, 8, 2),
    ]
    BpfInsn2 = [
        BpfMov64Reg(BPF_REG_1, BPF_REG_6),
        BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, sk_buff.offset("ifindex")),
    ]
    instructionEgress = (BpfInsn1 + insCgroupAccept + BpfInsn2 + insBpfParamStore +
                    BpfFuncCountPacketInit(self.map_fd) + insCgroupAccept
                    + insPackCountUpdate + insCgroupAccept)

    instructionIngress = [
        BpfMov64Reg(BPF_REG_6, BPF_REG_1),
        BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, sk_buff.offset("ifindex"))
    ]
    instructionIngress += (insBpfParamStore + BpfFuncCountPacketInit(self.map_fd)
                     + insCgroupAccept + insPackCountUpdate + insCgroupAccept)

    v4addr = self.IPV4_ADDR
    v6addr = self.IPV6_ADDR
    packet_count = 1

    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructionIngress)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    for netid in self.NETIDS:
      ifaceIdx = net_test.GetInterfaceIndex(self.GetInterfaceName(netid))
      self.TcpFullStateCheck(4, netid, packet_count, ifaceIdx, TYPE_IFACE_INGRESS)
      self.TcpFullStateCheck(6, netid, packet_count, ifaceIdx, TYPE_IFACE_INGRESS)
      self.ReceiveUDPPacketOn(4, netid, packet_count, ifaceIdx)
      self.ReceiveUDPPacketOn(6, netid, packet_count, ifaceIdx)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)
    os.close(self.prog_fd)

    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructionEgress)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_EGRESS)
    for netid in self.NETIDS:
      ifaceIdx = net_test.GetInterfaceIndex(self.GetInterfaceName(netid))
      self.CheckUDPEgressTraffic(4, netid, "mark", v4addr, packet_count, ifaceIdx)
      self.CheckUDPEgressTraffic(4, netid, "uid", v4addr, packet_count, ifaceIdx)
      self.CheckUDPEgressTraffic(4, netid, "oif", v4addr, packet_count, ifaceIdx)
      self.CheckUDPEgressTraffic(4, netid, "ucast_oif", v4addr, packet_count, ifaceIdx)
      self.CheckTCPEgressTraffic(4, netid, "mark", v4addr, 1, ifaceIdx)
      self.CheckTCPEgressTraffic(4, netid, "uid", v4addr, 1, ifaceIdx)
      self.CheckTCPEgressTraffic(4, netid, "oif", v4addr, 1, ifaceIdx)
      # Use this function to test a accepted socket sending packet out.
      self.TcpFullStateCheck(4, netid, packet_count, ifaceIdx, TYPE_IFACE_EGRESS)
      # The ifindex for egress IPv6 packet is always 0.
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_EGRESS)

if __name__ == "__main__":
  unittest.main()
