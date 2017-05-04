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
HAVE_EBPF_ACCOUNTING = net_test.LINUX_VERSION >= (4, 9, 0)
KEY_SIZE = 8
VALUE_SIZE = 4
TOTAL_ENTRIES = 20


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
      BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
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
    self.assertEquals(value, LookupMap(self.map_fd, key).value)
    DeleteMap(self.map_fd, key)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, key)

  def testIterateMap(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE, TOTAL_ENTRIES)
    value = 1024
    for key in xrange(1, TOTAL_ENTRIES):
      UpdateMap(self.map_fd, key, value)
    for key in xrange(1, TOTAL_ENTRIES):
      self.assertEquals(value, LookupMap(self.map_fd, key).value)
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
        self.assertEquals(value, LookupMap(self.map_fd, key).value)
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
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insSkFilterAccept
                     + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    SocketLoopBackWithFilter(packet_count, 4, self.prog_fd)
    SocketLoopBackWithFilter(packet_count, 6, self.prog_fd)
    self.assertEquals(packet_count * 2, LookupMap(self.map_fd, key).value)

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
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
    packet_count = 10
    def PacketCountByCookie(version):
      self.sock = SocketLoopBackWithFilter(packet_count, version, self.prog_fd)
      self.sock_diag = sock_diag.SockDiag()
      real_cookie = self.sock_diag.FindSockDiagFromFd(self.sock).id.cookie
      cookie = struct.unpack('=Q', real_cookie)[0]
      self.assertEquals(packet_count, LookupMap(self.map_fd, cookie).value)
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
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insSkFilterAccept
                     + insPackCountUpdate + insSkFilterAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER, instructions)
    packet_count = 10
    uid = 12345
    with net_test.RunAsUid(uid):
      self.assertRaisesErrno(errno.ENOENT, LookupMap, self.map_fd, uid)
      SocketLoopBackWithFilter(packet_count, 4, self.prog_fd)
      self.assertEquals(packet_count, LookupMap(self.map_fd, uid).value)
      SocketLoopBackWithFilter(packet_count, 6, self.prog_fd)
      self.assertEquals(packet_count * 2, LookupMap(self.map_fd, uid).value)

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
    instructions += (BpfFuncCountPacketInit(self.map_fd) + insCgroupAccept
                     + insPackCountUpdate + insCgroupAccept)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB, instructions)
    BpfProgAttach(self.prog_fd, self._cg_fd, BPF_CGROUP_INET_INGRESS)
    uid = os.getuid()
    packet_count = 20
    SocketLoopBackWithFilter(packet_count, 4, None)
    SocketLoopBackWithFilter(packet_count, 6, None)
    self.assertEquals(packet_count * 2, LookupMap(self.map_fd, uid).value)
    BpfProgDetach(self._cg_fd, BPF_CGROUP_INET_INGRESS)

if __name__ == "__main__":
  unittest.main()
