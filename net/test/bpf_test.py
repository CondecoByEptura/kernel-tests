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
import subprocess
import tempfile
import unittest

import bpf
import csocket
import net_test
from net_test import LINUX_VERSION
import sock_diag

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

HAVE_EBPF_ACCOUNTING = bpf.HAVE_EBPF_4_9
HAVE_EBPF_SOCKET = bpf.HAVE_EBPF_4_14

# bpf_ktime_get_ns() was made non-GPL requiring in 5.8 and at the same time
# bpf_ktime_get_boot_ns() was added, both of these changes were backported to
# Android Common Kernel in 4.14.221, 4.19.175, 5.4.97.
# As such we require 4.14.222+ 4.19.176+ 5.4.98+ 5.8.0+,
# but since we only really care about LTS releases:
HAVE_EBPF_KTIME_GET_NS_APACHE = (
    ((LINUX_VERSION > (4, 14, 221)) and (LINUX_VERSION < (4, 19, 0))) or
    ((LINUX_VERSION > (4, 19, 175)) and (LINUX_VERSION < (5, 4, 0))) or
    (LINUX_VERSION > (5, 4, 97))
)
HAVE_EBPF_KTIME_GET_BOOT_NS = HAVE_EBPF_KTIME_GET_NS_APACHE

KEY_SIZE = 8
VALUE_SIZE = 4
TOTAL_ENTRIES = 20
TEST_UID = 54321
TEST_GID = 12345
# Offset to store the map key in stack register REG10
key_offset = -8
# Offset to store the map value in stack register REG10
value_offset = -16


# Debug usage only.
def PrintMapInfo(map_fd):
  # A random key that the map does not contain.
  key = 10086
  while 1:
    try:
      next_key = bpf.GetNextKey(map_fd, key).value
      value = bpf.LookupMap(map_fd, next_key)
      print(repr(next_key) + " : " + repr(value.value))  # pylint: disable=superfluous-parens
      key = next_key
    except:  # pylint: disable=bare-except
      print("no value")  # pylint: disable=superfluous-parens
      break


# A dummy loopback function that causes a socket to send traffic to itself.
def SocketUDPLoopBack(packet_count, version, prog_fd):
  family = {4: socket.AF_INET, 6: socket.AF_INET6}[version]
  sock = socket.socket(family, socket.SOCK_DGRAM, 0)
  if prog_fd is not None:
    bpf.BpfProgAttachSocket(sock.fileno(), prog_fd)
  net_test.SetNonBlocking(sock)
  addr = {4: "127.0.0.1", 6: "::1"}[version]
  sock.bind((addr, 0))
  addr = sock.getsockname()
  sockaddr = csocket.Sockaddr(addr)
  for _ in range(packet_count):
    sock.sendto("foo", addr)
    data, retaddr = csocket.Recvfrom(sock, 4096, 0)
    assert "foo" == data
    assert sockaddr == retaddr
  return sock


# The main code block for eBPF packet counting program. It takes a preloaded
# key from BPF_REG_0 and use it to look up the bpf map, if the element does not
# exist in the map yet, the program will update the map with a new <key, 1>
# pair. Otherwise it will jump to next code block to handle it.
# REG0: regiter storing return value from helper function and the final return
# value of eBPF program.
# REG1 - REG5: temporary register used for storing values and load parameters
# into eBPF helper function. After calling helper function, the value for these
# registers will be reset.
# REG6 - REG9: registers store values that will not be cleared when calling
# eBPF helper function.
# REG10: A stack stores values need to be accessed by the address. Program can
# retrieve the address of a value by specifying the position of the value in
# the stack.
def BpfFuncCountPacketInit(map_fd):
  key_pos = bpf.BPF_REG_7
  return [
      # Get a preloaded key from BPF_REG_0 and store it at BPF_REG_7
      bpf.BpfMov64Reg(key_pos, bpf.BPF_REG_10),
      bpf.BpfAlu64Imm(bpf.BPF_ADD, key_pos, key_offset),
      # Load map fd and look up the key in the map
      bpf.BpfLoadMapFd(map_fd, bpf.BPF_REG_1),
      bpf.BpfMov64Reg(bpf.BPF_REG_2, key_pos),
      bpf.BpfFuncCall(bpf.BPF_FUNC_map_lookup_elem),
      # if the map element already exist, jump out of this
      # code block and let next part to handle it
      bpf.BpfJumpImm(bpf.BPF_AND, bpf.BPF_REG_0, 0, 10),
      bpf.BpfLoadMapFd(map_fd, bpf.BPF_REG_1),
      bpf.BpfMov64Reg(bpf.BPF_REG_2, key_pos),
      # Initial a new <key, value> pair with value equal to 1 and update to map
      bpf.BpfStMem(bpf.BPF_W, bpf.BPF_REG_10, value_offset, 1),
      bpf.BpfMov64Reg(bpf.BPF_REG_3, bpf.BPF_REG_10),
      bpf.BpfAlu64Imm(bpf.BPF_ADD, bpf.BPF_REG_3, value_offset),
      bpf.BpfMov64Imm(bpf.BPF_REG_4, 0),
      bpf.BpfFuncCall(bpf.BPF_FUNC_map_update_elem)
  ]


INS_BPF_EXIT_BLOCK = [
    bpf.BpfMov64Imm(bpf.BPF_REG_0, 0),
    bpf.BpfExitInsn()
]

# Bpf instruction for cgroup bpf filter to accept a packet and exit.
INS_CGROUP_ACCEPT = [
    # Set return value to 1 and exit.
    bpf.BpfMov64Imm(bpf.BPF_REG_0, 1),
    bpf.BpfExitInsn()
]

# Bpf instruction for socket bpf filter to accept a packet and exit.
INS_SK_FILTER_ACCEPT = [
    # Precondition: BPF_REG_6 = sk_buff context
    # Load the packet length from BPF_REG_6 and store it in BPF_REG_0 as the
    # return value.
    bpf.BpfLdxMem(bpf.BPF_W, bpf.BPF_REG_0, bpf.BPF_REG_6, 0),
    bpf.BpfExitInsn()
]

# Update a existing map element with +1.
INS_PACK_COUNT_UPDATE = [
    # Precondition: BPF_REG_0 = Value retrieved from BPF maps
    # Add one to the corresponding eBPF value field for a specific eBPF key.
    bpf.BpfMov64Reg(bpf.BPF_REG_2, bpf.BPF_REG_0),
    bpf.BpfMov64Imm(bpf.BPF_REG_1, 1),
    bpf.BpfRawInsn(bpf.BPF_STX | bpf.BPF_XADD | bpf.BPF_W, bpf.BPF_REG_2,
                   bpf.BPF_REG_1, 0, 0),
]

INS_BPF_PARAM_STORE = [
    bpf.BpfStxMem(bpf.BPF_DW, bpf.BPF_REG_10, bpf.BPF_REG_0, key_offset),
]


@unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                     "BPF helper function is not fully supported")
class BpfTest(net_test.NetworkTest):

  def setUp(self):
    super(BpfTest, self).setUp()
    self.map_fd = -1
    self.prog_fd = -1
    self.sock = None

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    if self.sock:
      self.sock.close()
    super(BpfTest, self).tearDown()

  def testCreateMap(self):
    key, value = 1, 1
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    bpf.UpdateMap(self.map_fd, key, value)
    self.assertEqual(value, bpf.LookupMap(self.map_fd, key).value)
    bpf.DeleteMap(self.map_fd, key)
    self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, self.map_fd, key)

  def CheckAllMapEntry(self, nonexistent_key, total_entries, value):
    count = 0
    key = nonexistent_key
    while True:
      if count == total_entries:
        self.assertRaisesErrno(errno.ENOENT, bpf.GetNextKey, self.map_fd, key)
        break
      else:
        result = bpf.GetNextKey(self.map_fd, key)
        key = result.value
        self.assertGreaterEqual(key, 0)
        self.assertEqual(value, bpf.LookupMap(self.map_fd, key).value)
        count += 1

  def testIterateMap(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    value = 1024
    for key in range(0, TOTAL_ENTRIES):
      bpf.UpdateMap(self.map_fd, key, value)
    for key in range(0, TOTAL_ENTRIES):
      self.assertEqual(value, bpf.LookupMap(self.map_fd, key).value)
    self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, self.map_fd, 101)
    nonexistent_key = -1
    self.CheckAllMapEntry(nonexistent_key, TOTAL_ENTRIES, value)

  def testFindFirstMapKey(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    value = 1024
    for key in range(0, TOTAL_ENTRIES):
      bpf.UpdateMap(self.map_fd, key, value)
    first_key = bpf.GetFirstKey(self.map_fd)
    key = first_key.value
    self.CheckAllMapEntry(key, TOTAL_ENTRIES - 1, value)

  def testRdOnlyMap(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES, map_flags=bpf.BPF_F_RDONLY)
    value = 1024
    key = 1
    self.assertRaisesErrno(errno.EPERM, bpf.UpdateMap, self.map_fd, key, value)
    self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, self.map_fd, key)

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                       "BPF helper function is not fully supported")
  def testWrOnlyMap(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES, map_flags=bpf.BPF_F_WRONLY)
    value = 1024
    key = 1
    bpf.UpdateMap(self.map_fd, key, value)
    self.assertRaisesErrno(errno.EPERM, bpf.LookupMap, self.map_fd, key)

  def testProgLoad(self):
    # Move skb to BPF_REG_6 for further usage
    instructions = [
        bpf.BpfMov64Reg(bpf.BPF_REG_6, bpf.BPF_REG_1)
    ]
    instructions += INS_SK_FILTER_ACCEPT
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SOCKET_FILTER,
                                   instructions)
    SocketUDPLoopBack(1, 4, self.prog_fd)
    SocketUDPLoopBack(1, 6, self.prog_fd)

  def testPacketBlock(self):
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SOCKET_FILTER,
                                   INS_BPF_EXIT_BLOCK)
    self.assertRaisesErrno(errno.EAGAIN, SocketUDPLoopBack, 1, 4, self.prog_fd)
    self.assertRaisesErrno(errno.EAGAIN, SocketUDPLoopBack, 1, 6, self.prog_fd)

  def testPacketCount(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    key = 0xf0f0
    # Set up instruction block with key loaded at BPF_REG_0.
    instructions = [
        bpf.BpfMov64Reg(bpf.BPF_REG_6, bpf.BPF_REG_1),
        bpf.BpfMov64Imm(bpf.BPF_REG_0, key)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (INS_BPF_PARAM_STORE + BpfFuncCountPacketInit(self.map_fd)
                     + INS_SK_FILTER_ACCEPT + INS_PACK_COUNT_UPDATE
                     + INS_SK_FILTER_ACCEPT)
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SOCKET_FILTER,
                                   instructions)
    packet_count = 10
    SocketUDPLoopBack(packet_count, 4, self.prog_fd)
    SocketUDPLoopBack(packet_count, 6, self.prog_fd)
    self.assertEqual(packet_count * 2, bpf.LookupMap(self.map_fd, key).value)

  @unittest.skipUnless(bpf.HAVE_EBPF_SUPPORT, "eBPF unsupported")
  def testKtimeGetNsGPL(self):
    instructions = [bpf.BpfFuncCall(bpf.BPF_FUNC_ktime_get_ns)]
    instructions += INS_BPF_EXIT_BLOCK
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SCHED_CLS, instructions)

  ##############################################################################
  #
  # Test for presence of kernel patch:
  #
  #   UPSTREAM: net: bpf: Make bpf_ktime_get_ns() available to non GPL programs
  #
  # 4.14: https://android-review.googlesource.com/c/kernel/common/+/1585269
  #       commit cbb4c73f9eab8f3c8ac29175d45c99ccba382e15
  #
  # 4.19: https://android-review.googlesource.com/c/kernel/common/+/1355243
  #       commit 272e21ccc9a92feeee80aff0587410a314b73c5b
  #
  # 5.4:  https://android-review.googlesource.com/c/kernel/common/+/1355422
  #       commit 45217b91eaaa3a563247c4f470f4cb785de6b1c6
  #
  @unittest.skipUnless(HAVE_EBPF_KTIME_GET_NS_APACHE,
                       "no bpf_ktime_get_ns() support for non-GPL programs")
  def testKtimeGetNsApache(self):
    instructions = [bpf.BpfFuncCall(bpf.BPF_FUNC_ktime_get_ns)]
    instructions += INS_BPF_EXIT_BLOCK
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SCHED_CLS, instructions,
                                   b"Apache 2.0")

  ##############################################################################
  #
  # Test for presence of kernel patch:
  #
  #   BACKPORT: bpf: add bpf_ktime_get_boot_ns()
  #
  # 4.14: https://android-review.googlesource.com/c/kernel/common/+/1585587
  #       commit 34073d7a8ee47ca908b56e9a1d14ca0615fdfc09
  #
  # 4.19: https://android-review.googlesource.com/c/kernel/common/+/1585606
  #       commit 4812ec50935dfe59ba9f48a572e278dd0b02af68
  #
  # 5.4:  https://android-review.googlesource.com/c/kernel/common/+/1585252
  #       commit 57b3f4830fb66a6038c4c1c66ca2e138fe8be231
  #
  @unittest.skipUnless(HAVE_EBPF_KTIME_GET_BOOT_NS,
                       "no bpf_ktime_get_boot_ns() support")
  def testKtimeGetBootNs(self):
    instructions = [bpf.BpfFuncCall(bpf.BPF_FUNC_ktime_get_boot_ns)]
    instructions += INS_BPF_EXIT_BLOCK
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SCHED_CLS, instructions,
                                   b"Apache 2.0")

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                       "BPF helper function is not fully supported")
  def testGetSocketCookie(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    # Move skb to REG6 for further usage, call helper function to get socket
    # cookie of current skb and return the cookie at REG0 for next code block
    instructions = [
        bpf.BpfMov64Reg(bpf.BPF_REG_6, bpf.BPF_REG_1),
        bpf.BpfFuncCall(bpf.BPF_FUNC_get_socket_cookie)
    ]
    instructions += (INS_BPF_PARAM_STORE + BpfFuncCountPacketInit(self.map_fd)
                     + INS_SK_FILTER_ACCEPT + INS_PACK_COUNT_UPDATE
                     + INS_SK_FILTER_ACCEPT)
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SOCKET_FILTER,
                                   instructions)
    packet_count = 10
    def PacketCountByCookie(version):
      self.sock = SocketUDPLoopBack(packet_count, version, self.prog_fd)
      cookie = sock_diag.SockDiag.GetSocketCookie(self.sock)
      self.assertEqual(packet_count, bpf.LookupMap(self.map_fd, cookie).value)
      self.sock.close()
    PacketCountByCookie(4)
    PacketCountByCookie(6)

  @unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                       "BPF helper function is not fully supported")
  def testGetSocketUid(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    # Set up the instruction with uid at BPF_REG_0.
    instructions = [
        bpf.BpfMov64Reg(bpf.BPF_REG_6, bpf.BPF_REG_1),
        bpf.BpfFuncCall(bpf.BPF_FUNC_get_socket_uid)
    ]
    # Concatenate the generic packet count bpf program to it.
    instructions += (INS_BPF_PARAM_STORE + BpfFuncCountPacketInit(self.map_fd)
                     + INS_SK_FILTER_ACCEPT + INS_PACK_COUNT_UPDATE
                     + INS_SK_FILTER_ACCEPT)
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_SOCKET_FILTER,
                                   instructions)
    packet_count = 10
    uid = TEST_UID
    with net_test.RunAsUid(uid):
      self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, self.map_fd, uid)
      SocketUDPLoopBack(packet_count, 4, self.prog_fd)
      self.assertEqual(packet_count, bpf.LookupMap(self.map_fd, uid).value)
      bpf.DeleteMap(self.map_fd, uid)
      SocketUDPLoopBack(packet_count, 6, self.prog_fd)
      self.assertEqual(packet_count, bpf.LookupMap(self.map_fd, uid).value)


@unittest.skipUnless(HAVE_EBPF_ACCOUNTING,
                     "Cgroup BPF is not fully supported")
class BpfCgroupTest(net_test.NetworkTest):

  @classmethod
  def setUpClass(cls):
    super(BpfCgroupTest, cls).setUpClass()
    cls._cg_dir = tempfile.mkdtemp(prefix="cg_bpf-")
    cmd = "mount -t cgroup2 cg_bpf %s" % cls._cg_dir
    try:
      subprocess.check_call(cmd.split())
    except subprocess.CalledProcessError:
      # If an exception is thrown in setUpClass, the test fails and
      # tearDownClass is not called.
      os.rmdir(cls._cg_dir)
      raise
    cls._cg_fd = os.open(cls._cg_dir, os.O_DIRECTORY | os.O_RDONLY)

  @classmethod
  def tearDownClass(cls):
    os.close(cls._cg_fd)
    subprocess.call(("umount %s" % cls._cg_dir).split())
    os.rmdir(cls._cg_dir)
    super(BpfCgroupTest, cls).tearDownClass()

  def setUp(self):
    super(BpfCgroupTest, self).setUp()
    self.prog_fd = -1
    self.map_fd = -1

  def tearDown(self):
    if self.prog_fd >= 0:
      os.close(self.prog_fd)
    if self.map_fd >= 0:
      os.close(self.map_fd)
    try:
      bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_EGRESS)
    except socket.error:
      pass
    try:
      bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)
    except socket.error:
      pass
    try:
      bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_SOCK_CREATE)
    except socket.error:
      pass
    super(BpfCgroupTest, self).tearDown()

  def testCgroupBpfAttach(self):
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_CGROUP_SKB,
                                   INS_BPF_EXIT_BLOCK)
    bpf.BpfProgAttach(self.prog_fd, self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)
    bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)

  def testCgroupIngress(self):
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_CGROUP_SKB,
                                   INS_BPF_EXIT_BLOCK)
    bpf.BpfProgAttach(self.prog_fd, self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)
    self.assertRaisesErrno(errno.EAGAIN, SocketUDPLoopBack, 1, 4, None)
    self.assertRaisesErrno(errno.EAGAIN, SocketUDPLoopBack, 1, 6, None)
    bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)
    SocketUDPLoopBack(1, 4, None)
    SocketUDPLoopBack(1, 6, None)

  def testCgroupEgress(self):
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_CGROUP_SKB,
                                   INS_BPF_EXIT_BLOCK)
    bpf.BpfProgAttach(self.prog_fd, self._cg_fd, bpf.BPF_CGROUP_INET_EGRESS)
    self.assertRaisesErrno(errno.EPERM, SocketUDPLoopBack, 1, 4, None)
    self.assertRaisesErrno(errno.EPERM, SocketUDPLoopBack, 1, 6, None)
    bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_EGRESS)
    SocketUDPLoopBack(1, 4, None)
    SocketUDPLoopBack(1, 6, None)

  def testCgroupBpfUid(self):
    self.map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, KEY_SIZE, VALUE_SIZE,
                                TOTAL_ENTRIES)
    # Similar to the program used in testGetSocketUid.
    instructions = [
        bpf.BpfMov64Reg(bpf.BPF_REG_6, bpf.BPF_REG_1),
        bpf.BpfFuncCall(bpf.BPF_FUNC_get_socket_uid)
    ]
    instructions += (INS_BPF_PARAM_STORE
                     + BpfFuncCountPacketInit(self.map_fd)
                     + INS_CGROUP_ACCEPT
                     + INS_PACK_COUNT_UPDATE
                     + INS_CGROUP_ACCEPT)
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_CGROUP_SKB, instructions)
    bpf.BpfProgAttach(self.prog_fd, self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)
    packet_count = 20
    uid = TEST_UID
    with net_test.RunAsUid(uid):
      self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, self.map_fd, uid)
      SocketUDPLoopBack(packet_count, 4, None)
      self.assertEqual(packet_count, bpf.LookupMap(self.map_fd, uid).value)
      bpf.DeleteMap(self.map_fd, uid)
      SocketUDPLoopBack(packet_count, 6, None)
      self.assertEqual(packet_count, bpf.LookupMap(self.map_fd, uid).value)
    bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_INGRESS)

  def checkSocketCreate(self, family, socktype, success):
    try:
      sock = socket.socket(family, socktype, 0)
      sock.close()
    except socket.error as e:
      if success:
        self.fail("Failed to create socket family=%d type=%d err=%s" %
                  (family, socktype, os.strerror(e.errno)))
      return
    if not success:
      self.fail("unexpected socket family=%d type=%d created, should be blocked"
                % (family, socktype))

  def trySocketCreate(self, success):
    for family in [socket.AF_INET, socket.AF_INET6]:
      for socktype in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
        self.checkSocketCreate(family, socktype, success)

  @unittest.skipUnless(HAVE_EBPF_SOCKET,
                       "Cgroup BPF socket is not supported")
  def testCgroupSocketCreateBlock(self):
    instructions = [
        bpf.BpfFuncCall(bpf.BPF_FUNC_get_current_uid_gid),
        bpf.BpfAlu64Imm(bpf.BPF_AND, bpf.BPF_REG_0, 0xfffffff),
        bpf.BpfJumpImm(bpf.BPF_JNE, bpf.BPF_REG_0, TEST_UID, 2),
    ]
    instructions += INS_BPF_EXIT_BLOCK + INS_CGROUP_ACCEPT
    self.prog_fd = bpf.BpfProgLoad(bpf.BPF_PROG_TYPE_CGROUP_SOCK, instructions)
    bpf.BpfProgAttach(self.prog_fd, self._cg_fd,
                      bpf.BPF_CGROUP_INET_SOCK_CREATE)
    with net_test.RunAsUid(TEST_UID):
      # Socket creation with target uid should fail
      self.trySocketCreate(False)
    # Socket create with different uid should success
    self.trySocketCreate(True)
    bpf.BpfProgDetach(self._cg_fd, bpf.BPF_CGROUP_INET_SOCK_CREATE)
    with net_test.RunAsUid(TEST_UID):
      self.trySocketCreate(True)

if __name__ == "__main__":
  unittest.main()
