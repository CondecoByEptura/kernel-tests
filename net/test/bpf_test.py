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


@unittest.skipUnless(HAVE_EBPF_SUPPORT,
                     "eBPF function not fully supported")
class BpfTest(net_test.NetworkTest):

  def testCreateMap(self):
    key, value = 1, 1
    map_fd = CreateMap(BPF_MAP_TYPE_HASH, 4, 4, 100)
    UpdateMap(map_fd, key, value)
    self.assertEquals(LookupMap(map_fd, key).value, value)
    DeleteMap(map_fd, key)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, map_fd, key)

  def testIterateMap(self):
    map_fd = CreateMap(BPF_MAP_TYPE_HASH, 4, 4, 100)
    value = 1024
    for key in xrange(1, 100):
      UpdateMap(map_fd, key, value)
    for key in xrange(1, 100):
      self.assertEquals(LookupMap(map_fd, key).value, value)
    self.assertRaisesErrno(errno.ENOENT, LookupMap, map_fd, 101)
    key = 0
    count = 0
    while 1:
      if count == 99:
        self.assertRaisesErrno(errno.ENOENT, GetNextKey, map_fd, key)
        break
      else:
        result = GetNextKey(map_fd, key)
        key = result.value
        self.assertGreater(key, 0)
        self.assertEquals(LookupMap(map_fd, key).value, value)
        count += 1

  def testProgLoad(self):
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    # Load a program that does nothing except pass every packet it receives
    # It should not block the packet transmission otherwise the test fails.
    prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    BpfProgAttachSocket(sock.fileno(), prog_fd)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    sock.sendto("foo", addr)
    data, addr = csocket.Recvfrom(sock, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)

  def testPacketBlock(self):
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfMov64Imm(BPF_REG_0, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    BpfProgAttachSocket(sock.fileno(), prog_fd)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sock.sendto("foo", addr)
    self.assertRaisesErrno(errno.EAGAIN, csocket.Recvfrom, sock, 4096, 0)

  def testPacketCount(self):
    map_fd = CreateMap(BPF_MAP_TYPE_HASH, 4, 4, 100)
    key = 0xf0f0
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfLoadMapFd(map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Imm(BPF_REG_7, key)
    bpf_prog += BpfStxMem(BPF_W, BPF_REG_10, BPF_REG_7, -4)
    bpf_prog += BpfMov64Reg(BPF_REG_8, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_8, -4)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_8)
    bpf_prog += BpfFuncLookupMap()
    bpf_prog += BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10)
    bpf_prog += BpfLoadMapFd(map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_8)
    bpf_prog += BpfStMem(BPF_W, BPF_REG_10, -8, 1)
    bpf_prog += BpfMov64Reg(BPF_REG_3, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_3, -8)
    bpf_prog += BpfMov64Imm(BPF_REG_4, 0)
    bpf_prog += BpfFuncUpdateMap()
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_0)
    bpf_prog += BpfMov64Imm(BPF_REG_1, 1)
    bpf_prog += BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1,
                           0, 0)
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    # this program loaded is used to counting the packet transmitted through
    # a target socket. It will store the packet count into the eBPF map and we
    # will verify if the counting result is correct.
    prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    BpfProgAttachSocket(sock.fileno(), prog_fd)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    packet_count = 100
    for i in xrange(packet_count):
      sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)
    self.assertEquals(LookupMap(map_fd, key).value, packet_count)

  @unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                       "BPF helper function is not fully supported")
  def testGetSocketCookie(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, 8, 4, 10)
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfFuncGetSocketCookie()
    bpf_prog += BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8)
    bpf_prog += BpfMov64Reg(BPF_REG_7, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_7, -8)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfFuncLookupMap()
    bpf_prog += BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfStMem(BPF_W, BPF_REG_10, -16, 1)
    bpf_prog += BpfMov64Reg(BPF_REG_3, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_3, -16)
    bpf_prog += BpfMov64Imm(BPF_REG_4, 0)
    bpf_prog += BpfFuncUpdateMap()
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_0)
    bpf_prog += BpfMov64Imm(BPF_REG_1, 1)
    bpf_prog += BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1,
                           0, 0)
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    # this program loaded is used to counting the packet transmitted through
    # a target socket. It will store the packet count into the eBPF map and we
    # will verify if the counting result is correct.
    prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    BpfProgAttachSocket(sock.fileno(), prog_fd)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    packet_count = 100
    for i in xrange(packet_count):
      sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)
    self.sock_diag = sock_diag.SockDiag()
    real_cookie = self.sock_diag.FindSockDiagFromFd(sock).id.cookie
    cookie = struct.unpack('=Q', real_cookie)[0]
    self.assertEquals(LookupMap(self.map_fd, cookie).value, packet_count)

  @unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                       "BPF helper function is not fully supported")
  def testGetSocketUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, 8, 4, 10)
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfFuncGetSocketUid()
    bpf_prog += BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8)
    bpf_prog += BpfMov64Reg(BPF_REG_7, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_7, -8)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfFuncLookupMap()
    bpf_prog += BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfStMem(BPF_W, BPF_REG_10, -16, 1)
    bpf_prog += BpfMov64Reg(BPF_REG_3, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_3, -16)
    bpf_prog += BpfMov64Imm(BPF_REG_4, 0)
    bpf_prog += BpfFuncUpdateMap()
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_0)
    bpf_prog += BpfMov64Imm(BPF_REG_1, 1)
    bpf_prog += BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1,
                           0, 0)
    bpf_prog += BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    # this program loaded is used to counting the packet transmitted through
    # a target socket. It will store the packet count into the eBPF map and we
    # will verify if the counting result is correct.
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_SOCKET_FILTER,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    BpfProgAttachSocket(sock.fileno(), self.prog_fd)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    packet_count = 100
    for i in xrange(packet_count):
      sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)
    uid = os.getuid()
    self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count)

@unittest.skipUnless(HAVE_CGROUP_HELPER_SUPPORT,
                     "Cgroup BPF is not fully supported")
class BpfCgroupTest(net_test.NetworkTest):

  def setUp(self):
    if not os.path.isdir("/media"):
      os.mkdir('/media')
    os.system('mount -t cgroup2 cg_bpf /media')
    self.prog_fd = -1
    self.map_fd = -1
    self.cg_fd = os.open('/media', os.O_DIRECTORY | os.O_RDONLY)

  def tearDown(self):
    if self.prog_fd > 0:
      os.close(self.prog_fd)
    if self.map_fd > 0:
      os.close(self.map_fd)
    os.close(self.cg_fd)
    os.system('umount cg_bpf')

  def testCgBpfAttach(self):
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfMov64Imm(BPF_REG_0, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)

  def testCgroupIngress(self):
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfMov64Imm(BPF_REG_0, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    sock.sendto("foo", addr)
    self.assertRaisesErrno(errno.EAGAIN, csocket.Recvfrom, sock, 4096, 0)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)
    sock.sendto("foo", addr)
    data, retaddr = csocket.Recvfrom(sock, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, retaddr)

  def testCgroupEgress(self):
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfMov64Imm(BPF_REG_0, 0)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_EGRESS)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.settimeout(1)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    self.assertRaisesErrno(errno.EPERM, sock.sendto, "foo", addr)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_EGRESS)
    sock.sendto("foo", addr)
    data, retaddr = csocket.Recvfrom(sock, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, retaddr)

  def testCgroupBpfUid(self):
    self.map_fd = CreateMap(BPF_MAP_TYPE_HASH, 8, 4, 10)
    bpf_prog = BpfMov64Reg(BPF_REG_6, BPF_REG_1)
    bpf_prog += BpfFuncGetSocketUid()
    bpf_prog += BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8)
    bpf_prog += BpfMov64Reg(BPF_REG_7, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_7, -8)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfFuncLookupMap()
    bpf_prog += BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10)
    bpf_prog += BpfLoadMapFd(self.map_fd, BPF_REG_1)
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_7)
    bpf_prog += BpfStMem(BPF_W, BPF_REG_10, -16, 1)
    bpf_prog += BpfMov64Reg(BPF_REG_3, BPF_REG_10)
    bpf_prog += BpfAlu64Imm(BPF_ADD, BPF_REG_3, -16)
    bpf_prog += BpfMov64Imm(BPF_REG_4, 0)
    bpf_prog += BpfFuncUpdateMap()
    bpf_prog += BpfMov64Imm(BPF_REG_0, 1)
    bpf_prog += BpfExitInsn()
    bpf_prog += BpfMov64Reg(BPF_REG_2, BPF_REG_0)
    bpf_prog += BpfMov64Imm(BPF_REG_1, 1)
    bpf_prog += BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1,
                           0, 0)
    bpf_prog += BpfMov64Imm(BPF_REG_0, 1)
    bpf_prog += BpfExitInsn()
    insn_buff = ctypes.create_string_buffer(bpf_prog)
    # this program loaded is used to counting the packet transmitted through
    # a target socket. It will store the packet count into the eBPF map and we
    # will verify if the counting result is correct.
    self.prog_fd = BpfProgLoad(BPF_PROG_TYPE_CGROUP_SKB,
                          ctypes.addressof(insn_buff),
                          len(insn_buff), BpfInsn._length)
    BpfProgAttach(self.prog_fd, self.cg_fd, BPF_CGROUP_INET_INGRESS)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    addr = "127.0.0.1"
    sock.bind((addr, 0))
    addr = sock.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    packet_count = 100
    for i in xrange(packet_count):
      sock.sendto("foo", addr)
      data, retaddr = csocket.Recvfrom(sock, 4096, 0)
      self.assertEqual("foo", data)
      self.assertEqual(sockaddr, retaddr)
    uid = os.getuid()
    self.assertEquals(LookupMap(self.map_fd, uid).value, packet_count)
    BpfProgDetach(self.cg_fd, BPF_CGROUP_INET_INGRESS)

if __name__ == "__main__":
  unittest.main()
