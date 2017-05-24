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

import csocket
import cstruct
import net_test
import socket

# TODO: figure out how to make this arch-dependent if we run these tests
# on non-X86
__NR_bpf = 321
LOG_LEVEL = 1
LOG_SIZE = 65536

# BPF syscall commands constants.
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_PROG_LOAD = 5
BPF_OBJ_PIN = 6
BPF_OBJ_GET = 7
BPF_PROG_ATTACH = 8
BPF_PROG_DETACH = 9
SO_ATTACH_BPF = 50

# BPF map type constant.
BPF_MAP_TYPE_UNSPEC = 0
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4

# BPF program type constant.
BPF_PROG_TYPE_UNSPEC = 0
BPF_PROG_TYPE_SOCKET_FILTER = 1
BPF_PROG_TYPE_KPROBE = 2
BPF_PROG_TYPE_SCHED_CLS = 3
BPF_PROG_TYPE_SCHED_ACT = 4
BPF_PROG_TYPE_TRACEPOINT = 5
BPF_PROG_TYPE_XDP = 6
BPF_PROG_TYPE_PERF_EVENT = 7
BPF_PROG_TYPE_CGROUP_SKB = 8
BPF_PROG_TYPE_CGROUP_SOCK = 9

# BPF program attach type.
BPF_CGROUP_INET_INGRESS = 0
BPF_CGROUP_INET_EGRESS = 1
BPF_CGROUP_INET_SOCK_CREATE = 2

# BPF register constant
BPF_REG_0 = 0
BPF_REG_1 = 1
BPF_REG_2 = 2
BPF_REG_3 = 3
BPF_REG_4 = 4
BPF_REG_5 = 5
BPF_REG_6 = 6
BPF_REG_7 = 7
BPF_REG_8 = 8
BPF_REG_9 = 9
BPF_REG_10 = 10

# BPF instruction constants
BPF_PSEUDO_MAP_FD = 1
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xa0
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40
BPF_K = 0x00
BPF_X = 0x08
BPF_ALU64 = 0x07
BPF_DW = 0x18
BPF_XADD = 0xc0
BPF_MOV = 0xb0

BPF_ARSH = 0xc0
BPF_END = 0xd0
BPF_TO_LE = 0x00
BPF_TO_BE = 0x08

BPF_JNE = 0x50
BPF_JSGT = 0x60

BPF_JSGE = 0x70
BPF_CALL = 0x80
BPF_EXIT = 0x90

# BPF helper function constants
BPF_FUNC_unspec = 0
BPF_FUNC_map_lookup_elem = 1
BPF_FUNC_map_update_elem = 2
BPF_FUNC_map_delete_elem = 3
BPF_FUNC_get_socket_cookie = 46
BPF_FUNC_get_socket_uid = 47

#  These object below belongs to the same kernel union and the types below
#  (e.g., bpf_attr_create) aren't kernel struct names but just different
#  variants of the union.
BpfAttrCreate = cstruct.Struct("bpf_attr_create", "=IIII",
                               "map_type key_size value_size max_entries")
BpfAttrOps = cstruct.Struct("bpf_attr_ops", "=QQQQ",
                            "map_fd key_ptr value_ptr flags")
BpfAttrProgLoad = cstruct.Struct(
    "bpf_attr_prog_load", "=IIQQIIQI", "prog_type insn_cnt insns"
    " license log_level log_size log_buf kern_version")
BpfAttrProgAttach = cstruct.Struct("bpf_attr_prog_attach", "=III",
                                   "target_fd attach_bpf_fd attach_type")
BpfInsn = cstruct.Struct("bpf_insn", "=BBhi", "code dst_src_reg off imm")

BpfSkBuff = cstruct.Struct("bpf_sk_buff", "=LLLLLLLLLLLLLLLLL",
                           "len pkt_type mark queue_mapping protocol vlan_present"
                           " vlan_tci vlan_proto priority ingress_ifindex"
                           " ifindex tc_index cb5 hash tc_classid data data_end")

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)


# BPF program syscalls
def BpfSyscall(op, attr):
  ret = libc.syscall(__NR_bpf, op, attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return ret

def CreateMap(map_type, key_size, value_size, max_entries):
  attr = BpfAttrCreate((map_type, key_size, value_size, max_entries))
  return BpfSyscall(BPF_MAP_CREATE, attr)


def UpdateMap(map_fd, key, value, flags=0):
  c_value = ctypes.c_uint32(value)
  c_key = ctypes.c_uint32(key)
  value_ptr = ctypes.addressof(c_value)
  key_ptr = ctypes.addressof(c_key)
  attr = BpfAttrOps((map_fd, key_ptr, value_ptr, flags))
  BpfSyscall(BPF_MAP_UPDATE_ELEM, attr)


def LookupMap(map_fd, key):
  c_value = ctypes.c_uint32(0)
  c_key = ctypes.c_uint32(key)
  attr = BpfAttrOps(
      (map_fd, ctypes.addressof(c_key), ctypes.addressof(c_value), 0))
  BpfSyscall(BPF_MAP_LOOKUP_ELEM, attr)
  return c_value


def GetNextKey(map_fd, key):
  c_key = ctypes.c_uint32(key)
  c_next_key = ctypes.c_uint32(0)
  attr = BpfAttrOps(
      (map_fd, ctypes.addressof(c_key), ctypes.addressof(c_next_key), 0))
  BpfSyscall(BPF_MAP_GET_NEXT_KEY, attr)
  return c_next_key


def DeleteMap(map_fd, key):
  c_key = ctypes.c_uint32(key)
  attr = BpfAttrOps((map_fd, ctypes.addressof(c_key), 0, 0))
  BpfSyscall(BPF_MAP_DELETE_ELEM, attr)


def BpfProgLoad(prog_type, instructions):
  bpf_prog = "".join(instructions)
  insn_buff = ctypes.create_string_buffer(bpf_prog)
  gpl_license = ctypes.create_string_buffer(b"GPL")
  log_buf = ctypes.create_string_buffer(b"", LOG_SIZE)
  attr = BpfAttrProgLoad((prog_type, len(insn_buff) / BpfInsn._length,
                          ctypes.addressof(insn_buff),
                          ctypes.addressof(gpl_license), LOG_LEVEL,
                          LOG_SIZE, ctypes.addressof(log_buf), 0))
  return BpfSyscall(BPF_PROG_LOAD, attr)


def BpfProgAttachSocket(sock_fd, prog_fd):
  prog_ptr = ctypes.c_uint32(prog_fd)
  ret = libc.setsockopt(sock_fd, socket.SOL_SOCKET, SO_ATTACH_BPF,
                        ctypes.addressof(prog_ptr), ctypes.sizeof(prog_ptr))
  csocket.MaybeRaiseSocketError(ret)


def BpfProgAttach(prog_fd, target_fd, prog_type):
  attr = BpfAttrProgAttach((target_fd, prog_fd, prog_type))
  return BpfSyscall(BPF_PROG_ATTACH, attr)


def BpfProgDetach(target_fd, prog_type):
  attr = BpfAttrProgAttach((target_fd, 0, prog_type))
  return BpfSyscall(BPF_PROG_DETACH, attr)


# BPF program command constructors
def BpfMov64Reg(dst, src):
  code = BPF_ALU64 | BPF_MOV | BPF_X
  dst_src = src << 4 | dst
  ret = BpfInsn((code, dst_src, 0, 0))
  return ret.Pack()


def BpfLdxMem(size, dst, src, off):
  code = BPF_LDX | (size & 0x18) | BPF_MEM
  dst_src = src << 4 | dst
  ret = BpfInsn((code, dst_src, off, 0))
  return ret.Pack()


def BpfStxMem(size, dst, src, off):
  code = BPF_STX | (size & 0x18) | BPF_MEM
  dst_src = src << 4 | dst
  ret = BpfInsn((code, dst_src, off, 0))
  return ret.Pack()


def BpfStMem(size, dst, off, imm):
  code = BPF_ST | (size & 0x18) | BPF_MEM
  dst_src = dst
  ret = BpfInsn((code, dst_src, off, imm))
  return ret.Pack()


def BpfAlu64Imm(op, dst, imm):
  code = BPF_ALU64 | (op & 0xf0) | BPF_K
  dst_src = dst
  ret = BpfInsn((code, dst_src, 0, imm))
  return ret.Pack()


def BpfJumpImm(op, dst, imm, off):
  code = BPF_JMP | (op & 0xf0) | BPF_K
  dst_src = dst
  ret = BpfInsn((code, dst_src, off, imm))
  return ret.Pack()


def BpfRawInsn(code, dst, src, off, imm):
  ret = BpfInsn((code, (src << 4 | dst), off, imm))
  return ret.Pack()


def BpfMov64Imm(dst, imm):
  code = BPF_ALU64 | BPF_MOV | BPF_K
  dst_src = dst
  ret = BpfInsn((code, dst_src, 0, imm))
  return ret.Pack()

def BpfLdAbs(size, imm):
  code = BPF_LD | (size & 0x18) | BPF_ABS
  ret = BpfInsn((code, 0, 0, imm))
  return ret.Pack()

def BpfExitInsn():
  code = BPF_JMP | BPF_EXIT
  ret = BpfInsn((code, 0, 0, 0))
  return ret.Pack()


def BpfLoadMapFd(map_fd, dst):
  code = BPF_LD | BPF_DW | BPF_IMM
  dst_src = BPF_PSEUDO_MAP_FD << 4 | dst
  insn1 = BpfInsn((code, dst_src, 0, map_fd))
  insn2 = BpfInsn((0, 0, 0, map_fd >> 32))
  return insn1.Pack() + insn2.Pack()


def BpfFuncCall(op):
  code = BPF_JMP | BPF_CALL
  dst_src = 0
  ret = BpfInsn((code, dst_src, 0, op))
  return ret.Pack()


# the main code block for eBPF packet counting program. It takes a preloaded key
# from BPF_REG_0 and use it to look up the bpf map, if the element does not
# exist in the map yet, the program will update the map with a new <key, 1>
# pair. Otherwise it will jump to next code block to handle it.
def BpfFuncCountPacketInit(map_fd):
  insPackCountStart = [
      BpfStxMem(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
      BpfMov64Reg(BPF_REG_7, BPF_REG_10),
      BpfAlu64Imm(BPF_ADD, BPF_REG_7, -8),
      BpfLoadMapFd(map_fd, BPF_REG_1),
      BpfMov64Reg(BPF_REG_2, BPF_REG_7),
      BpfFuncCall(BPF_FUNC_map_lookup_elem),
      # if the map element already exist, jump out of this
      # code block and let next part to handle it
      BpfJumpImm(BPF_AND, BPF_REG_0, 0, 10),
      BpfLoadMapFd(map_fd, BPF_REG_1),
      BpfMov64Reg(BPF_REG_2, BPF_REG_7),
      BpfStMem(BPF_W, BPF_REG_10, -16, 1),
      BpfMov64Reg(BPF_REG_3, BPF_REG_10),
      BpfAlu64Imm(BPF_ADD, BPF_REG_3, -16),
      BpfMov64Imm(BPF_REG_4, 0),
      BpfFuncCall(BPF_FUNC_map_update_elem)
  ]
  return insPackCountStart;

# Bpf instruction to block a packet before exist a filter.
insBpfExitBlock = [
    BpfMov64Reg(BPF_REG_6, BPF_REG_1),
    BpfMov64Imm(BPF_REG_0, 0),
    BpfExitInsn()
]

# Bpf instruction for cgroup bpf filter to accept a packet before exit.
insCgroupAccept = [
    BpfMov64Imm(BPF_REG_0, 1),
    BpfExitInsn()
]

# Bpf instruction for socket bpf filter to accept a packet before exit.
insSkFilterAccept = [
    BpfLdxMem(BPF_W, BPF_REG_0, BPF_REG_6, 0),
    BpfExitInsn()
]

# Update a existing map element with +1.
insPackCountUpdate = [
    BpfMov64Reg(BPF_REG_2, BPF_REG_0),
    BpfMov64Imm(BPF_REG_1, 1),
    BpfRawInsn(BPF_STX | BPF_XADD | BPF_W, BPF_REG_2, BPF_REG_1, 0, 0),
]
