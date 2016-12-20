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

# TODO: figure out how to make this arch-dependent if we run these tests
# on non-X86
__NR_bpf = 321

# BPF syscall commands constants.
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_PROG_LOAD = 5
BPF_OBJ_PIN = 6
BPF_OBJ_GET = 7
SOL_SOCKET = 1
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

# BPF instruction constanti
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

# BPF helper function constant
BPF_FUNC_unspec = 0
BPF_FUNC_map_lookup_elem = 1
BPF_FUNC_map_update_elem = 2
BPF_FUNC_map_delete_elem = 3

# BPF attr struct
BpfAttrCreate = cstruct.Struct("bpf_attr_create", "=IIII",
                               "map_type key_size value_size max_entries")
BpfAttrOperation = cstruct.Struct("bpf_attr_ops", "=QQQQ",
                                  "map_fd key_ptr value_ptr flags")
BpfAttrProgLoad = cstruct.Struct(
    "bpf_attr_prog_load", "=IIQQIIQI", "prog_type insn_cnt insns"
    " license log_level log_size log_buf kern_version")
BpfInsn = cstruct.Struct("bpf_insn", "=BBhi", "code dst_src_reg off imm")

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)


# BPF program syscalls
def CreateMap(map_type, key_size, value_size, max_entries):
  attr = BpfAttrCreate((map_type, key_size, value_size, max_entries))
  ret = libc.syscall(__NR_bpf, BPF_MAP_CREATE, attr.CPointer(), len(attr))
  return ret


def UpdateMap(map_fd, key, value, flags=0):
  c_value = ctypes.c_uint32(value)
  c_key = ctypes.c_uint32(key)
  value_ptr = ctypes.addressof(c_value)
  key_ptr = ctypes.addressof(c_key)
  attr = BpfAttrOperation((map_fd, key_ptr, value_ptr, flags))
  ret = libc.syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
                     attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return


def LookupMap(map_fd, key):
  c_value = ctypes.c_uint32(0)
  c_key = ctypes.c_uint32(key)
  attr = BpfAttrOperation(
      (map_fd, ctypes.addressof(c_key), ctypes.addressof(c_value), 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM,
                     attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return c_value


def GetNextKey(map_fd, key):
  c_key = ctypes.c_uint32(key)
  c_next_key = ctypes.c_uint32(0)
  attr = BpfAttrOperation(
      (map_fd, ctypes.addressof(c_key), ctypes.addressof(c_next_key), 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY,
                     attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return c_next_key


def DeleteMap(map_fd, key):
  c_key = ctypes.c_uint32(key)
  attr = BpfAttrOperation((map_fd, ctypes.addressof(c_key), 0, 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_DELETE_ELEM,
                     attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return


def BpfProgLoad(prog_type, insn_ptr, prog_len, insn_len):
  gpl_license = ctypes.create_string_buffer(b"GPL")
  log_buf = ctypes.create_string_buffer(b"", 65536)
  attr = BpfAttrProgLoad(
      (prog_type, prog_len / insn_len, insn_ptr, ctypes.addressof(gpl_license),
       1, 65536, ctypes.addressof(log_buf), 0))
  ret = libc.syscall(__NR_bpf, BPF_PROG_LOAD, attr.CPointer(), len(attr))
  return ret


def BpfProgAttach(sock_fd, prog_fd):
  prog_ptr = ctypes.c_uint32(prog_fd)
  ret = libc.setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
                        ctypes.addressof(prog_ptr), ctypes.sizeof(prog_ptr))
  csocket.MaybeRaiseSocketError(ret)


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


def BpfFuncLookupMap():
  code = BPF_JMP | BPF_CALL
  dst_src = 0
  ret = BpfInsn((code, dst_src, 0, BPF_FUNC_map_lookup_elem))
  return ret.Pack()


def BpfFuncUpdateMap():
  code = BPF_JMP | BPF_CALL
  dst_src = 0
  ret = BpfInsn((code, dst_src, 0, BPF_FUNC_map_update_elem))
  return ret.Pack()


def BpfFuncDeleteMap():
  code = BPF_JMP | BPF_CALL
  dst_src = 0
  ret = BpfInsn((code, dst_src, 0, BPF_FUNC_map_delete_elem))
  return ret.Pack()
