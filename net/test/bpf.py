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
import unittest
import struct

import csocket
import cstruct
import net_test


# TODO: figure out how to make this arch-dependent if we run these tests on non-X86
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

# BPF attr struct
BpfAttrCreate = cstruct.Struct("bpf_attr_create", "=IIII",
                               "map_type key_size value_size max_entries")
BpfAttrOperation = cstruct.Struct("bpf_attr_ops", "=QQQQ", "map_fd key_ptr value_ptr flags")
BpfAttrProgLoad = cstruct.Struct("bpf_attr_prog_load", "=IIQQIIQI", "prog_type insn_cnt insns "
                                 "license log_level log_size log_buf kern_version")

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)

def CreateMap(map_type, key_size, value_size, max_entries):
  attr = BpfAttrCreate((map_type, key_size, value_size, max_entries))
  ret = libc.syscall(__NR_bpf, BPF_MAP_CREATE, attr.CPointer(), len(attr))
  return ret

def UpdateMap(map_fd, key, value, flags = 0):
  _value = ctypes.c_uint32(value)
  _key = ctypes.c_uint32(key)
  value_ptr = ctypes.addressof(_value)
  key_ptr = ctypes.addressof(_key)
  attr = BpfAttrOperation((map_fd, key_ptr, value_ptr, flags))
  ret = libc.syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return

def LookupMap(map_fd, key):
  _value = ctypes.c_uint32(0)
  _key = ctypes.c_uint32(key)
  attr = BpfAttrOperation((map_fd, ctypes.addressof(_key), ctypes.addressof(_value), 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return _value

def GetNextKey(map_fd, key):
  _key = ctypes.c_uint32(key)
  _nextkey = ctypes.c_uint32(0)
  attr = BpfAttrOperation((map_fd, ctypes.addressof(_key), ctypes.addressof(_nextkey), 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return _nextkey

def DeleteMap(map_fd, key):
  _key = ctypes.c_uint32(key);
  attr = BpfAttrOperation((map_fd, ctypes.addressof(_key), 0, 0))
  ret = libc.syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, attr.CPointer(), len(attr))
  csocket.MaybeRaiseSocketError(ret)
  return

