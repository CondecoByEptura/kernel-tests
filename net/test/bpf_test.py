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

import cstruct
import net_test


# TODO: figure out how to make this arch-dependent if we run these tests on non-X86
__NR_bpf = 321

# Constants. TODO: Add more.
BPF_MAP_CREATE = 0

BPF_PROG_TYPE_UNSPEC = 0
BPF_MAP_TYPE_HASH = 1

BpfAttrCreate = cstruct.Struct("bpf_attr_create", "=IIII", "map_type key_size value_size max_entries")

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def CreateMap():
  attr = BpfAttrCreate((BPF_MAP_TYPE_HASH, 4, 4, 100))
  ret = libc.syscall(__NR_bpf, BPF_MAP_CREATE, attr.CPointer(), len(attr))
  return ret


class BpfTest(net_test.NetworkTest):

  def testCreateMap(self):
    self.assertEquals(0, CreateMap())


if __name__ == "__main__":
  unittest.main()
