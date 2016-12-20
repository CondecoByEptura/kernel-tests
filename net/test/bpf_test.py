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
import struct
import unittest

import bpf
import csocket
import cstruct
import net_test

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
HAVE_EBPF_SUPPORT = net_test.LINUX_VERSION >= (4, 4, 0)

class BpfTest(net_test.NetworkTest):

  @unittest.skipUnless(HAVE_EBPF_SUPPORT, "eBPF function not fully supported")
  def testCreateMap(self):
    key, value = 1, 1
    map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, 4, 4, 100)
    self.assertGreater(map_fd, 0)
    bpf.UpdateMap(map_fd, key, value)
    self.assertEquals(bpf.LookupMap(map_fd, key).value, value)
    bpf.DeleteMap(map_fd, key)
    self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, map_fd, key)

  @unittest.skipUnless(HAVE_EBPF_SUPPORT, "eBPF function not fully supported")
  def testIterateMap(self):
    map_fd = bpf.CreateMap(bpf.BPF_MAP_TYPE_HASH, 4, 4, 100)
    self.assertGreater(map_fd, 0)
    value = 1024
    for key in xrange(1, 100) :
      bpf.UpdateMap(map_fd, key, value)
    for key in xrange(1, 100) :
      self.assertEquals(bpf.LookupMap(map_fd, key).value, value);
    self.assertRaisesErrno(errno.ENOENT, bpf.LookupMap, map_fd, 101)
    key = 0
    count = 0
    while 1:
      try:
        result = bpf.GetNextKey(map_fd, key)
      except:
        break;
      else:
        key = result.value
        self.assertGreater(key, 0)
        self.assertEquals(bpf.LookupMap(map_fd, key).value, value)
        count = count + 1
    self.assertEquals(count, 99)

if __name__ == "__main__":
  unittest.main()
