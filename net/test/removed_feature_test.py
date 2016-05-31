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

import unittest

import gzip
import net_test


class RemovedFeatureTest(net_test.NetworkTest):
  KCONFIG = None

  def loadKernelConfig(self):
    if self.KCONFIG is not None:
      return

    self.KCONFIG = {}
    with gzip.open('/proc/config.gz') as f:
      for line in f:
        line = line.strip()
        parts = line.split("=")
        if (len(parts) == 2):
          # Lines of the form:
          # CONFIG_FOO=y
          self.KCONFIG[parts[0]] = parts[1]

  def testNetfilterRejectWithSocketError(self):
    """Verify that the CONFIG_IP{,6}_NF_TARGET_REJECT_SKERR option is gone.
       See b/28424847 and b/28719525 for more context.
    """
    self.loadKernelConfig()
    self.assertEqual("y", self.KCONFIG["CONFIG_IP_NF_FILTER"])
    self.assertEqual("y", self.KCONFIG["CONFIG_IP_NF_TARGET_REJECT"])
    self.assertTrue("CONFIG_IP_NF_TARGET_REJECT_SKERR" not in self.KCONFIG)

    self.assertEqual("y", self.KCONFIG["CONFIG_IP6_NF_FILTER"])
    self.assertEqual("y", self.KCONFIG["CONFIG_IP6_NF_TARGET_REJECT"])
    self.assertTrue("CONFIG_IP6_NF_TARGET_REJECT_SKERR" not in self.KCONFIG)


if __name__ == "__main__":
  unittest.main()
