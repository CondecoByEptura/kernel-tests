#!/usr/bin/python
#
# Copyright 2021 The Android Open Source Project
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

import net_test


class IptablesTest(net_test.NetworkTest):

  def testIdletimerTarget(self):
    # We need to add a proper test.
    #
    # For now we know IDLETIMER is busted due to how upstream
    # vs android common kernel conflict resolution was done.
    self.assertLess(net_test.LINUX_VERSION, (5, 7, 0))


if __name__ == "__main__":
  unittest.main()
