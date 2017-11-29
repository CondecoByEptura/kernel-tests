#!/usr/bin/python
#
# Copyright 2017 The Android Open Source Project
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

import os
import unittest
from utils import shell

POWER_DIR = '/sys/power/'
POWER_STATE_PATH = os.path.join(POWER_DIR, 'state')
SUPPORTED_SLEEP_STATES = [
    'disk',
    'freeze',
    'mem',
    'standby',
]

class RandomTest(unittest.TestCase):
  def testBootIdFormat(self):
    sleep_states = shell.call('cat %s' % POWER_STATE_PATH).split()
    self.assertTrue(set(sleep_states).issubset(SUPPORTED_SLEEP_STATES))

if __name__ == '__main__':
  unittest.main()
