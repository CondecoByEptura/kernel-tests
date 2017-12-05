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

'''Test cases for kernel interface under /proc/sys/kernel/random/.'''

import os
import unittest
import uuid

from cki.utils import shell

RANDOM_DIR = '/proc/sys/kernel/random/'
BOOT_ID_PATH = os.path.join(RANDOM_DIR, 'boot_id')
UUID_PATH = os.path.join(RANDOM_DIR, 'uuid')


class RandomTest(unittest.TestCase):

  def testBootIdFormat(self):
    '''Test /proc/sys/kernel/random/boot_id.

    Make sure it contains a well formated UUID string.
    '''

    boot_id = shell.call('cat %s' % BOOT_ID_PATH).rstrip()
    # If boot_id as a malformed hexadecimal UUID string, constructing a UUID
    # from it will throw an exception.
    uuid.UUID(boot_id)

  def testReadUuidTwice(self):
    '''Test /proc/sys/kernel/random/uuid.

    Each read of this file must generate a new UUID.
    '''

    output = shell.call('cat %s' % UUID_PATH).rstrip()
    first_uuid = uuid.UUID(output)

    output = shell.call('cat %s' % UUID_PATH).rstrip()
    second_uuid = uuid.UUID(output)

    self.assertNotEqual(first_uuid, second_uuid)


if __name__ == '__main__':
  unittest.main()
