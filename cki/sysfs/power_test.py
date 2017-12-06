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

"""Test cases for kernel interface under /sys/power/."""

import os
import unittest
import uuid

from cki.utils import shell

POWER_DIR = '/sys/power/'
POWER_STATE_PATH = os.path.join(POWER_DIR, 'state')
WAKE_LOCK_PATH = os.path.join(POWER_DIR, 'wake_lock')
WAKE_UNLOCK_PATH = os.path.join(POWER_DIR, 'wake_unlock')

# All sleep states supported by /sys/power/state per
# Documentation/power/states.txt
SUPPORTED_SLEEP_STATES = [
    'disk',
    'freeze',
    'mem',
    'standby',
]


class SysPowerTest(unittest.TestCase):

  def testSupportedSleepStates(self):
    """Check sleep states in /sys/power/state."""

    sleep_states = shell.call('cat %s' % POWER_STATE_PATH).split()
    # /sys/power/state must contains only supported sleep states.
    self.assertTrue(set(sleep_states).issubset(SUPPORTED_SLEEP_STATES))
    # Suspend-to-idle (aka "freeze") state must always be supported.
    self.assertTrue('freeze' in sleep_states)

  def testWakeLockUnlock(self):
    """Sanity checking that locking/unlocking a wake_lock works."""

    # Acquire a wake_lock.
    lock_name = uuid.uuid4().hex
    shell.call('echo %s > %s' % (lock_name, WAKE_LOCK_PATH))

    # Check that lock_name is reported as a active wakeup source.
    active_sources = shell.call('cat %s' % WAKE_LOCK_PATH).split()
    self.assertTrue(lock_name in active_sources)

    # Release the wake_lock.
    shell.call('echo %s > %s' % (lock_name, WAKE_UNLOCK_PATH))

    # Check that lock_name is not a active wakeup source anymore.
    active_sources = shell.call('cat %s' % WAKE_LOCK_PATH).split()
    self.assertTrue(lock_name not in active_sources)
    inactive_sources = shell.call('cat %s' % WAKE_UNLOCK_PATH).split()
    self.assertTrue(lock_name in inactive_sources)


if __name__ == '__main__':
  unittest.main()
