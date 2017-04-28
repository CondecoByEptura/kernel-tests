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

"""Unit tests for csocket."""

from socket import *  # pylint: disable=wildcard-import
import unittest
import os
import csocket

CTRL_PROCPATH = "/proc/net/xt_qtaguid/ctrl"

class QtaguidTest(unittest.TestCase):

  @classmethod
  def setUpClass(self):
    self.dev_file = open("/dev/xt_qtaguid", "r");

  def writeToCtrl(self, command):
    ctrl_file = open(CTRL_PROCPATH, 'w')
    ctrl_file.write(command)
    ctrl_file.close()

  def checkTag(self, tag, uid):
    with open(CTRL_PROCPATH, 'r') as ctrl_file:
      for line in ctrl_file:
        if "tag=0x{0:x} (uid={1})".format((tag|uid), uid) in line:
          ctrl_file.close()
          return True
    ctrl_file.close()
    return False

  def testCloseWithoutUntag(self):
    sk = socket(AF_INET, SOCK_DGRAM, 0)
    uid = os.getuid()
    tag = 0xff00ff00 << 32
    command = 't {0} {1} {2}'.format(sk.fileno(), tag, uid);
    self.writeToCtrl(command)
    self.assertTrue(self.checkTag(tag, uid))
    sk.close();
    self.assertFalse(self.checkTag(tag, uid))

  @classmethod
  def tearDownClass(self):
    self.dev_file.close();


if __name__ == "__main__":
  unittest.main()
