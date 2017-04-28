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

"""Unit tests for xt_qtaguid."""

import errno
from socket import *  # pylint: disable=wildcard-import
import unittest
import os
import csocket
import net_test

CTRL_PROCPATH = "/proc/net/xt_qtaguid/ctrl"


class QtaguidTest(net_test.NetworkTest):

  def writeToCtrl(self, command):
    ctrl_file = open(CTRL_PROCPATH, 'w')
    ctrl_file.write(command)
    ctrl_file.close()

  def checkTag(self, tag, uid):
    for line in open(CTRL_PROCPATH, 'r').readlines():
      if "tag=0x{0:x} (uid={1})".format((tag|uid), uid) in line:
        return True
    return False

  def setIptablesRule(self, is_add, is_gid, my_id):
    add_del = "-A" if is_add else "-D"
    uid_gid = "--gid-owner" if is_gid else "--uid-owner"
    args = "iptables %s OUTPUT -m owner %s %d -j DROP" % (
        add_del, uid_gid, my_id)
    iptables_path = "/sbin/iptables"
    if not os.access(iptables_path, os.X_OK):
      iptables_path = "/system/bin/iptables"
    ret = os.spawnvp(os.P_WAIT, iptables_path, args.split(" "))
    if ret:
      raise ConfigurationError("Setup command failed: %s" % args)

  @unittest.skip("no avalaile yet")
  def testCloseWithoutUntag(self):
    self.dev_file = open("/dev/xt_qtaguid", "r");
    sk = socket(AF_INET, SOCK_DGRAM, 0)
    uid = os.getuid()
    tag = 0xff00ff00 << 32
    command =  "t %d %d %d" % (sk.fileno(), tag, uid)
    self.writeToCtrl(command)
    self.assertTrue(self.checkTag(tag, uid))
    sk.close();
    self.assertFalse(self.checkTag(tag, uid))
    self.dev_file.close();

  @unittest.skip("not avalaible yet")
  def testTagWithoutDeviceOpen(self):
    sk = socket(AF_INET, SOCK_DGRAM, 0)
    uid = os.getuid()
    tag = 0xff00ff00 << 32
    command = "t %d %d %d" % (sk.fileno(), tag, uid)
    self.writeToCtrl(command)
    self.assertTrue(self.checkTag(tag, uid))
    self.dev_file = open("/dev/xt_qtaguid", "r")
    sk.close()
    self.assertFalse(self.checkTag(tag, uid))
    self.dev_file.close();

  def testUidMatch(self):
    self.setIptablesRule(True, False, os.getuid())
    s = socket(AF_INET, SOCK_DGRAM, 0);
    addr = "127.0.0.1"
    s.bind((addr, 0))
    addr = s.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.setIptablesRule(False, False, os.getuid())
    s.sendto("foo", addr)
    data, addr = csocket.Recvfrom(s, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)

  def testGidMatch(self):
    self.setIptablesRule(True, True, os.getgid())
    s = socket(AF_INET, SOCK_DGRAM, 0);
    addr = "127.0.0.1"
    s.bind((addr, 0))
    addr = s.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.setIptablesRule(False, True, os.getgid())
    s.sendto("foo", addr)
    data, addr = csocket.Recvfrom(s, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)

  @unittest.skip("no avalaile yet")
  def testCheckNotMatchGid(self):
    self.assertIn("match_no_sk_gid", open(CTRL_PROCPATH, 'r').read())


if __name__ == "__main__":
  unittest.main()
