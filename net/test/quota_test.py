#!/usr/bin/python
#
# Copyright 2018 The Android Open Source Project
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

"""Unit tests for xt_quota."""

import errno
from socket import *  # pylint: disable=wildcard-import
import unittest
import os

import net_test
import packets
import tcp_test

class QuotaTest(tcp_test.TcpBaseTest):

  def RunIptablesCommand(self, args):
    self.assertFalse(net_test.RunIptablesCommand(4, args))
    self.assertFalse(net_test.RunIptablesCommand(6, args))

  def setUp(self):
    self.RunIptablesCommand("-N quota_test_OUTPUT")
    self.RunIptablesCommand("-A OUTPUT -j quota_test_OUTPUT")

  def tearDown(self):
    self.RunIptablesCommand("-D OUTPUT -j quota_test_OUTPUT")
    self.RunIptablesCommand("-F quota_test_OUTPUT")
    self.RunIptablesCommand("-X quota_test_OUTPUT")

  def SetIptablesRule(self, version, is_add, bytes_count, drop, inverted):
    add_del = "-A" if is_add else "-D"
    ret = "DROP" if drop else "RETURN"
    if inverted:
      args = "%s quota_test_OUTPUT -m quota ! --quota %s -j %s" % (add_del, bytes_count, ret)
    else:
      args = "%s quota_test_OUTPUT -m quota --quota %s -j %s" % (add_del, bytes_count, ret)
    self.assertFalse(net_test.RunIptablesCommand(version, args))

  def AddIptablesRule(self, version, bytes_count, drop):
    self.SetIptablesRule(version, True, bytes_count, drop, False)

  def AddIptablesInvertedRule(self, version, bytes_count, drop):
    self.SetIptablesRule(version, True, bytes_count, drop, True)

  def DelIptablesRule(self, version, bytes_count, drop):
    self.SetIptablesRule(version, False, bytes_count, drop, False)

  def DelIptablesInvertedRule(self, version, bytes_count, drop):
    self.SetIptablesRule(version, False, bytes_count, drop, True)

  def CheckSendPacket(self, socket, addr):
    socket.sendto("foo", addr)
    data, sockaddr = socket.recvfrom(4096)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)


  def CheckSocketOutput(self, version):
    family = {4: AF_INET, 6: AF_INET6}[version]
    bytes_count = {4: 35, 6: 100} [version]
    s = socket(family, SOCK_DGRAM, 0)
    addr = {4: "127.0.0.1", 6: "::1"}[version]
    s.bind((addr, 0))
    addr = s.getsockname()
    self.AddIptablesRule(version, bytes_count, True)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.CheckSendPacket(s, addr)
    self.AddIptablesRule(version, 10000, False)
    self.CheckSendPacket(s, addr)
    self.DelIptablesRule(version, 10000, False)
    self.DelIptablesRule(version, bytes_count, True)
    self.CheckSendPacket(s, addr)

  def CheckSocketOutputInverted(self, version):
    family = {4: AF_INET, 6: AF_INET6}[version]
    bytes_count = {4: 35, 6: 100} [version]
    s = socket(family, SOCK_DGRAM, 0)
    addr = {4: "127.0.0.1", 6: "::1"}[version]
    s.bind((addr, 0))
    addr = s.getsockname()
    self.AddIptablesInvertedRule(version, bytes_count, True)
    self.CheckSendPacket(s, addr)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.AddIptablesRule(version, 10000, False)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.DelIptablesRule(version, 10000, False)
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.DelIptablesInvertedRule(version, bytes_count, True)
    self.CheckSendPacket(s, addr)

  def testQuotaNotReset(self):
    self.CheckSocketOutput(4)
    self.CheckSocketOutput(6)
    self.CheckSocketOutputInverted(4)
    self.CheckSocketOutputInverted(6)

if __name__ == "__main__":
  unittest.main()
