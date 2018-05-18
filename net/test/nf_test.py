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

import unittest

import errno
from socket import *

import multinetwork_base
import net_test

class NetilterTest(multinetwork_base.MultiNetworkBaseTest):
  def setUp(self):
    multinetwork_base.MultiNetworkBaseTest.setUp(self)
    net_test.RunIptablesCommand(4, "-A OUTPUT -d 1.2.3.4 -j REJECT")
    net_test.RunIptablesCommand(6, "-A OUTPUT -d ::1:2:3:4 -j REJECT")

  def tearDown(self):
    net_test.RunIptablesCommand(4, "-D OUTPUT -d 1.2.3.4 -j REJECT")
    net_test.RunIptablesCommand(6, "-D OUTPUT -d ::1:2:3:4 -j REJECT")
    multinetwork_base.MultiNetworkBaseTest.tearDown(self)

  # Test a rejected TCP connect. The responding ICMP may not have skb->dev set.
  # This tests the local-ICMP output-input path.
  def testRejectTcp(self):
    sock = net_test.TCPSocket(net_test.GetAddressFamily(4))
    netid = self.RandomNetid()
    self.SelectInterface(sock, netid, "mark")

    # Expect this to fail with ICMP unreachable
    try:
        sock.connect(("1.2.3.4", 53))
    except IOError:
        pass

  # Test a rejected UDP connect. The responding ICMP may not have skb->dev set.
  def testRejectUdp(self):
    sock = net_test.UDPSocket(net_test.GetAddressFamily(4))
    netid = self.RandomNetid()
    self.SelectInterface(sock, netid, "mark")

    # Expect this to fail with ICMP unreachable
    try:
        sock.sendto(net_test.UDP_PAYLOAD, ("1.2.3.4", 53))
    except IOError:
        pass


if __name__ == "__main__":
  unittest.main()
