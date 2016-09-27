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

import binascii
import posix
import os
import select
from socket import *  # pylint: disable=wildcard-import
import threading
import time
import unittest

import cstruct
import multinetwork_base
import net_test


class ResilientRouterSolicitationTest(multinetwork_base.MultiNetworkBaseTest):
  """Tests for IPv6 'resilient rs' RFC 7559 backoff behaviour.

  Relevant kernel commits:
    upstream net-next:
      f00bar ...
  """
  ROUTER_SOLICIT = 133

  _TEST_NETID = 123
  _PROC_NET_TUNABLE = "/proc/sys/net/ipv6/conf/%s/%s"
  _MAX_RSES_OF_INTEREST = 8

  @classmethod
  def setUpClass(cls):
  	return

  def setUp(self):
  	return

  @classmethod
  def tearDownClass(cls):
  	return

  def tearDown(self):
  	return

  @classmethod
  def isIPv6RouterSolicitation(cls, packet):
    return ((len(packet) >= 14 + 40 + 1) and
            # Use net_test.ETH_P_IPV6 here
            (ord(packet[12]) == 0x86) and
            (ord(packet[13]) == 0xdd) and
            (ord(packet[14]) >> 4 == 6) and
            (ord(packet[14 + 40]) == cls.ROUTER_SOLICIT))

  def makeTunInterface(self, netid):
    defaultDisableIPv6Path = self._PROC_NET_TUNABLE % ("default", "disable_ipv6")
    savedDefaultDisableIPv6 = self.GetSysctl(defaultDisableIPv6Path)
    self.SetSysctl(defaultDisableIPv6Path, 1)
    tun = self.CreateTunInterface(netid)
    self.SetSysctl(defaultDisableIPv6Path, savedDefaultDisableIPv6)
    return tun

  def testRouterSolicitationBackoff(self):
    netid = self._TEST_NETID
    tun = self.makeTunInterface(netid)
    epoll = select.epoll()
    epoll.register(tun, select.EPOLLIN | select.EPOLLPRI)

    PROC_SETTINGS = [
        ("router_solicitation_delay", 1),
        ("router_solicitation_interval", 1),
        ("router_solicitation_max_interval", 8),
        ("router_solicitations", -1),
        ("disable_ipv6", 0)  # MUST be last
    ]

    iface = self.GetInterfaceName(netid)
    for tunable, value in PROC_SETTINGS:
      self.SetSysctl(self._PROC_NET_TUNABLE % (iface, tunable), value)

    prevTime = time.time()

    rsSendTimes = []
    while True:
      epoll.poll(8 * 1.2)
      try:
        packet = posix.read(tun.fileno(), 4096)
      except OSError:
        print "epoll timeout; stopping"
        break

      txTime = time.time()
      if not self.isIPv6RouterSolicitation(packet):
        print "Dropping: " + binascii.hexlify(packet)
        continue

      print "RS: " + binascii.hexlify(packet)
      rsSendTimes.append(txTime - prevTime)
      prevTime = txTime
      print rsSendTimes

      if len(rsSendTimes) >= self._MAX_RSES_OF_INTEREST:
        break

    print ""
    print "Grand total: " + str(rsSendTimes[1:])


if __name__ == "__main__":
  unittest.main()
