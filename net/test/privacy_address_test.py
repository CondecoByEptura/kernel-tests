#!/usr/bin/python
#
# Copyright 2020 The Android Open Source Project
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

import collections
from socket import *  # pylint: disable=wildcard-import
import time
import unittest

import iproute
import multinetwork_base
import net_test


IPV6_ADDR_PREFERENCES = 72

IPV6_PREFER_SRC_TMP = 0x0001
IPV6_PREFER_SRC_PUBLIC = 0x0002


class PrivacyAddressBaseTest(multinetwork_base.MultiNetworkBaseTest):

  """Base class for privacy address tests.

  Individual tests are subclasses of this class. This exists to ensure that each
  test runs just after MultinetworkBaseTest.setUpClass and thus starts with a
  known set of IPv6 addresses on each interface. Otherwise, the set of addresses
  seen by each test would depend on which tests previously ran.
  """

  Address = collections.namedtuple("Address",
                                   "addr flags scope ifindex valid preferred")

  class AddressesByType(
      collections.namedtuple("AddressesByType", "linklocal stable privacy")):

    def TotalCount(self):
      total = 0
      for field in self._fields:
        total += len(getattr(self, field))
      return total


  def setUp(self):
    # Enable privacy addresses.
    # It's up to the test to send an RA if it wants them though.
    self.SetIPv6SysctlOnAllIfaces("use_tempaddr", "2")

    # Prevent flaky tests by ensuring that all interface have exactly the
    # expected number of addresses when each testcase starts.
    for netid in self.tuns:
      self.WaitForAddresses(netid, 2, linklocal=1, stable=1)


  def FromNetlinkAddress(self, ifaddrmsg, attrs):
    valid = attrs["IFA_CACHEINFO"].valid
    preferred = attrs["IFA_CACHEINFO"].prefered  # NOTYPO
    return self.Address(attrs["IFA_ADDRESS"], ifaddrmsg.flags, ifaddrmsg.scope,
                        ifaddrmsg.index, valid, preferred)

  @staticmethod
  def IsLinkLocal(addr):
    return addr.scope == iproute.RT_SCOPE_LINK

  @staticmethod
  def IsGlobalStable(addr):
    return (addr.scope == iproute.RT_SCOPE_UNIVERSE and
            (addr.flags & iproute.IFA_F_TEMPORARY) == 0)

  @staticmethod
  def IsGlobalPrivacy(addr):
    return (addr.scope == iproute.RT_SCOPE_UNIVERSE and
            (addr.flags & iproute.IFA_F_TEMPORARY) != 0)

  def GetAddresses(self, netid):
    addrs = []
    for ifaddrmsg, attrs in self.iproute.DumpAddresses(6):
      if ifaddrmsg.index not in self.ifindices.values():
        continue
      if netid is None or ifaddrmsg.index == self.ifindices[netid]:
        addrs.append(self.FromNetlinkAddress(ifaddrmsg, attrs))
    return addrs

  def GetAddressesByType(self, netid):
    addrs = self.GetAddresses(netid)
    bytype = self.AddressesByType([], [], [])
    for addr in addrs:
      if self.IsLinkLocal(addr): bytype.linklocal.append(addr)
      elif self.IsGlobalStable(addr): bytype.stable.append(addr)
      elif self.IsGlobalPrivacy(addr): bytype.privacy.append(addr)
      else: raise ValueError("Unknown type for address: %s" % addr)

    return bytype

  def WaitForAddresses(self, netid, total,
                       linklocal=None, stable=None, privacy=None):
    """Wait for addresses to appear. Prevents flaky tests."""
    for i in range(20):
      addrs = self.GetAddresses(netid)
      if len(addrs) == total:
        return addrs
      time.sleep(0.05)
      addrs = self.GetAddresses(netid)
    self.fail("%d addresses did not appear after waiting 1 second" % total)

    bytype = self.GetAddressesByType(netid)
    if linklocal is not None:
      self.assertEqual(linklocal, len(bytype.linklocal))
    if stable is not None:
      self.assertEqual(stable, len(bytype.stable))
    if privacy is not None:
      self.assertEqual(privacy, len(bytype.privacy))

  def assertSourceAddressForConnectionIn(self, addrlist, netid, addrpref):
    s = net_test.UDPSocket(AF_INET6)
    self.SelectInterface(s, netid, "mark")
    if addrpref is not None:
      s.setsockopt(IPPROTO_IPV6, net_test.IPV6_ADDR_PREFERENCES, addrpref)
    s.connect((net_test.IPV6_ADDR, 53))
    srcaddr, port = s.getsockname()[:2]
    self.assertTrue(any(srcaddr == a.addr for a in addrlist))

  @staticmethod
  def GetIID(addr):
    addr = inet_pton(AF_INET6, addr)
    addr = "\x00" * 8 + addr[8:]
    return inet_ntop(AF_INET6, addr)


class PrivacyAddressPreferenceTest(PrivacyAddressBaseTest):

  def testPrivacyAddressesPreference(self):
    for netid in self.tuns:
      # Now send an RA and expect to see a privacy address as well.
      self.SendRA(netid)
      self.WaitForAddresses(netid, 3, linklocal=1, stable=1, privacy=1)

    # Check that connections use privacy addresses by default.
    for netid in self.tuns:
      self.assertSourceAddressForConnectionIn(
          self.GetAddressesByType(netid).privacy, netid, None)
      self.assertSourceAddressForConnectionIn(
          self.GetAddressesByType(netid).stable, netid,
          net_test.IPV6_PREFER_SRC_PUBLIC)

    # but with PREFER_SRC_PUBLIC uses stable addresses.
    self.SetIPv6SysctlOnAllIfaces("use_tempaddr", "1")
    for netid in self.tuns:
      self.assertSourceAddressForConnectionIn(
          self.GetAddressesByType(netid).stable, netid, None)
      self.assertSourceAddressForConnectionIn(
          self.GetAddressesByType(netid).privacy, netid,
          net_test.IPV6_PREFER_SRC_TMP)


class PrivacyAddressLifetimeTest(PrivacyAddressBaseTest):

  def testRefreshLifetime(self):
    for netid in self.tuns:
      # Create privacy addresses with lifetime of 6000s.
      self.SendRA(netid, validity=600)
      self.WaitForAddresses(netid, 3, linklocal=1, stable=1, privacy=1)
      oldaddr = self.GetAddressesByType(netid).privacy[0]

      # Send an RA with a higher lifetime. No new addresses should be created
      # and the existing privacy address lifetime should increase.
      self.SendRA(netid, validity=1200)
      self.WaitForAddresses(netid, 3, linklocal=1, stable=1, privacy=1)
      newaddr = self.GetAddressesByType(netid).privacy[0]

      self.assertEqual(oldaddr.preferred, 6000)
      self.assertEqual(oldaddr.valid, 6000)
      self.assertEqual(newaddr.preferred, 12000)
      self.assertEqual(newaddr.valid, 12000)

      # Don't simply assert that oldaddr is equal to newaddr because in
      # addition to the lifetimes being different, things like the flags might
      # be different as well.
      self.assertEqual(oldaddr.ifindex, newaddr.ifindex)
      self.assertEqual(oldaddr.scope, newaddr.scope)
      self.assertEqual(oldaddr.flags & iproute.IFA_F_TEMPORARY,
                       newaddr.flags & iproute.IFA_F_TEMPORARY)


if __name__ == "__main__":
  unittest.main()
