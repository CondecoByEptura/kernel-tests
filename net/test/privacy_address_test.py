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

  def setUp(self):
    self.SetIPv6SysctlOnAllIfaces("use_tempaddr", "2")

  Address = collections.namedtuple("Address",
                                   "addr flags scope ifindex valid preferred")


  class AddressesByType(
      collections.namedtuple("AddressesByType", "linklocal stable privacy")):

    def TotalCount(self):
      total = 0
      for field in self._fields:
        total += len(getattr(self, field))
      return total


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

    bytype = self.AddressesByType([], [], [])
    for addr in addrs:
      if self.IsLinkLocal(addr): bytype.linklocal.append(addr)
      elif self.IsGlobalStable(addr): bytype.stable.append(addr)
      elif self.IsGlobalPrivacy(addr): bytype.privacy.append(addr)
      else: raise ValueError("Unknown type for address: %s" % addr)

    return bytype

  def assertSourceAddressForConnectionIn(self, addrlist, netid, addrpref):
    s = net_test.UDPSocket(AF_INET6)
    self.SelectInterface(s, netid, "mark")
    if addrpref is not None:
      s.setsockopt(IPPROTO_IPV6, net_test.IPV6_ADDR_PREFERENCES, addrpref)
    s.connect((net_test.IPV6_ADDR, 53))
    srcaddr, port = s.getsockname()[:2]
    self.assertTrue(any(srcaddr == a.addr for a in addrlist))

  def assertExpectedAddressCount(self, netid, total,
                                 linklocal=None, stable=None, privacy=None):
    bytype = self.GetAddresses(netid)
    if linklocal is not None:
      self.assertEqual(linklocal, len(bytype.linklocal))
    if stable is not None:
      self.assertEqual(stable, len(bytype.stable))
    if privacy is not None:
      self.assertEqual(privacy, len(bytype.privacy))

  @staticmethod
  def GetIID(addr):
    addr = inet_pton(AF_INET6, addr)
    addr = "\x00" * 8 + addr[8:]
    return inet_ntop(AF_INET6, addr)

  def testGetIID(self):
    self.assertEqual("::", self.GetIID("::"))
    self.assertEqual("::1", self.GetIID("::1"))
    self.assertEqual("::b", self.GetIID("a::b"))
    self.assertEqual("::f110:8c2f:14a:8064",
                     self.GetIID("2001:db8:a:b:f110:8c2f:14a:8064"))


class PrivacyAddressPreferenceTest(PrivacyAddressBaseTest):

  def testPrivacyAddressesPreference(self):
    for netid in self.tuns:
      # No privacy addresses expected because the sysctl was created after
      # the initial RAs were set in setUpClass.
      self.assertExpectedAddressCount(netid, 2, linklocal=1, stable=1, privacy=0)

      # Now send an RA and expect to see a privacy address as well.
      self.SendRA(netid)

      bytype = self.GetAddresses(netid)
      self.assertEqual(3, bytype.TotalCount())
      self.assertEquals(1, len(bytype.linklocal))
      self.assertEquals(1, len(bytype.stable))
      self.assertEquals(1, len(bytype.privacy))

    # Check that connections use privacy addresses by default.
    for netid in self.tuns:
      self.assertSourceAddressForConnectionIn(
          self.GetAddresses(netid).privacy, netid, None)
      self.assertSourceAddressForConnectionIn(
          self.GetAddresses(netid).stable, netid,
          net_test.IPV6_PREFER_SRC_PUBLIC)

    # but with PREFER_SRC_PUBLIC uses stable addresses.
    self.SetIPv6SysctlOnAllIfaces("use_tempaddr", "1")
    for netid in self.tuns:
      self.assertSourceAddressForConnectionIn(
          self.GetAddresses(netid).stable, netid, None)
      self.assertSourceAddressForConnectionIn(
          self.GetAddresses(netid).privacy, netid,
          net_test.IPV6_PREFER_SRC_TMP)


class PrivacyAddressLifetimeTest(PrivacyAddressBaseTest):

  def testRefreshLifetime(self):
    for netid in self.tuns:
      # Create privacy addresses with lifetime of 6000s.
      self.SendRA(netid, validity=600)
      self.assertExpectedAddressCount(netid, 3, linklocal=1, stable=1, privacy=1)
      oldaddr = self.GetAddresses(netid).privacy[0]

      # Send an RA with a higher lifetime. No new addresses should be created
      # and the existing privacy address lifetime should increase.
      self.SendRA(netid, validity=1200)
      self.assertExpectedAddressCount(netid, 3, linklocal=1, stable=1, privacy=1)
      newaddr = self.GetAddresses(netid).privacy[0]

      self.assertEqual(oldaddr.preferred, 6000)
      self.assertEqual(oldaddr.valid, 6000)
      self.assertEqual(newaddr.preferred, 12000)
      self.assertEqual(newaddr.valid, 12000)

      newaddr = newaddr._replace(valid=oldaddr.valid,
                                 preferred=oldaddr.preferred)
      self.assertEquals(oldaddr, newaddr)


if __name__ == "__main__":
  unittest.main()
