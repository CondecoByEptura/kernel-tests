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

# pylint: disable=g-bad-todo,g-bad-file-header,wildcard-import
from errno import *  # pylint: disable=wildcard-import
from socket import *  # pylint: disable=wildcard-import

import struct
import subprocess
import time
import unittest

from tun_twister import TunTwister
import csocket
import iproute
import multinetwork_base
import net_test
import xfrm
import xfrm_base

# Parameters to Set up VTI as a special network
_XFRM_NETID = 50
_XFRM_IFNAME = "xfrm1"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI + 1

_TEST_OMARK = _TEST_OUT_SPI + _XFRM_NETID
_TEST_IMARK = _TEST_IN_SPI + _XFRM_NETID

IFLA_XFRM_UNSPEC = 0
IFLA_XFRM_LINK = 1
IFLA_XFRM_IMARK = 2
IFLA_XFRM_IMASK = 3
IFLA_XFRM_OMARK = 4
IFLA_XFRM_OMASK = 5

class XfrmInterfaceTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmInterfaceTest, self).setUp()
    # If the hard-coded netids are redefined this will catch the error.
    self.assertNotIn(_XFRM_NETID, self.NETIDS,
                     "VTI netid %d already in use" % _XFRM_NETID)
    self.iproute = iproute.IPRoute()
    self._QuietDeleteLink(_XFRM_IFNAME)

  def tearDown(self):
    super(XfrmInterfaceTest, self).tearDown()
    self._QuietDeleteLink(_XFRM_IFNAME)

  @staticmethod
  def _GetLocalInnerAddress(version):
    return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]

  @staticmethod
  def _GetRemoteInnerAddress(version):
    return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]

  def _GetRemoteOuterAddress(self, version):
    return self.GetRemoteAddress(version)

  def _QuietDeleteLink(self, ifname):
    try:
      self.iproute.DeleteLink(ifname)
    except IOError:
      # The link was not present.
      pass

  def _SwapInterfaceAddress(self, ifname, old_addr, new_addr):
    """Exchange two addresses on a given interface.

    Args:
      ifname: Name of the interface
      old_addr: An address to be removed from the interface
      new_addr: An address to be added to an interface
    """
    version = 6 if ":" in new_addr else 4
    ifindex = net_test.GetInterfaceIndex(ifname)
    self.iproute.AddAddress(new_addr,
                            net_test.AddressLengthBits(version), ifindex)
    self.iproute.DelAddress(old_addr,
                            net_test.AddressLengthBits(version), ifindex)

  # TODO: Take encryption and auth parameters.
  def _CreateXfrmTunnel(self,
                        direction,
                        selector,
                        outer_family,
                        tsrc_addr,
                        tdst_addr,
                        spi,
                        mark=None,
                        output_mark=None):
    """Create an XFRM Tunnel Consisting of a Policy and an SA.

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.

    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      selector: A selector as returned by EmptySelector or SrcDstSelector.
        Decides which packets will be transformed. If None, matches all packets.
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
      output_mark: The mark used to select the underlying network for packets
        outbound from xfrm.
    """
    self.xfrm.AddSaInfo(
        tsrc_addr, tdst_addr,
        htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, 0, selector,
        self.ALGO_CBC_AES_256,
        self.ALGO_HMAC_SHA1,
        None,
        mark,
        output_mark)

    policy, tmpl = xfrm_base.CreateEspPolicyAndTemplate(
        outer_family, direction, htonl(spi), 0, selector,
        (tsrc_addr, tdst_addr))

    self.xfrm.AddPolicyInfo(policy, tmpl, mark)


  def CreateXfrmInterface(self, dev_name, netid, imark, omark):
    """Create an XFRM interface."""
    ifindex = self.ifindices[netid]

    ifdata = self.iproute._NlAttrU32(IFLA_XFRM_LINK, ifindex)
    ifdata += self.iproute._NlAttrU32(IFLA_XFRM_IMARK, imark)
    ifdata += self.iproute._NlAttrU32(IFLA_XFRM_IMASK, 0xffffffff)
    ifdata += self.iproute._NlAttrU32(IFLA_XFRM_OMARK, omark)
    ifdata += self.iproute._NlAttrU32(IFLA_XFRM_OMASK, 0xffffffff)

    linkinfo = self.iproute._NlAttrStr(iproute.IFLA_INFO_KIND, "xfrm")
    linkinfo += self.iproute._NlAttr(iproute.IFLA_INFO_DATA, ifdata)
    
    msg = iproute.IfinfoMsg().Pack()
    msg += self.iproute._NlAttrStr(iproute.IFLA_IFNAME, dev_name)
    msg += self.iproute._NlAttr(iproute.IFLA_LINKINFO, linkinfo)

    return self.iproute._SendNlRequest(iproute.RTM_NEWLINK, msg)

  def testAddXfrmInterface(self):
    """Test the creation of an XFRM Interface."""
    open("/proc/sys/kernel/printk", "w").write("9\n")
    netid = self.RandomNetid()
    self.CreateXfrmInterface(_XFRM_IFNAME, netid, _TEST_IMARK, _TEST_OMARK)
    if_index = self.iproute.GetIfIndex(_XFRM_IFNAME)
    net_test.SetInterfaceUp(_XFRM_IFNAME)

    # Validate that the netlink interface matches the ioctl interface.
    self.assertEquals(net_test.GetInterfaceIndex(_XFRM_IFNAME), if_index)
    self.iproute.DeleteLink(_XFRM_IFNAME)
    with self.assertRaises(IOError):
      self.iproute.GetIfIndex(_XFRM_IFNAME)

  def _SetupXfrmNetwork(self, ifname, is_add):
    """Setup rules and routes for a VTI Network.

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Bring up the interface so that we can start adding addresses
      # and routes.
      net_test.SetInterfaceUp(_XFRM_IFNAME)

      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the VTI, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      self.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % _XFRM_IFNAME, 0)
    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(ifname)
      table = _XFRM_NETID

      # Set up routing rules.
      start, end = self.UidRangeForNetid(_XFRM_NETID)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, ifname, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, _XFRM_NETID, table,
                              self.PRIORITY_FWMARK)
      if is_add:
        self.iproute.AddAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        self.iproute.DelAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
    if not is_add:
      net_test.SetInterfaceDown(_XFRM_IFNAME)

  # TODO: Should we completely re-write this using null encryption and null
  # authentication? We could then assemble and disassemble packets for each
  # direction individually. This approach would improve debuggability, avoid the
  # complexity of the twister, and allow the test to more-closely validate
  # deployable configurations.
  def _CheckXfrmOutput(self, inner_version, outer_version):
    """Test packet input and output over a Virtual Tunnel Interface."""
    netid = self.RandomNetid()
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    self.CreateXfrmInterface(_XFRM_IFNAME, netid, _TEST_IMARK, _TEST_OMARK)
    self._SetupXfrmNetwork(_XFRM_IFNAME, True)

    try:
      # For the VTI, the selectors are wildcard since packets will only
      # be selected if they have the appropriate mark, hence the inner
      # addresses are wildcard.
      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          selector=xfrm.EmptySelector(net_test.GetAddressFamily(inner_version)),
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=local_outer,
          tdst_addr=remote_outer,
          mark=xfrm.ExactMarkMatch(_TEST_OMARK),
          spi=_TEST_OUT_SPI,
          output_mark=netid)

      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          selector=xfrm.EmptySelector(net_test.GetAddressFamily(inner_version)),
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=remote_outer,
          tdst_addr=local_outer,
          mark=xfrm.ExactMarkMatch(_TEST_IMARK),
          spi=_TEST_IN_SPI,
          output_mark=netid)

      # Create a socket to receive packets.
      read_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
      # The second parameter of the tuple is the port number regardless of AF.
      port = read_sock.getsockname()[1]
      # Guard against the eventuality of the receive failing.
      csocket.SetSocketTimeout(read_sock, 100)

      # Send a packet out via the vti-backed network, bound for the port number
      # of the input socket.
      write_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      self.SelectInterface(write_sock, _XFRM_NETID, "mark")
      subprocess.call("ip xfrm policy".split())
      subprocess.call("ip xfrm state".split())
#      subprocess.call(("ip link show %s" % _XFRM_IFNAME).split())
#      subprocess.call("ip rule".split())
      write_sock.sendto(net_test.UDP_PAYLOAD,
                        (self._GetRemoteInnerAddress(inner_version), port))

      # Read a tunneled IP packet on the underlying (outbound) network
      # verifying that it is an ESP packet.
      pkt = self._ExpectEspPacketOn(netid, _TEST_OUT_SPI, 1, None, local_outer,
                                    remote_outer)

      # Perform an address switcheroo so that the inner address of the remote
      # end of the tunnel is now the address on the local VTI interface; this
      # way, the twisted inner packet finds a destination via the VTI once
      # decrypted.
      remote = self._GetRemoteInnerAddress(inner_version)
      local = self._GetLocalInnerAddress(inner_version)
      self._SwapInterfaceAddress(_XFRM_IFNAME, new_addr=remote, old_addr=local)
      try:
        # Swap the packet's IP headers and write it back to the
        # underlying network.
        pkt = TunTwister.TwistPacket(pkt)
        self.ReceivePacketOn(netid, pkt)
        # Receive the decrypted packet on the dest port number.
        read_packet = read_sock.recv(4096)
        self.assertEquals(read_packet, net_test.UDP_PAYLOAD)
      finally:
        # Unwind the switcheroo
        self._SwapInterfaceAddress(_XFRM_IFNAME, new_addr=local, old_addr=remote)

    finally:
      self._SetupXfrmNetwork(_XFRM_IFNAME, False)

  def testIpv4InIpv4XfrmOutput(self):
    self._CheckXfrmOutput(4, 4)


if __name__ == "__main__":
  unittest.main()
