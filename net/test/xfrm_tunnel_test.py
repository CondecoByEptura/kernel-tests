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
import unittest

import iproute
import multinetwork_base
import net_test
import tunnel
import xfrm
import xfrm_base

_DEFAULT_OUT_SPI_1 = 0x1234
_DEFAULT_IN_SPI_1 = 0x5678

# Match all bits of the mark
_MARK_MASK_ALL = 0xffffffff

# Conveniently match the mark/tunnel key with the SPI
_DEFAULT_OKEY_1 = _DEFAULT_OUT_SPI_1
_DEFAULT_IKEY_1 = _DEFAULT_IN_SPI_1
_DEFAULT_OUT_MARK_1 = _DEFAULT_OKEY_1
_DEFAULT_IN_MARK_1 = _DEFAULT_IKEY_1

_VTI_NETID = 50
_VTI_IFNAME = "test_vti"
_VTI_RULE_PRIORITY = 150


class XfrmTunnelTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmTunnelTest, self).setUp()
    self.xfrm = xfrm.Xfrm()
    self.iproute = iproute.IPRoute()

    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  def tearDown(self):
    super(XfrmTunnelTest, self).tearDown()
    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  @staticmethod
  def _GetLocalInnerAddress(version):
    return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]

  @staticmethod
  def _GetRemoteInnerAddress(version):
    return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]

  @staticmethod
  def _GetAddressFamily(version):
    return {4: AF_INET, 6: AF_INET6}[version]

  def _GetRemoteOuterAddress(self, version):
    return self.GetRemoteAddress(version)

  # TODO: take encryption and auth parameters
  def _CreateXfrmTunnel(self, direction, inner_family, src_addr, dst_addr,
                        outer_family, tsrc_addr, tdst_addr, spi, mark):
    """Create an XFRM Tunnel Consisting of a Policy and an SA

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.
    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      inner_family: The address family (AF_INET or AF_INET6) the tunneled
        packets
      src_addr: The source address of the inner packets to be tunneled
      dst_addr: The destination address of the inner packets to be tunneled
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
    """
    self.xfrm.AddMinimalSaInfo(
        tsrc_addr, tdst_addr,
        htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, 0,
        XfrmTunnelTest._ALGO_CBC_AES_256, XfrmTunnelTest._ENCRYPTION_KEY_256,
        XfrmTunnelTest._ALGO_HMAC_SHA1, XfrmTunnelTest._AUTHENTICATION_KEY_128,
        None, mark, _MARK_MASK_ALL if mark is not None else None)

    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo(
        sel=sel,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        priority=100,
        index=0,
        dir=direction,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_ANY)

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId(
        daddr=xfrm.PaddedAddress(tdst_addr), spi=htonl(spi), proto=IPPROTO_ESP)
    tmpl = xfrm.XfrmUserTmpl(
        id=xfrmid,
        family=outer_family,
        saddr=xfrm.PaddedAddress(tsrc_addr),
        reqid=0,
        mode=xfrm.XFRM_MODE_TUNNEL,
        share=xfrm.XFRM_SHARE_ANY,
        optional=0,  # require
        aalgos=XfrmTunnelTest._ALL_ALGORITHMS,  # auth algos
        ealgos=XfrmTunnelTest._ALL_ALGORITHMS,  # encryption algos
        calgos=XfrmTunnelTest._ALL_ALGORITHMS)  # compression algos

    self.xfrm.AddPolicyInfo(policy, tmpl,
                            xfrm.XfrmMark((mark, _MARK_MASK_ALL))
                            if mark else None)

  def testAddTunnel(self):
    """Test a bi-directional XFRM Tunnel with explicit selectors"""
    for inner_version in [4, 6]:
      for outer_version in [4, 6]:
        netid = self._RandomNetid()
        self.SetDefaultNetwork(netid)
        try:
          local_inner = self._GetWildcardAddress(inner_version)
          remote_inner = self._GetRemoteInnerAddress(inner_version)
          local_outer = self.MyAddress(outer_version, netid)
          remote_outer = self._GetRemoteOuterAddress(outer_version)
          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_OUT,
              inner_family=self._GetAddressFamily(inner_version),
              src_addr=local_inner,
              dst_addr=remote_inner,
              outer_family=self._GetAddressFamily(outer_version),
              tsrc_addr=local_outer,
              tdst_addr=remote_outer,
              mark=None,
              spi=_DEFAULT_OUT_SPI_1)

          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_IN,
              inner_family=self._GetAddressFamily(inner_version),
              src_addr=remote_inner,
              dst_addr=local_inner,
              outer_family=self._GetAddressFamily(outer_version),
              tsrc_addr=remote_outer,
              tdst_addr=local_outer,
              mark=None,
              spi=_DEFAULT_IN_SPI_1)

          s = socket(self._GetAddressFamily(inner_version), SOCK_DGRAM, 0)
          s.sendto(net_test.UDP_PAYLOAD,
                   (self._GetRemoteInnerAddress(inner_version), 53))
          packets = self.ReadAllPacketsOn(netid)
          self.assertEquals(1, len(packets))
          packet = packets[0]
          self.assertEquals(local_outer, packet.src)
          self.assertEquals(
              self._GetRemoteOuterAddress(outer_version), packet.dst)
          esp_hdr = xfrm.EspHdr(str(packet.payload))
          self.assertEquals(xfrm.EspHdr((_DEFAULT_OUT_SPI_1, 1)), esp_hdr)
        finally:
          self.xfrm.FlushSaInfo()
          self.xfrm.FlushPolicyInfo()
          self.ClearDefaultNetwork()

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface"""
    for version in [4, 6]:
      netid = self._RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVti(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=self._GetRemoteOuterAddress(version),
          o_key=_DEFAULT_OKEY_1,
          i_key=_DEFAULT_IKEY_1)
      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _SetupVtiNetwork(self, ifname, is_add):
    """Setup rules and routes for a VTI Network

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: boolean that set up if is_add is True or
        teardown if is_add is False
    """
    for version in [4, 6]:
      # Find out how to configure things.
      ifindex = net_test.GetInterfaceIndex(ifname)
      table = _VTI_NETID

      # Set up routing rules.
      start, end = self.UidRangeForNetid(_VTI_NETID)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, ifname, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, _VTI_NETID, table,
                              self.PRIORITY_FWMARK)
      if is_add:
        if version == 4:
          self.iproute.AddAddress(
              self._MyIPv4Address(_VTI_NETID), self.OnlinkPrefixLen(4), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        if version == 4:
          self.iproute.DelAddress(
              self._MyIPv4Address(_VTI_NETID), self.OnlinkPrefixLen(4), ifindex)

  def testVtiOutput(self):
    """Test packet output over an IPsec tunnel that is selected using a VTI"""
    for inner_version in [4, 6]:
      for outer_version in [4, 6]:
        # FIXME: IPv6 in IPv6 is still not working...
        if inner_version is 6 and outer_version is 6:
          continue
        netid = self._RandomNetid()
        local_outer = self.MyAddress(outer_version, netid)
        remote_outer = self._GetRemoteOuterAddress(outer_version)
        self.iproute.CreateVti(
            dev_name=_VTI_IFNAME,
            local_addr=local_outer,
            remote_addr=remote_outer,
            i_key=_DEFAULT_IKEY_1,
            o_key=_DEFAULT_OKEY_1)
        # Add the actual inner address of the tunnel to the VTI Interface
        self.iproute.AddAddress(
            self._GetLocalInnerAddress(inner_version),
            self.OnlinkPrefixLen(inner_version),
            self.iproute.GetIfIndex(_VTI_IFNAME))
        net_test.SetInterfaceUp(_VTI_IFNAME)
        self._SetupVtiNetwork(_VTI_IFNAME, True)

        try:
          inner_addr = self._GetWildcardAddress(inner_version)
          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_OUT,
              inner_family=self._GetAddressFamily(inner_version),
              src_addr=inner_addr,
              dst_addr=inner_addr,
              outer_family=self._GetAddressFamily(outer_version),
              tsrc_addr=local_outer,
              tdst_addr=remote_outer,
              mark=_DEFAULT_OUT_MARK_1,
              spi=_DEFAULT_OUT_SPI_1)

          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_IN,
              inner_family=self._GetAddressFamily(inner_version),
              src_addr=inner_addr,
              dst_addr=inner_addr,
              outer_family=self._GetAddressFamily(outer_version),
              tsrc_addr=remote_outer,
              tdst_addr=local_outer,
              mark=_DEFAULT_IN_MARK_1,
              spi=_DEFAULT_IN_SPI_1)

          s = socket(self._GetAddressFamily(inner_version), SOCK_DGRAM, 0)
          self.SelectInterface(s, _VTI_NETID, "mark")

          # TODO: The underlying network must be the default until we can use
          # the output mark to select a network. Remove this and replace with a
          # mark-based selection when available.
          self.SetDefaultNetwork(netid)
          try:
            s.sendto(net_test.UDP_PAYLOAD,
                     (self._GetRemoteInnerAddress(inner_version), 53))
            self._ExpectEspPacketOn(netid, _DEFAULT_OUT_SPI_1, 1, None,
                                    local_outer, remote_outer)
          finally:
            self.ClearDefaultNetwork()

          s.sendto(net_test.UDP_PAYLOAD,
                   (self._GetRemoteInnerAddress(inner_version), 53))
          packets = self.ReadAllPacketsOn(netid)
          if (packets):
            packets[0].show()
          self.assertEquals(0, len(packets),
                            "Unexpected packets received! count=%d" %
                            (len(packets)))

        finally:
          self.xfrm.FlushSaInfo()
          self.xfrm.FlushPolicyInfo()
          self._SetupVtiNetwork(_VTI_IFNAME, False)
          self.iproute.DeleteLink(dev_name=_VTI_IFNAME)


if __name__ == "__main__":
  unittest.main()
