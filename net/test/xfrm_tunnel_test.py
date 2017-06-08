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
import os
import random
from scapy import all as scapy
from socket import *  # pylint: disable=wildcard-import
import struct
import subprocess
import unittest

import iproute
import multinetwork_base
import net_test
import tunnel
import xfrm

_ENCRYPTION_KEY = ("308146eb3bd84b044573d60f5a5fd159"
                   "57c7d4fe567a2120f35bae0f9869ec22".decode("hex"))
_AUTH_TRUNC_KEY = "af442892cdcd0ef650e9c299f9a8436a".decode("hex")

_LOCAL_INNER_ADDR1 = {4: "10.16.5.15", 6: "2001:db8:1::1"}
_REMOTE_INNER_ADDR1 = {4: "10.16.5.20", 6: "2001:db8:2::1"}

_TUNNEL_REMOTE_ADDR = {4: "8.8.8.8", 6: "2600::8080:4040"}

_ADDR_ANY = {4: "0.0.0.0", 6: "::"}

_ALL_ALGORITHMS = 0xffffffff
_ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
_ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))

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


class XfrmTunnelTest(multinetwork_base.MultiNetworkBaseTest):

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

  def _CreateXfrmTunnel(self, direction, af_inner, src_addr, dst_addr, af_tun,
                        tsrc_addr, tdst_addr, spi, mark):
    self.xfrm.AddMinimalSaInfo(tsrc_addr, tdst_addr,
                               htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL,
                               0, _ALGO_CBC_AES_256, _ENCRYPTION_KEY,
                               _ALGO_HMAC_SHA1, _AUTH_TRUNC_KEY, None, mark,
                               _MARK_MASK_ALL if mark is not None else None)

    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        family=af_inner)

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
        family=af_tun,
        saddr=xfrm.PaddedAddress(tsrc_addr),
        reqid=0,
        mode=xfrm.XFRM_MODE_TUNNEL,
        share=xfrm.XFRM_SHARE_ANY,
        optional=0,  # require
        aalgos=_ALL_ALGORITHMS,  # auth algos
        ealgos=_ALL_ALGORITHMS,  # encryption algos
        calgos=_ALL_ALGORITHMS)  # compression algos

    self.xfrm.AddPolicyInfo(policy, tmpl,
                            xfrm.XfrmMark((mark, _MARK_MASK_ALL))
                            if mark else None)

  # Add an IPsec Tunnel
  def testAddTunnel(self):
    for i_ver in [4, 6]:
      for o_ver in [4, 6]:
        netid = self.NETIDS[0]
        local_addr = self.MyAddress(o_ver, netid)
        self.SetDefaultNetwork(netid)
        try:
          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_OUT,
              af_inner=(AF_INET if i_ver is 4 else AF_INET6),
              src_addr=_ADDR_ANY[i_ver],
              dst_addr=_REMOTE_INNER_ADDR1[i_ver],
              af_tun=(AF_INET if o_ver is 4 else AF_INET6),
              tsrc_addr=local_addr,
              tdst_addr=_TUNNEL_REMOTE_ADDR[o_ver],
              mark=None,
              spi=_DEFAULT_OUT_SPI_1)

          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_IN,
              af_inner=(AF_INET if i_ver is 4 else AF_INET6),
              src_addr=_REMOTE_INNER_ADDR1[i_ver],
              dst_addr=_ADDR_ANY[i_ver],
              af_tun=(AF_INET if o_ver is 4 else AF_INET6),
              tsrc_addr=_TUNNEL_REMOTE_ADDR[o_ver],
              tdst_addr=local_addr,
              mark=None,
              spi=_DEFAULT_IN_SPI_1)

          s = socket((AF_INET if i_ver is 4 else AF_INET6), SOCK_DGRAM, 0)
          s.sendto(net_test.UDP_PAYLOAD, (_REMOTE_INNER_ADDR1[i_ver], 53))
          packets = self.ReadAllPacketsOn(netid)
          self.assertEquals(1, len(packets))
          packet = packets[0]
          self.assertEquals(local_addr, packet.src)
          self.assertEquals(_TUNNEL_REMOTE_ADDR[o_ver], packet.dst)
          esp_hdr = xfrm.EspHdr(str(packet.payload))
          self.assertEquals(xfrm.EspHdr((_DEFAULT_OUT_SPI_1, 1)), esp_hdr)
        finally:
          self.xfrm.FlushSaInfo()
          self.xfrm.FlushPolicyInfo()
          self.ClearDefaultNetwork()

  # Create a VTI
  def testAddVti(self):
    for ver in [4, 6]:
      netid = self.NETIDS[0]
      local_addr = self.MyAddress(ver, netid)
      self.iproute.CreateVti(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=_TUNNEL_REMOTE_ADDR[ver],
          o_key=_DEFAULT_OKEY_1,
          i_key=_DEFAULT_IKEY_1)
      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  # Temprarily Set up a VTI as a Network
  def _SetupVtiNetwork(self, ifname, is_add):
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

  # Combine an IPsec Tunnel with a VTI to Output Packets on the Default Network
  def testVtiOutput(self):
    for i_ver in [4, 6]:
      for o_ver in [4, 6]:
        # TODO: IPv6 in IPv6 is still not working...
        if i_ver is 6 and o_ver is 6:
          return
        netid = self.NETIDS[0]
        local_addr = self.MyAddress(o_ver, netid)
        self.iproute.CreateVti(
            dev_name=_VTI_IFNAME,
            local_addr=local_addr,
            remote_addr=_TUNNEL_REMOTE_ADDR[o_ver],
            i_key=_DEFAULT_IKEY_1,
            o_key=_DEFAULT_OKEY_1)
        # Add the inner address of the tunnel to the VTI Interface
        self.iproute.AddAddress(_LOCAL_INNER_ADDR1[i_ver],
                                self.OnlinkPrefixLen(i_ver),
                                self.iproute.GetIfIndex(_VTI_IFNAME))
        net_test.SetInterfaceUp(_VTI_IFNAME)
        self._SetupVtiNetwork(_VTI_IFNAME, True)

        try:
          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_OUT,
              af_inner=(AF_INET if i_ver is 4 else AF_INET6),
              src_addr=_ADDR_ANY[i_ver],
              dst_addr=_ADDR_ANY[i_ver],
              af_tun=(AF_INET if o_ver is 4 else AF_INET6),
              tsrc_addr=local_addr,
              tdst_addr=_TUNNEL_REMOTE_ADDR[o_ver],
              mark=_DEFAULT_OUT_MARK_1,
              spi=_DEFAULT_OUT_SPI_1)

          self._CreateXfrmTunnel(
              direction=xfrm.XFRM_POLICY_IN,
              af_inner=(AF_INET if i_ver is 4 else AF_INET6),
              src_addr=_ADDR_ANY[i_ver],
              dst_addr=_ADDR_ANY[i_ver],
              af_tun=(AF_INET if o_ver is 4 else AF_INET6),
              tsrc_addr=_TUNNEL_REMOTE_ADDR[o_ver],
              tdst_addr=local_addr,
              mark=_DEFAULT_IN_MARK_1,
              spi=_DEFAULT_IN_SPI_1)

          s = socket((AF_INET if i_ver is 4 else AF_INET6), SOCK_DGRAM, 0)
          self.SelectInterface(s, _VTI_NETID, "mark")

          self.SetDefaultNetwork(netid)
          try:
            s.sendto(net_test.UDP_PAYLOAD, (_REMOTE_INNER_ADDR1[i_ver], 53))
            packets = self.ReadAllPacketsOn(netid)
            self.assertEquals(1, len(packets))
            packet = packets[0]
            self.assertEquals(local_addr, packet.src)
            self.assertEquals(_TUNNEL_REMOTE_ADDR[o_ver], packet.dst)
            esp_hdr = xfrm.EspHdr(str(packet.payload))
            self.assertEquals(xfrm.EspHdr((_DEFAULT_OUT_SPI_1, 1)), esp_hdr)
          finally:
            self.ClearDefaultNetwork()

          s.sendto(net_test.UDP_PAYLOAD, (_REMOTE_INNER_ADDR1[i_ver], 53))
          packets = self.ReadAllPacketsOn(netid)
          if (packets):
            packets[0].show()
          self.assertEquals(0, len(packets))

        finally:
          self.xfrm.FlushSaInfo()
          self.xfrm.FlushPolicyInfo()
          self._SetupVtiNetwork(_VTI_IFNAME, False)
          self.iproute.DeleteLink(dev_name=_VTI_IFNAME)


if __name__ == "__main__":
  unittest.main()
