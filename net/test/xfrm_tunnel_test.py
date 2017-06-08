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

_TEST_ADDR_1 = "10.16.5.20"

_TUNNEL_REMOTE_ADDR = "8.8.8.8"

_IP_ADDR_ANY = "0.0.0.0"

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

_VTI_NETID = 123
_VTI_IFNAME = "nettest123"
_VTI_RULE_PRIORITY = 150


class XfrmTunnelTest(multinetwork_base.MultiNetworkBaseTest):

  @classmethod
  def setUpClass(cls):
    super(XfrmTunnelTest, cls).setUpClass()
    cls.xfrm = xfrm.Xfrm()
    cls.tunnel = tunnel.IPTunnel()
    cls.iproute = iproute.IPRoute()

  def setUp(self):
    super(XfrmTunnelTest, self).setUp()
    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  def tearDown(self):
    super(XfrmTunnelTest, self).tearDown()
    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  def expectEspPacketOn(self, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(IPPROTO_ESP, packet.nh)
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(length, len(packet.payload))

  def createXfrmTunnel(self,
                       direction,
                       addr_family,
                       src_addr,
                       dst_addr,
                       tsrc_addr,
                       tdst_addr,
                       spi,
                       mark,
                       req_id=0):
    # Direction = OUT
    self.xfrm.AddMinimalSaInfo(tsrc_addr, tdst_addr,
                               htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL,
                               req_id, _ALGO_CBC_AES_256, _ENCRYPTION_KEY,
                               _ALGO_HMAC_SHA1, _AUTH_TRUNC_KEY, None, mark,
                               _MARK_MASK_ALL if mark is not None else None)

    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        family=addr_family)

    # Create a user policy that specifies that all outbound packets matching the
    # (essentially no-op) selector should be encrypted.
    policy = xfrm.XfrmUserpolicyInfo(
        (sel, xfrm.NO_LIFETIME_CFG, xfrm.NO_LIFETIME_CUR, 100, 0, direction,
         xfrm.XFRM_POLICY_ALLOW, xfrm.XFRM_POLICY_LOCALOK, xfrm.XFRM_SHARE_ANY))

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId((xfrm.PaddedAddress(tdst_addr), htonl(spi),
                          IPPROTO_ESP))
    tmpl = xfrm.XfrmUserTmpl((
        xfrmid,
        addr_family,
        xfrm.PaddedAddress(tsrc_addr),
        req_id,
        xfrm.XFRM_MODE_TUNNEL,
        xfrm.XFRM_SHARE_ANY,
        0,  # require
        _ALL_ALGORITHMS,  # auth algos
        _ALL_ALGORITHMS,  # encryption algos
        _ALL_ALGORITHMS))  # compression algos

    self.xfrm.AddPolicyInfo(policy, tmpl,
                            xfrm.XfrmMark((mark, _MARK_MASK_ALL))
                            if mark else None)

  def expectIPEspPacketOn(self, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    packet.show()
    self.assertEquals(IPPROTO_ESP, packet.nh)
    spi_seq = xfrm.EspHdr(spi, seq).Pack()
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(length, len(packet.payload))

  # Add an IPsec Tunnel
  def testAddTunnel(self):
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    self.SetDefaultNetwork(netid)
    try:
      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          addr_family=AF_INET,
          src_addr=_IP_ADDR_ANY,
          dst_addr=_TEST_ADDR_1,
          tsrc_addr=local_addr,
          tdst_addr=_TUNNEL_REMOTE_ADDR,
          mark=None,
          spi=_DEFAULT_OUT_SPI_1)

      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          addr_family=AF_INET,
          src_addr=_TEST_ADDR_1,
          dst_addr=_IP_ADDR_ANY,
          tsrc_addr=_TUNNEL_REMOTE_ADDR,
          tdst_addr=local_addr,
          mark=None,
          spi=_DEFAULT_IN_SPI_1)

      s = socket(AF_INET, SOCK_DGRAM, 0)
      s.sendto(net_test.UDP_PAYLOAD, (_TEST_ADDR_1, 53))
      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      packet = packets[0]
      self.assertEquals(local_addr, packet.src)
      self.assertEquals(_TUNNEL_REMOTE_ADDR, packet.dst)
      esp_hdr = xfrm.EspHdr(str(packet.payload))
      self.assertEquals(xfrm.EspHdr((_DEFAULT_OUT_SPI_1, 1)), esp_hdr)
    finally:
      self.ClearDefaultNetwork()

  # Create a VTI
  def testAddVti(self):
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    self.tunnel.CreateVti(
        dev_name=_VTI_IFNAME,
        local_addr=_TEST_ADDR_1,
        remote_addr=_TUNNEL_REMOTE_ADDR,
        o_key=_DEFAULT_OKEY_1,
        i_key=_DEFAULT_IKEY_1)
    if_index = self.tunnel.GetIfIndex(_VTI_IFNAME)

    # Validate that the netlink interface matches the ioctl interface
    self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
    self.tunnel.DeleteTunnel(_VTI_IFNAME)
    self.assertRaises(IOError, self.tunnel.GetIfIndex, _VTI_IFNAME)

  # Combine an IPsec Tunnel with a VTI to Output Packets on the Default Network
  def testVtiOutput(self):
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    self.tunnel.CreateVti(
        dev_name=_VTI_IFNAME,
        local_addr=local_addr,
        remote_addr=_TUNNEL_REMOTE_ADDR,
        i_key=_DEFAULT_IKEY_1,
        o_key=_DEFAULT_OKEY_1)
    self.ifindices[_VTI_NETID] = net_test.GetInterfaceIndex(_VTI_IFNAME)
    net_test.SetInterfaceUp(_VTI_IFNAME)

    self._RunSetupCommands(_VTI_NETID, True)

    try:
      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          addr_family=AF_INET,
          src_addr=_IP_ADDR_ANY,
          dst_addr=_IP_ADDR_ANY,
          tsrc_addr=local_addr,
          tdst_addr=_TUNNEL_REMOTE_ADDR,
          mark=_DEFAULT_OUT_MARK_1,
          spi=_DEFAULT_OUT_SPI_1)

      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          addr_family=AF_INET,
          src_addr=_IP_ADDR_ANY,
          dst_addr=_IP_ADDR_ANY,
          tsrc_addr=_TUNNEL_REMOTE_ADDR,
          tdst_addr=local_addr,
          mark=_DEFAULT_IN_MARK_1,
          spi=_DEFAULT_IN_SPI_1)

      s = socket(AF_INET, SOCK_DGRAM, 0)
      self.SetSocketMark(s, _VTI_NETID)

      self.SetDefaultNetwork(netid)
      try:
        s.sendto(net_test.UDP_PAYLOAD, (_TEST_ADDR_1, 53))
        packets = self.ReadAllPacketsOn(netid)
        self.assertEquals(1, len(packets))
        packet = packets[0]
        self.assertEquals(local_addr, packet.src)
        self.assertEquals(_TUNNEL_REMOTE_ADDR, packet.dst)
        esp_hdr = xfrm.EspHdr(str(packet.payload))
        self.assertEquals(xfrm.EspHdr((_DEFAULT_OUT_SPI_1, 1)), esp_hdr)
      finally:
        self.ClearDefaultNetwork()

      s.sendto(net_test.UDP_PAYLOAD, (_TEST_ADDR_1, 53))
      packets = self.ReadAllPacketsOn(netid)
      if (packets):
        packets[0].show()
      self.assertEquals(0, len(packets))

    finally:
      self._RunSetupCommands(_VTI_NETID, False)
      self.tunnel.DeleteTunnel(dev_name=_VTI_IFNAME)


if __name__ == "__main__":
  unittest.main()
