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

XFRM_ADDR_ANY = 16 * "\x00"
LOOPBACK = 15 * "\x00" + "\x01"
ENCRYPTED_PAYLOAD = ("b1c74998efd6326faebe2061f00f2c750e90e76001664a80c287b150"
                     "59e74bf949769cc6af71e51b539e7de3a2a14cb05a231b969e035174"
                     "d98c5aa0cef1937db98889ec0d08fa408fecf616")
ENCRYPTION_KEY = ("308146eb3bd84b044573d60f5a5fd159"
                  "57c7d4fe567a2120f35bae0f9869ec22".decode("hex"))
AUTH_TRUNC_KEY = "af442892cdcd0ef650e9c299f9a8436a".decode("hex")

TEST6_ADDR1 = "2001:4860:4860::8888"
TEST6_ADDR2 = "2001:4860:4860::8844"

TEST_ADDR1 = "10.16.5.20"
TEST_ADDR2 = "10.16.5.10"

TEST_SPI = 0x1234

ALL_ALGORITHMS = 0xffffffff
ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))


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
    self.xfrm.AddMinimalSaInfo(tsrc_addr, tdst_addr, htonl(spi), IPPROTO_ESP,
                               xfrm.XFRM_MODE_TUNNEL, req_id, ALGO_CBC_AES_256,
                               ENCRYPTION_KEY, ALGO_HMAC_SHA1, AUTH_TRUNC_KEY,
                               None, mark, 0xFFFFFFFF if mark is not None else None)

    sel = xfrm.XfrmSelector((xfrm.PaddedAddress(dst_addr),
                             xfrm.PaddedAddress(src_addr), 0, 0, 0, 0,
                             addr_family, 0, 0, 0, 0, 0))

    # Create a user policy that specifies that all outbound packets matching the
    # (essentially no-op) selector should be encrypted.
    policy = xfrm.XfrmUserpolicyInfo(
        (sel, xfrm.NO_LIFETIME_CFG, xfrm.NO_LIFETIME_CUR, 100, 0, direction,
         xfrm.XFRM_POLICY_ALLOW, xfrm.XFRM_POLICY_LOCALOK, xfrm.XFRM_SHARE_ANY))

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId(
        (xfrm.PaddedAddress(tdst_addr), htonl(spi), IPPROTO_ESP))
    tmpl = xfrm.XfrmUserTmpl((xfrmid,
                              addr_family,
                              xfrm.PaddedAddress(tsrc_addr),
                              req_id,
                              xfrm.XFRM_MODE_TUNNEL,
                              xfrm.XFRM_SHARE_ANY,
                              0,  # require
                              ALL_ALGORITHMS,  # auth algos
                              ALL_ALGORITHMS,  # encryption algos
                              ALL_ALGORITHMS))  # compression algos

    self.xfrm.AddPolicyInfo(
        policy, tmpl, xfrm.XfrmMark((mark, 0xFFFFFFFF)) if mark else None)

  def expectIPEspPacketOn(self, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    packet.show()
    self.assertEquals(IPPROTO_ESP, packet.nh)
    spi_seq = struct.pack("!II", spi, seq)
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(length, len(packet.payload))


  def testAddTunnel(self):
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    self.SetDefaultNetwork(netid)
    try:
      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          addr_family=AF_INET,
          src_addr="0.0.0.0",
          dst_addr=TEST_ADDR1,
          tsrc_addr=local_addr,
          tdst_addr="8.8.8.8",
          mark=None,
          spi=0x1234)

      self.createXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          addr_family=AF_INET,
          src_addr=TEST_ADDR1,
          dst_addr="0.0.0.0",
          tsrc_addr="8.8.8.8",
          tdst_addr=local_addr,
          mark=None,
          spi=0x5678)

      s = socket(AF_INET, SOCK_DGRAM, 0)
      s.sendto(net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))
      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      packet = packets[0]
      packet.show()
      self.assertEquals(packet.src, local_addr)
      self.assertEquals(packet.dst, "8.8.8.8")
      esp_hdr = xfrm.EspHdr(str(packet.payload))
      self.assertEquals(xfrm.EspHdr((0x1234, 1)), esp_hdr)
      print esp_hdr
    finally:
      self.ClearDefaultNetwork()

  def testAddVti(self):
    return
    self.tunnel.CreateVti(
        dev_name="test_vti",
        local_addr="1.2.3.4",
        remote_addr="5.6.7.8",
        o_key=0x1234,
        i_key=0x5678)
    if_index = self.tunnel.GetIfIndex("test_vti")
    # Verify that a tunnel was added of the name test_vti
    self.assertNotEquals(if_index, -1)

    # Validate that the netlink interface matches the ioctl interface
    self.assertEquals(if_index, net_test.GetInterfaceIndex("test_vti"))
    self.tunnel.DeleteTunnel(dev_name="test_vti")
    if_index = self.tunnel.GetIfIndex("test_vti")

    # Ensure that the tunnel is deleted
    self.assertEquals(if_index, -1)

  # NETID[0] will be the user interface
  # NETID[1] will be the default route (output)
  def testVtiOutput(self):
    self.tunnel.CreateVti(
        dev_name="test_vti",
        local_addr="1.2.3.4",
        remote_addr="8.8.8.8",
        i_key=0x1234,
        o_key=0x5678)
    self.createXfrmTunnel(
        direction=xfrm.XFRM_POLICY_OUT,
        addr_family=AF_INET,
        src_addr="0.0.0.0",
        dst_addr="0.0.0.0",
        tsrc_addr="1.2.3.4",
        tdst_addr="8.8.8.8",
        mark=0x1234,
        spi=0x1234)

    self.createXfrmTunnel(
        direction=xfrm.XFRM_POLICY_IN,
        addr_family=AF_INET,
        src_addr="0.0.0.0",
        dst_addr="0.0.0.0",
        tsrc_addr="8.8.8.8",
        tdst_addr="1.2.3.4",
        mark=0x5678,
        spi=0x5678)

    ifindex = self.tunnel.GetIfIndex("test_vti")
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    print "ip link show"
    subprocess.call("ip link show".split())
    print "ip rule list"
    subprocess.call("ip rule list".split())
    print "ip route show - before"
    table_str = "ip route show table %d" % self._TableForNetid(netid)
    subprocess.call(table_str.split())
    print "ip route show - after"
    self.SetDefaultNetwork(netid)
    subprocess.call(table_str.split())
    self.tunnel.DeleteTunnel(dev_name="test_vti")
    subprocess.call("ip rule list".split())
    return
    for version in [4]:
      plen = {4: 32, 6: 128}[version]
      table = self._TableForNetid(user_netid)
      self.iproute.IifRule(version, True, "lo", "test_vti", 50)
      self.iproute.AddRoute(version, table, "default", 0, router, ifindex)
    subprocess.call("ip route show table all".split())

if __name__ == "__main__":
  unittest.main()
