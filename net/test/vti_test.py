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

import multinetwork_base
import net_test
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


class VtiTest(multinetwork_base.MultiNetworkBaseTest):
    @classmethod
    def setUpClass(cls):
        super(VtiTest, cls).setUpClass()
        cls.xfrm = xfrm.Xfrm()

    def setUp(self):
        # TODO: delete this when we're more diligent about deleting our SAs.
        super(VtiTest, self).setUp()
        self.xfrm.FlushSaInfo()

    def tearDown(self):
        super(VtiTest, self).tearDown()
        self.xfrm.FlushSaInfo()
        self.xfrm.FlushPolicyInfo()

    def expectEspPacketOn(self, netid, spi, seq, length):
        packets = self.ReadAllPacketsOn(netid)
        self.assertEquals(1, len(packets))
        packet = packets[0]
        self.assertEquals(IPPROTO_ESP, packet.nh)
        spi_seq = struct.pack("!II", spi, seq)
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
                         req_id=0):
        # Direction = OUT
        self.xfrm.AddMinimalSaInfo(tsrc_addr, tdst_addr, htonl(spi),
                                   IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, req_id,
                                   ALGO_CBC_AES_256, ENCRYPTION_KEY,
                                   ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None)

        sel = xfrm.XfrmSelector(
            (xfrm.PaddedAddress(dst_addr), xfrm.PaddedAddress(src_addr), 0, 0,
             0, 0, addr_family, 32, 0, 0, 0, 0))

        # Create a user policy that specifies that all outbound packets matching the
        # (essentially no-op) selector should be encrypted.
        policy = xfrm.XfrmUserpolicyInfo(
            (sel, xfrm.NO_LIFETIME_CFG, xfrm.NO_LIFETIME_CUR, 100, 0,
             direction, xfrm.XFRM_POLICY_ALLOW, xfrm.XFRM_POLICY_LOCALOK,
             xfrm.XFRM_SHARE_ANY))

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

        self.xfrm.AddPolicyInfo(policy, tmpl)

    def testAddTunnel(self):
        netid = self.NETIDS[0]
        local_addr = self.MyAddress(4, netid)

        tnetid = self.NETIDS[1]
        tnet_addr = self.MyAddress(4, tnetid)

        self.createXfrmTunnel(
            direction=xfrm.XFRM_POLICY_OUT,
            addr_family=AF_INET,
            src_addr="0.0.0.0",
            dst_addr=TEST_ADDR1,
            tsrc_addr=local_addr,
            tdst_addr="8.8.8.8",
            # tdst_addr=tnet_addr,
            spi=0x1234)
        self.createXfrmTunnel(
            direction=xfrm.XFRM_POLICY_IN,
            addr_family=AF_INET,
            src_addr=TEST_ADDR1,
            dst_addr="0.0.0.0",
            tsrc_addr="8.8.8.8",
            # tsrc_addr=tnet_addr,
            tdst_addr=local_addr,
            spi=0x5678)

        subprocess.check_output(
            "ip route add 0.0.0.0/0 scope global proto kernel dev nettest150".
            split())
        print subprocess.check_output("ip route show".split())
        print subprocess.check_output("ip link show".split())
        print subprocess.check_output("/sbin/iptables -L".split())
        s = socket(AF_INET, SOCK_DGRAM, 0)
        self.SelectInterface(s, netid, "mark")
        # saddr, sport = s.getsockname()[:2]
        # daddr, dport = s.getpeername()[:2]
        s.sendto(net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))
        pkts = self.ReadAllPacketsOn(tnetid)
        print pkts


if __name__ == "__main__":
    unittest.main()
