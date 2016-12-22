#!/usr/bin/python
#
# Copyright 2015 The Android Open Source Project
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
import re
from socket import *  # pylint: disable=wildcard-import
import struct
import subprocess
import unittest

import multinetwork_base
import net_test
import netlink
import packets
import xfrm

IN6ADDR_ANY = 16 * "\x00"
LOOPBACK = 15 * "\x00" + "\x01"
ENCRYPTED_PAYLOAD = ("b1c74998efd6326faebe2061f00f2c750e90e76001664a80c287b150"
                     "59e74bf949769cc6af71e51b539e7de3a2a14cb05a231b969e035174"
                     "d98c5aa0cef1937db98889ec0d08fa408fecf616")

class XfrmTest(multinetwork_base.MultiNetworkBaseTest):

  def testSocketPolicy(self):
    s = socket(AF_INET6, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    s.connect(("2001:4860:4860::8888", 53))
    saddr, sport = s.getsockname()[:2]
    daddr, dport = s.getpeername()[:2]

    subprocess.call("ip xfrm state flush".split())
    cmd = (
        "ip xfrm state add dst %s spi 0x1234 "
        "proto esp mode transport replay-window 4 "
        "auth-trunc hmac(sha1) 0xaf442892cdcd0ef650e9c299f9a8436a1daf1ea9 96 "
        "enc cbc(aes) "
        "0x308146eb3bd84b044573d60f5a5fd15957c7d4fe567a2120f35bae0f9869ec22" %
        daddr)
    subprocess.call(cmd.split())

    sel = xfrm.XfrmSelector((IN6ADDR_ANY, IN6ADDR_ANY, 0, 0, 0, 0,
                             AF_INET6, 0, 0, IPPROTO_UDP, 0, 0))
#    sel = xfrm.XfrmSelector((xfrm.RawAddress(daddr), xfrm.RawAddress(saddr),
#                             htons(dport), htons(0xffff),
#                             htons(sport), htons(0xffff),
#                             AF_INET6, 128, 128, IPPROTO_UDP, 0, 0))
    # Lifetime and current lifetime are only meaningful for queries.
    lft = "\x00" * len(xfrm.XfrmLifetimeCfg)
    curlft = "\x00" * len(xfrm.XfrmLifetimeCur)
    info = xfrm.XfrmUserpolicyInfo((sel, lft, curlft, 100, 0,
                                    xfrm.XFRM_POLICY_OUT,
                                    xfrm.XFRM_POLICY_ALLOW,
                                    xfrm.XFRM_POLICY_LOCALOK,
                                    xfrm.XFRM_SHARE_UNIQUE))
#    xfrmid = xfrm.XfrmId((xfrm.RawAddress(daddr), htonl(0x1234), IPPROTO_ESP))
    xfrmid = xfrm.XfrmId((IN6ADDR_ANY, htonl(0x1234), IPPROTO_ESP))
    tmpl = xfrm.XfrmUserTmpl((xfrmid, AF_INET6, IN6ADDR_ANY, 0,
                              xfrm.XFRM_MODE_TRANSPORT, xfrm.XFRM_SHARE_UNIQUE,
                              0,            # require
                              0xffffffff,   # auth algos
                              0xffffffff,   # encryption algos
                              0xffffffff))  # ??? calgos
                              
    data = info.Pack() + tmpl.Pack()
    s.setsockopt(IPPROTO_IPV6, xfrm.IPV6_XFRM_POLICY, data)
    subprocess.call("ip xfrm policy".split())
    subprocess.call("ip xfrm state".split())
    s.sendto(net_test.UDP_PAYLOAD, ("2001:4860:4860::8888", 53))

    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(IPPROTO_ESP, packet.nh)
    spi_seq = struct.pack("!II", 0x1234, 1)
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(84, len(packet.payload))

    s2 = socket(AF_INET6, SOCK_DGRAM, 0)
    self.SelectInterface(s2, netid, "mark")
    s2.sendto(net_test.UDP_PAYLOAD, ("2001:4860:4860::8888", 53))
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(IPPROTO_UDP, packet.nh)


if __name__ == "__main__":
  unittest.main()
