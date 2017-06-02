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

TEST_ADDR1 = "2001:4860:4860::8888"
TEST_ADDR2 = "2001:4860:4860::8844"

TEST_SPI = 0x1234

ALL_ALGORITHMS = 0xffffffff
ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))


def MakeUserPolicy(family):
  """Creates an XfrmUserpolicyInfo for testing.

  This returns a policy specifying that all UDP packets in the given address family should be encrypted.
  NOTE: These policies aren't actually used to select traffic. That will be done by the socket policy, which selects the SA entry (i.e. xfrm state) via the XfrmUserTmpl.
  """
  sel = xfrm.XfrmSelector(family=family, proto=IPPROTO_UDP)
  # TODO: what happens without XFRM_SHARE_UNIQUE?
  return xfrm.XfrmUserpolicyInfo(
      sel=sel,
      lft=xfrm.NO_LIFETIME_CFG,
      curlft=xfrm.NO_LIFETIME_CUR,
      priority=100,
      index=0,
      dir=xfrm.XFRM_POLICY_OUT,
      action=xfrm.XFRM_POLICY_ALLOW,
      flags=xfrm.XFRM_POLICY_LOCALOK,
      share=xfrm.XFRM_SHARE_UNIQUE)


def MakeUserTemplate(family):
  """Creates an XfrmUserTmpl for testing.

  This returns a template matching SAs which use TEST_SPI and the given address family.
  NOTE: XfrmController uses templates designed to match exactly one SA. This is much less strict.
  """
  xfrmid = xfrm.XfrmId(
      daddr=XFRM_ADDR_ANY, spi=TEST_SPI, proto=IPPROTO_ESP)
  return xfrm.XfrmUserTmpl(
      id=xfrmid,
      family=family,
      saddrXFRM_ADDR_ANY,
      reqid=0,
      mode=xfrm.XFRM_MODE_TRANSPORT,
      share=xfrm.XFRM_SHARE_UNIQUE,
      optional=0,  # require
      aalgos=ALL_ALGORITHMS,  # auth algos
      ealgos=ALL_ALGORITHMS,  # encryption algos
      calgos=ALL_ALGORITHMS)  # compression algos


class XfrmTest(multinetwork_base.MultiNetworkBaseTest):

  @classmethod
  def setUpClass(cls):
    super(XfrmTest, cls).setUpClass()
    cls.xfrm = xfrm.Xfrm()

  def setUp(self):
    # TODO: delete this when we're more diligent about deleting our SAs.
    super(XfrmTest, self).setUp()
    self.xfrm.FlushSaInfo()

  def tearDown(self):
    super(XfrmTest, self).tearDown()
    self.xfrm.FlushSaInfo()

  def expectIPv6EspPacketOn(self, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(IPPROTO_ESP, packet.nh)
    spi_seq = struct.pack("!II", spi, seq)
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(length, len(packet.payload))

  def assertIsUdpEncapEsp(self, packet, spi, seq, length):
    self.assertEquals(IPPROTO_UDP, packet.proto)
    self.assertEquals(4500, packet.dport)
    # Skip UDP header. TODO: isn't there a better way to do this?
    payload = str(packet.payload)[8:]
    self.assertEquals(length, len(payload))
    spi_seq = struct.pack("!II", ntohl(spi), seq)
    self.assertEquals(spi_seq, str(payload)[:len(spi_seq)])

  def testAddSa(self):
    self.xfrm.AddMinimalSaInfo(
        "::", TEST_V6_ADDR1,
        TEST_SPI, IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, 3320,
        ALGO_CBC_AES_256, ENCRYPTION_KEY, ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None)
    expected = ("src :: dst 2001:4860:4860::8888\n"
                "\tproto esp spi 0x00001234 reqid 3320 mode transport\n"
                "\treplay-window 4 \n"
                "\tauth-trunc hmac(sha1) 0x%s 96\n"
                "\tenc cbc(aes) 0x%s\n"
                "\tsel src ::/0 dst ::/0 \n" % (AUTH_TRUNC_KEY.encode("hex"),
                                                ENCRYPTION_KEY.encode("hex")))

    actual = subprocess.check_output("ip xfrm state".split())
    try:
      self.assertMultiLineEqual(expected, actual)
    finally:
      self.xfrm.DeleteSaInfo(TEST_ADDR1, htonl(TEST_SPI), IPPROTO_ESP)

  def testFlush(self):
    self.assertEquals(0, len(self.xfrm.DumpSaInfo()))
    self.xfrm.AddMinimalSaInfo(
        "::", "2000::",
        TEST_SPI, IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, 1234,
        ALGO_CBC_AES_256, ENCRYPTION_KEY, ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None)
    self.xfrm.AddMinimalSaInfo(
        "0.0.0.0", "192.0.2.1",
        TEST_SPI, IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, 4321,
        ALGO_CBC_AES_256, ENCRYPTION_KEY, ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None)
    self.assertEquals(2, len(self.xfrm.DumpSaInfo()))
    self.xfrm.FlushSaInfo()
    self.assertEquals(0, len(self.xfrm.DumpSaInfo()))

  @unittest.skipUnless(net_test.LINUX_VERSION < (4, 4, 0), "regression")
  def testSocketPolicy(self):
    # Open an IPv6 UDP socket and connect it.
    s = socket(AF_INET6, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    s.connect((TEST_ADDR1, 53))
    saddr, sport = s.getsockname()[:2]
    daddr, dport = s.getpeername()[:2]

    # Create a selector that matches all UDP packets. It's not actually used to
    # select traffic, that will be done by the socket policy, which selects the
    # SA entry (i.e., xfrm state) via the SPI and reqid.
    sel = xfrm.XfrmSelector(
        daddr=XFRM_ADDR_ANY,
        saddr=XFRM_ADDR_ANY,
        dport=0,
        dport_mask=0,
        sport=0,
        sport_mask=0,
        family=AF_INET6,
        prefixlen_d=0,
        prefixlen_s=0,
        proto=IPPROTO_UDP,
        ifindex=0,
        user=0)

    # Create a user policy that specifies that all outbound packets matching the
    # (essentially no-op) selector should be encrypted.
    info = xfrm.XfrmUserpolicyInfo(
        sel=sel,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        priority=100,
        index=0,
        dir=xfrm.XFRM_POLICY_OUT,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_UNIQUE)

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId((XFRM_ADDR_ANY, htonl(TEST_SPI), IPPROTO_ESP))
    tmpl = xfrm.XfrmUserTmpl((xfrmid, AF_INET6, XFRM_ADDR_ANY, 0,
                              xfrm.XFRM_MODE_TRANSPORT, xfrm.XFRM_SHARE_UNIQUE,
                              0,                # require
                              ALL_ALGORITHMS,   # auth algos
                              ALL_ALGORITHMS,   # encryption algos
                              ALL_ALGORITHMS))  # compression algos

    # Set the policy and template on our socket.
    data = info.Pack() + tmpl.Pack()
    s.setsockopt(IPPROTO_IPV6, xfrm.IPV6_XFRM_POLICY, data)

    # Because the policy has level set to "require" (the default), attempting
    # to send a packet results in an error, because there is no SA that
    # matches the socket policy we set.
    self.assertRaisesErrno(
        EAGAIN,
        s.sendto, net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))

    # Adding a matching SA causes the packet to go out encrypted. The SA's
    # SPI must match the one in our template, and the destination address must
    # match the packet's destination address (in tunnel mode, it has to match
    # the tunnel destination).
    reqid = 0
    self.xfrm.AddMinimalSaInfo(
        "::", TEST_V6_ADDR1,
        TEST_SPI, IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, reqid,
        ALGO_CBC_AES_256, ENCRYPTION_KEY, ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None)

    s.sendto(net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))
    self.expectIPv6EspPacketOn(netid, TEST_SPI, 1, 84)

    # Sending to another destination doesn't work: again, no matching SA.
    self.assertRaisesErrno(
        EAGAIN,
        s.sendto, net_test.UDP_PAYLOAD, (TEST_ADDR2, 53))

    # Sending on another socket without the policy applied results in an
    # unencrypted packet going out.
    s2 = socket(AF_INET6, SOCK_DGRAM, 0)
    self.SelectInterface(s2, netid, "mark")
    s2.sendto(net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(IPPROTO_UDP, packet.nh)

    # Deleting the SA causes the first socket to return errors again.
    self.xfrm.DeleteSaInfo(TEST_ADDR1, htonl(TEST_SPI), IPPROTO_ESP)
    self.assertRaisesErrno(
        EAGAIN,
        s.sendto, net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))


  def testUdpEncapWithSocketPolicy(self):
    # TODO: test IPv6 instead of IPv4.
    netid = random.choice(self.NETIDS)
    myaddr = self.MyAddress(4, netid)
    remoteaddr = self.GetRemoteAddress(4)

    # Reserve a port on which to receive UDP encapsulated packets. Sending
    # packets works without this (and potentially can send packets with a source
    # port belonging to another application), but receiving requires the port to
    # be bound and the encapsulation socket option enabled.
    encap_socket = net_test.Socket(AF_INET, SOCK_DGRAM, 0)
    encap_socket.bind((myaddr, 0))
    encap_port = encap_socket.getsockname()[1]
    encap_socket.setsockopt(IPPROTO_UDP, xfrm.UDP_ENCAP,
                               xfrm.UDP_ENCAP_ESPINUDP)

    # Open a socket to send traffic.
    s = socket(AF_INET, SOCK_DGRAM, 0)
    self.SelectInterface(s, netid, "mark")
    s.connect((remoteaddr, 53))

    # Create a UDP encap policy and template inbound and outbound and apply
    # them to s.
    sel = xfrm.XfrmSelector((XFRM_ADDR_ANY, XFRM_ADDR_ANY, 0, 0, 0, 0,
                             AF_INET, 0, 0, IPPROTO_UDP, 0, 0))

    # Use the same SPI both inbound and outbound because this lets us receive
    # encrypted packets by simply replaying the packets the kernel sends.
    in_reqid = 123
    in_spi = htonl(TEST_SPI)
    out_reqid = 456
    out_spi = htonl(TEST_SPI)

    # Start with the outbound policy.
    # TODO: what happens without XFRM_SHARE_UNIQUE?
    info = xfrm.XfrmUserpolicyInfo((sel,
                                    xfrm.NO_LIFETIME_CFG, xfrm.NO_LIFETIME_CUR,
                                    100, 0,
                                    xfrm.XFRM_POLICY_OUT,
                                    xfrm.XFRM_POLICY_ALLOW,
                                    xfrm.XFRM_POLICY_LOCALOK,
                                    xfrm.XFRM_SHARE_UNIQUE))
    xfrmid = xfrm.XfrmId((XFRM_ADDR_ANY, out_spi, IPPROTO_ESP))
    usertmpl = xfrm.XfrmUserTmpl((xfrmid, AF_INET, XFRM_ADDR_ANY, out_reqid,
                              xfrm.XFRM_MODE_TRANSPORT, xfrm.XFRM_SHARE_UNIQUE,
                              0,                # require
                              ALL_ALGORITHMS,   # auth algos
                              ALL_ALGORITHMS,   # encryption algos
                              ALL_ALGORITHMS))  # compression algos

    data = info.Pack() + usertmpl.Pack()
    s.setsockopt(IPPROTO_IP, xfrm.IP_XFRM_POLICY, data)

    # Uncomment for debugging.
    # subprocess.call("ip xfrm policy".split())

    # Create inbound and outbound SAs that specify UDP encapsulation.
    encaptmpl = xfrm.XfrmEncapTmpl((xfrm.UDP_ENCAP_ESPINUDP, htons(encap_port),
                                    htons(4500), 16 * "\x00"))
    self.xfrm.AddMinimalSaInfo(myaddr, remoteaddr, out_spi, IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, out_reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, encaptmpl)

    # Add an encap template that's the mirror of the outbound one.
    encaptmpl.sport, encaptmpl.dport = encaptmpl.dport, encaptmpl.sport
    self.xfrm.AddMinimalSaInfo(remoteaddr, myaddr, in_spi, IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, in_reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, encaptmpl)

    # Uncomment for debugging.
    # subprocess.call("ip xfrm state".split())

    # Now send a packet.
    s.sendto("foo", (remoteaddr, 53))
    srcport = s.getsockname()[1]
    # s.send("foo")  # TODO: WHY DOES THIS NOT WORK?

    # Expect to see an UDP encapsulated packet.
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertIsUdpEncapEsp(packet, out_spi, 1, 52)

    # Now test the receive path. Because we don't know how to decrypt packets,
    # we just play back the encrypted packet that kernel sent earlier. We swap
    # the addresses in the IP header to make the packet look like it's bound for
    # us, but we can't do that for the port numbers because the UDP header is
    # part of the integrity protected payload, which we can only replay as is.
    # So the source and destination ports are swapped and the packet appears to
    # be sent from srcport to port 53. Open another socket on that port, and
    # apply the inbound policy to it.
    twisted_socket = socket(AF_INET, SOCK_DGRAM, 0)
    net_test.SetSocketTimeout(twisted_socket, 100)
    twisted_socket.bind(("0.0.0.0", 53))

    # TODO: why does this work even without the per-socket policy applied? The
    # received packet obviously matches an SA, but don't inbound packets need to
    # match a policy as well?
    info.dir = xfrm.XFRM_POLICY_IN
    xfrmid.spi = in_spi
    usertmpl.reqid = in_reqid
    data = info.Pack() + usertmpl.Pack()
    twisted_socket.setsockopt(IPPROTO_IP, xfrm.IP_XFRM_POLICY, data)

    # Save the payload of the packet so we can replay it back to ourselves.
    payload = str(packet.payload)[8:]
    spi_seq = struct.pack("!II", ntohl(in_spi), 1)
    payload = spi_seq + payload[len(spi_seq):]

    # Tamper with the packet and check that it's dropped and counted as invalid.
    sainfo = self.xfrm.FindSaInfo(in_spi)
    self.assertEquals(0, sainfo.stats.integrity_failed)
    broken = payload[:25] + chr((ord(payload[25]) + 1) % 256) + payload[26:]
    incoming = (scapy.IP(src=remoteaddr, dst=myaddr) /
                scapy.UDP(sport=4500, dport=encap_port) / broken)
    self.ReceivePacketOn(netid, incoming)
    sainfo = self.xfrm.FindSaInfo(in_spi)
    self.assertEquals(1, sainfo.stats.integrity_failed)

    # Now play back the valid packet and check that we receive it.
    incoming = (scapy.IP(src=remoteaddr, dst=myaddr) /
                scapy.UDP(sport=4500, dport=encap_port) / payload)
    self.ReceivePacketOn(netid, incoming)
    data, src = twisted_socket.recvfrom(4096)
    self.assertEquals("foo", data)
    self.assertEquals((remoteaddr, srcport), src)

    # Check that unencrypted packets are not received.
    unencrypted = (scapy.IP(src=remoteaddr, dst=myaddr) /
                   scapy.UDP(sport=srcport, dport=53) / "foo")
    self.assertRaisesErrno(EAGAIN, twisted_socket.recv, 4096)

  def testInboundThingy(self):
    crypt = xfrm.XfrmAlgo(name="cbc(aes)", key_len=256)
    ekey = ("fd84f7dc021f541160b67537a8bdfa18"
            "744e86c85154c5cbf193391a5276af68").decode("hex")
    auth = xfrm.XfrmAlgoAuth(name="hmac(sha256)", key_len=256, trunc_len=128)
    akey = ("d1f990a0e43a2e1d9e9af7965f5b757d"
            "69fd30faa5233d2e39ff67cf9e8e35a1").decode("hex")
    # Complete with IP header.
    # UDP sport=54321, dport=7777
    esp_pkt = ("4500005c000100004032666b0a010001"
               "0a010002deadbeef000000019de09b61"
               "33fa36516e7828a33b405c48144430d8"
               "8731aead445789f5c79cc6250d905442"
               "a9c356c29f9c362ad21963943d397e28"
               "3becc2ed4f294e833b0ce64c").decode("hex")

    s = socket(AF_INET, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    #s.connect((TEST_V4_ADDR1, 54321)) # IP and port shouldn't restrict receiving anything.
    s.bind(("0.0.0.0",
            7777))  # listen on 7777 to receive the incoming esp packet?

    self.xfrm.AddMinimalSaInfo(
        src="0.0.0.0",
        dst="0.0.0.0",
        spi=0xdeadbeef,
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=0,
        encryption=crypt,
        encryption_key=ekey,
        auth_trunc=auth,
        auth_trunc_key=akey,
        encap=None)
    policy = MakeUserPolicy(AF_INET)
    template = MakeUserTemplate(AF_INET)
    template.id.spi = 0xdeadbeef
    data = policy.Pack() + template.Pack()
    s.setsockopt(IPPROTO_IP, xfrm.IP_XFRM_POLICY, data)

    # This sends our packet to the tap interface.
    self.ReceivePacketOn(netid, esp_pkt)
    s.settimeout(1)
    data, src = s.recvfrom(4096)
    print src
    print data

  def testReceiveSimplePacket(self):
    s = socket(AF_INET, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    local_addr = self.MyAddress(4, netid)
    remote_addr = self.GetRemoteAddress(4)
    s.bind((local_addr, 8080))  # listen on 8080
    pkt = (scapy.IP(src=remote_addr, dst=local_addr) / scapy.UDP(
        sport=9999, dport=8080) / "hello socket")
    self.ReceivePacketOn(netid, pkt.build())

    s.settimeout(1)
    data, src = s.recvfrom(4096)
    print src
    print data

  def testSendThenReceive(self):
    s = socket(AF_INET, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    local_addr = self.MyAddress(4, netid)
    remote_addr = self.GetRemoteAddress(4)
    s.sendto('hello socket1', (remote_addr, 9999))
    s.sendto('hello socket2', (remote_addr, 9999))

    pkts = self.ReadAllPacketsOn(netid)
    self.assertEquals(2, len(pkts))
    for pkt in pkts:
      pkt.show()

    local_port = s.getsockname()[1]
    pkt = (scapy.IP(src=remote_addr, dst=local_addr) / scapy.UDP(
        sport=9999, dport=local_port) / "well hello there")
    pkt.show()
    self.ReceivePacketOn(netid, pkt.build())
    s.settimeout(1)
    data, src = s.recvfrom(4096)
    print src
    print data


if __name__ == "__main__":
  unittest.main()
