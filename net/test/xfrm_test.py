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
import itertools
import random
from scapy import all as scapy
from socket import *  # pylint: disable=wildcard-import
import struct
import subprocess
import threading
import unittest

import multinetwork_base
import net_test
from tun_twister import TapTwister
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

ADDR_ANY = {AF_INET: "0.0.0.0", AF_INET6: "::"}

# IP addresses to use for tunnel endpoints. For generality, these should be
# different from the addresses we send packets to.
TUNNEL_ENDPOINT_IPV4 = "8.8.4.4"
TUNNEL_ENDPOINT_IPV6 = TEST_ADDR2

TEST_SPI = 0x1234

ALL_ALGORITHMS = 0xffffffff
ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))

# List of encryption algorithms for use in ParamTests.
CRYPT_ALGOS = [
    xfrm.XfrmAlgo((xfrm.XFRM_EALG_CBC_AES, 128)),
    xfrm.XfrmAlgo((xfrm.XFRM_EALG_CBC_AES, 192)),
    xfrm.XfrmAlgo((xfrm.XFRM_EALG_CBC_AES, 256)),
]

# List of auth algorithms for use in ParamTests.
AUTH_ALGOS = [
    # RFC 4868 specifies that the only supported truncation length is half the
    # hash size.
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_MD5, 128, 96)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA1, 160, 96)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA256, 256, 128)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA384, 384, 192)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA512, 512, 256)),
    # Test larger truncation lengths for good measure.
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_MD5, 128, 128)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA1, 160, 160)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA256, 256, 256)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA384, 384, 384)),
    xfrm.XfrmAlgoAuth((xfrm.XFRM_AALG_HMAC_SHA512, 512, 512)),
]


def GetEspPacketLength(version, mode, outer):
  """Calculates encrypted length of a UDP packet with payload UDP_PAYLOAD.

  Currently assumes ALGO_CBC_AES_256 and ALGO_HMAC_SHA1.

  Args:
    version: 4 or 6, the version of the inner packet.
    mode: XFRM_MODE_TRANSPORT or XFRM_MODE_TUNNEL.
    outer: IPPROTO_IP, IPPROTO_IPV6, or UDP_ENCAP_ESPINUDP. The outer header.

  Return: the packet length.

  Raises:
    NotImplementedError: unsupported combination.
  """
  # TODO: make this non-trivial, either using a more general matrix, or by
  # calculating sizes dynamically based on algorithm block sizes and padding.
  LENGTHS = {
      4: {
          xfrm.XFRM_MODE_TUNNEL: {
              IPPROTO_IP: 100,
          },
      },
      6: {
          xfrm.XFRM_MODE_TRANSPORT: {
              IPPROTO_IPV6: 84,
          },
          xfrm.XFRM_MODE_TUNNEL: {
              IPPROTO_IP: 132,
          },
      },
  }

  try:
    return LENGTHS[version][mode][outer]
  except KeyError:
    raise NotImplementedError(
      "Unsupported combination version=%d mode=%d outer=%d" %
      (version, mode, outer))


def ApplySocketPolicy(sock, family, direction, spi, reqid, tun_addrs=None):
  """Create and apply socket policy objects.

  AH is not supported. This is ESP only.

  Args:
    sock: The socket that needs a policy
    family: AF_INET or AF_INET6
    direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
    spi: 32-bit SPI in network byte order
    reqid: 32-bit ID matched against SAs
    tun_addrs: A tuple of two strings or None, the tunnel addresses.
      If None, requests a transport mode SA.
      If a tuple, specifies the local/remote endpoints of a tunnel mode SA.

  Return: a tuple of XfrmUserpolicyInfo, XfrmUserTmpl
  """
  # For transport mode, set the template destination to the socket
  # destination. This has to match the destination address in the SA.
  # For tunnel mode, explicitly specify source and destination addresses.
  if tun_addrs is None:
    mode = xfrm.XFRM_MODE_TRANSPORT
    saddr = XFRM_ADDR_ANY
    daddr = XFRM_ADDR_ANY
  else:
    mode = xfrm.XFRM_MODE_TUNNEL
    saddr = xfrm.PaddedAddress(tun_addrs[0])
    daddr = xfrm.PaddedAddress(tun_addrs[1])

  # Create a selector that matches all packets of the specified address family.
  # It's not actually used to select traffic, that will be done by the socket
  # policy, which selects the SA entry (i.e., xfrm state) via the SPI and reqid.
  selector = xfrm.XfrmSelector(
      daddr=XFRM_ADDR_ANY, saddr=XFRM_ADDR_ANY, family=family)

  # Create a user policy that specifies that all outbound packets matchin
  # the (essentially no-op) selector should be encrypted.
  policy = xfrm.XfrmUserpolicyInfo(
      sel=selector,
      lft=xfrm.NO_LIFETIME_CFG,
      curlft=xfrm.NO_LIFETIME_CUR,
      dir=direction,
      action=xfrm.XFRM_POLICY_ALLOW,
      flags=xfrm.XFRM_POLICY_LOCALOK,
      share=xfrm.XFRM_SHARE_UNIQUE)

  # Create a template that specifies the SPI and the protocol.
  xfrmid = xfrm.XfrmId(daddr=daddr, spi=spi, proto=IPPROTO_ESP)
  template = xfrm.XfrmUserTmpl(
      id=xfrmid,
      family=family,
      saddr=saddr,
      reqid=reqid,
      mode=mode,
      share=xfrm.XFRM_SHARE_UNIQUE,
      optional=0,  #require
      aalgos=ALL_ALGORITHMS,
      ealgos=ALL_ALGORITHMS,
      calgos=ALL_ALGORITHMS)

  # Set the policy and template on our socket.
  opt_data = policy.Pack() + template.Pack()
  if family == AF_INET:
    sock.setsockopt(IPPROTO_IP, xfrm.IP_XFRM_POLICY, opt_data)
  else:
    sock.setsockopt(IPPROTO_IPV6, xfrm.IPV6_XFRM_POLICY, opt_data)


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

  def expectEspPacketOn(self, version, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    if version == 4:
      self.assertTrue(isinstance(packet, scapy.IP))
      self.assertEquals(IPPROTO_ESP, packet.proto)
    else:
      self.assertTrue(isinstance(packet, scapy.IPv6))
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

  @classmethod
  def InjectTests(cls):
    """Inject parameterized test cases into this class.

    Because a library for parameterized testing is not availble in
    net_test.rootfs.20150203, this does a minimal parameterization.

    This finds methods named like "ParamTestFoo" and replaces them with several
    "testFoo(*)" methods taking different parameter dicts. A set of test
    parameters is generated from every combination of encryption,
    authentication, IP version, and TCP/UDP.

    The benefit of this approach is that an individually failing tests have a
    clearly separated stack trace, and one failed test doesn't prevent the rest
    from running.
    """
    param_test_names = [
        name for name in dir(cls) if name.startswith("ParamTest")
    ]
    FAMILIES = (AF_INET, AF_INET6)
    TYPES = (SOCK_DGRAM, SOCK_STREAM)
    for crypt, auth, family, proto, name in itertools.product(
        CRYPT_ALGOS, AUTH_ALGOS, FAMILIES, TYPES, param_test_names):
      func = getattr(cls, name)
      params = {"crypt": crypt, "auth": auth, "family": family, "proto": proto}

      def TestClosure(self, params=params):
        func(self, params)

      # Produce a unique and readable name for each test. e.g.
      #     testSocketPolicySimple_cbc-aes_256_hmac-sha512_512_256_IPv6_UDP
      param_string = "%s_%d_%s_%d_%d_%s_%s" % (
          crypt.name, crypt.key_len, auth.name, auth.key_len, auth.trunc_len,
          "IPv4" if family == AF_INET else "IPv6",
          "UDP" if proto == SOCK_DGRAM else "TCP")
      new_name = "%s_%s" % (func.__name__.replace("ParamTest", "test"),
                            param_string)
      new_name = new_name.replace("(", "-").replace(")", "")  # remove parens
      setattr(cls, new_name, TestClosure)

  def testAddSa(self):
    self.xfrm.AddMinimalSaInfo("::", TEST_ADDR1, htonl(TEST_SPI), IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, 3320,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None, None)
    expected = (
        "src :: dst 2001:4860:4860::8888\n"
        "\tproto esp spi 0x00001234 reqid 3320 mode transport\n"
        "\treplay-window 4 \n"
        "\tauth-trunc hmac(sha1) 0x%s 96\n"
        "\tenc cbc(aes) 0x%s\n"
        "\tsel src ::/0 dst ::/0 \n" % (
            AUTH_TRUNC_KEY.encode("hex"), ENCRYPTION_KEY.encode("hex")))

    actual = subprocess.check_output("ip xfrm state".split())
    try:
      self.assertMultiLineEqual(expected, actual)
    finally:
      self.xfrm.DeleteSaInfo(TEST_ADDR1, htonl(TEST_SPI), IPPROTO_ESP)

  def testFlush(self):
    self.assertEquals(0, len(self.xfrm.DumpSaInfo()))
    self.xfrm.AddMinimalSaInfo("::", "2000::", htonl(TEST_SPI),
                               IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, 1234,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None, None)
    self.xfrm.AddMinimalSaInfo("0.0.0.0", "192.0.2.1", htonl(TEST_SPI),
                               IPPROTO_ESP, xfrm.XFRM_MODE_TRANSPORT, 4321,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None, None)
    self.assertEquals(2, len(self.xfrm.DumpSaInfo()))
    self.xfrm.FlushSaInfo()
    self.assertEquals(0, len(self.xfrm.DumpSaInfo()))

  def testSocketPolicy(self):
    # Open an IPv6 UDP socket and connect it.
    s = socket(AF_INET6, SOCK_DGRAM, 0)
    netid = random.choice(self.NETIDS)
    self.SelectInterface(s, netid, "mark")
    s.connect((TEST_ADDR1, 53))
    saddr, sport = s.getsockname()[:2]
    daddr, dport = s.getpeername()[:2]
    reqid = 0

    ApplySocketPolicy(s, AF_INET6, xfrm.XFRM_POLICY_OUT, htonl(TEST_SPI), reqid)

    # Invalidate destination cache entries, so that future sends on the socket
    # use the socket policy we've just applied instead of being sent in the
    # clear due to the previously-cached dst cache entry.
    #
    # TODO: fix this problem in the kernel, as this workaround cannot be used in
    # on-device code.
    self.InvalidateDstCache(6, netid)

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
    self.xfrm.AddMinimalSaInfo("::", TEST_ADDR1, htonl(TEST_SPI), IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None, None)
    s.sendto(net_test.UDP_PAYLOAD, (TEST_ADDR1, 53))
    expected_length = GetEspPacketLength(6, xfrm.XFRM_MODE_TRANSPORT,
                                         IPPROTO_IPV6)
    self.expectEspPacketOn(6, netid, TEST_SPI, 1, expected_length)

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

    # Use the same SPI both inbound and outbound because this lets us receive
    # encrypted packets by simply replaying the packets the kernel sends.
    in_reqid = 123
    in_spi = htonl(TEST_SPI)
    out_reqid = 456
    out_spi = htonl(TEST_SPI)

    # Apply an outbound socket policy to s.
    ApplySocketPolicy(s, AF_INET, xfrm.XFRM_POLICY_OUT, out_spi, out_reqid)

    # Uncomment for debugging.
    # subprocess.call("ip xfrm policy".split())

    # Create inbound and outbound SAs that specify UDP encapsulation.
    encaptmpl = xfrm.XfrmEncapTmpl((xfrm.UDP_ENCAP_ESPINUDP, htons(encap_port),
                                    htons(4500), 16 * "\x00"))
    self.xfrm.AddMinimalSaInfo(myaddr, remoteaddr, out_spi, IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, out_reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, encaptmpl,
                               None, None)

    # Add an encap template that's the mirror of the outbound one.
    encaptmpl.sport, encaptmpl.dport = encaptmpl.dport, encaptmpl.sport
    self.xfrm.AddMinimalSaInfo(remoteaddr, myaddr, in_spi, IPPROTO_ESP,
                               xfrm.XFRM_MODE_TRANSPORT, in_reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, encaptmpl,
                               None, None)

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

    # TODO: why does this work without a per-socket policy applied?
    # The received  packet obviously matches an SA, but don't inbound packets
    # need to match a policy as well?

    # Save the payload of the packet so we can replay it back to ourselves, and
    # replace the SPI with our inbound SPI.
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

    # Check that unencrypted packets on twisted_socket are not received.
    unencrypted = (scapy.IP(src=remoteaddr, dst=myaddr) /
                   scapy.UDP(sport=srcport, dport=53) / "foo")
    self.assertRaisesErrno(EAGAIN, twisted_socket.recv, 4096)

  def testAllocSpecificSpi(self):
    spi = 0xABCD
    new_sa = self.xfrm.AllocSpi("::", IPPROTO_ESP, spi, spi)
    self.assertEquals(spi, ntohl(new_sa.id.spi))

  def testAllocSpecificSpiUnavailable(self):
    """Attempt to allocate the same SPI twice."""
    spi = 0xABCD
    new_sa = self.xfrm.AllocSpi("::", IPPROTO_ESP, spi, spi)
    self.assertEquals(spi, ntohl(new_sa.id.spi))
    with self.assertRaisesErrno(ENOENT):
      new_sa = self.xfrm.AllocSpi("::", IPPROTO_ESP, spi, spi)

  def testAllocRangeSpi(self):
    start, end = 0xABCD0, 0xABCDF
    new_sa = self.xfrm.AllocSpi("::", IPPROTO_ESP, start, end)
    spi = ntohl(new_sa.id.spi)
    self.assertGreaterEqual(spi, start)
    self.assertLessEqual(spi, end)

  def testAllocRangeSpiUnavailable(self):
    """Attempt to allocate N+1 SPIs from a range of size N."""
    start, end = 0xABCD0, 0xABCDF
    range_size = end - start + 1
    spis = set()
    # Assert that allocating SPI fails when none are available.
    with self.assertRaisesErrno(ENOENT):
      # Allocating range_size + 1 SPIs is guaranteed to fail.  Due to the way
      # kernel picks random SPIs, this has a high probability of failing before
      # reaching that limit.
      for i in xrange(range_size + 1):
        new_sa = self.xfrm.AllocSpi("::", IPPROTO_ESP, start, end)
        spi = ntohl(new_sa.id.spi)
        self.assertNotIn(spi, spis)
        spis.add(spi)

  @unittest.skipIf(net_test.LINUX_VERSION[:2] == (3, 18), "b/63589559")
  def ParamTestSocketPolicySimple(self, params):
    """Test two-way traffic using transport mode and socket policies."""

    def AssertEncrypted(packet):
      # This gives a free pass to ICMP and ICMPv6 packets, which show up
      # nondeterministically in tests.
      self.assertEquals(None,
                        packet.getlayer(scapy.UDP),
                        "UDP packet sent in the clear")
      self.assertEquals(None,
                        packet.getlayer(scapy.TCP),
                        "TCP packet sent in the clear")

    # We create a pair of sockets, "left" and "right", that will talk to each
    # other using transport mode ESP. Because of TapTwister, both sockets
    # perceive each other as owning "remote_addr".
    netid = random.choice(self.NETIDS)
    if params["family"] == AF_INET:
      # TODO: utils should use AF_INET & AF_INET6 constants.
      local_addr = self.MyAddress(4, netid)
      remote_addr = self.GetRemoteAddress(4)
    else:
      local_addr = self.MyAddress(6, netid)
      remote_addr = self.GetRemoteAddress(6)
    ekey_left = os.urandom(params["crypt"].key_len / 8)
    akey_left = os.urandom(params["auth"].key_len / 8)
    ekey_right = os.urandom(params["crypt"].key_len / 8)
    akey_right = os.urandom(params["auth"].key_len / 8)
    spi_left = htonl(0xbeefface)
    spi_right = htonl(0xcafed00d)
    req_ids = [100, 200, 300, 400]  # Used to match templates and SAs.

    # Left outbound SA
    self.xfrm.AddMinimalSaInfo(
        src=local_addr,
        dst=remote_addr,
        spi=spi_right,
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=req_ids[0],
        encryption=params["crypt"],
        encryption_key=ekey_right,
        auth_trunc=params["auth"],
        auth_trunc_key=akey_right,
        encap=None,
        mark=None,
        mark_mask=None)
    # Right inbound SA
    self.xfrm.AddMinimalSaInfo(
        src=remote_addr,
        dst=local_addr,
        spi=spi_right,
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=req_ids[1],
        encryption=params["crypt"],
        encryption_key=ekey_right,
        auth_trunc=params["auth"],
        auth_trunc_key=akey_right,
        encap=None,
        mark=None,
        mark_mask=None)
    # Right outbound SA
    self.xfrm.AddMinimalSaInfo(
        src=local_addr,
        dst=remote_addr,
        spi=spi_left,
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=req_ids[2],
        encryption=params["crypt"],
        encryption_key=ekey_left,
        auth_trunc=params["auth"],
        auth_trunc_key=akey_left,
        encap=None,
        mark=None,
        mark_mask=None)
    # Left inbound SA
    self.xfrm.AddMinimalSaInfo(
        src=remote_addr,
        dst=local_addr,
        spi=spi_left,
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=req_ids[3],
        encryption=params["crypt"],
        encryption_key=ekey_left,
        auth_trunc=params["auth"],
        auth_trunc_key=akey_left,
        encap=None,
        mark=None,
        mark_mask=None)

    # Make two sockets.
    sock_left = socket(params["family"], params["proto"], 0)
    sock_left.settimeout(2.0)
    sock_left.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    self.SelectInterface(sock_left, netid, "mark")
    sock_right = socket(params["family"], params["proto"], 0)
    sock_right.settimeout(2.0)
    sock_right.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    self.SelectInterface(sock_right, netid, "mark")

    # Apply the left outbound socket policy.
    ApplySocketPolicy(sock_left, params["family"], xfrm.XFRM_POLICY_OUT,
                      spi_right, req_ids[0])
    # Apply right inbound socket policy.
    ApplySocketPolicy(sock_right, params["family"], xfrm.XFRM_POLICY_IN,
                      spi_right, req_ids[1])
    # Apply right outbound socket policy.
    ApplySocketPolicy(sock_right, params["family"], xfrm.XFRM_POLICY_OUT,
                      spi_left, req_ids[2])
    # Apply left inbound socket policy.
    ApplySocketPolicy(sock_left, params["family"], xfrm.XFRM_POLICY_IN,
                      spi_left, req_ids[3])

    server_ready = threading.Event()
    server_error = None  # Save exceptions thrown by the server.

    def TcpServer(sock, client_port):
      try:
        sock.listen(1)
        server_ready.set()
        accepted, peer = sock.accept()
        self.assertEquals(remote_addr, peer[0])
        self.assertEquals(client_port, peer[1])
        data = accepted.recv(2048)
        self.assertEquals("hello request", data)
        accepted.send("hello response")
      except Exception as e:
        server_error = e
      finally:
        sock.close()

    def UdpServer(sock, client_port):
      try:
        server_ready.set()
        data, peer = sock.recvfrom(2048)
        self.assertEquals(remote_addr, peer[0])
        self.assertEquals(client_port, peer[1])
        self.assertEquals("hello request", data)
        sock.sendto("hello response", peer)
      except Exception as e:
        server_error = e
      finally:
        sock.close()

    # Server and client need to know each other's port numbers in advance.
    sock_left.bind((ADDR_ANY[params["family"]], 0))
    sock_right.bind((ADDR_ANY[params["family"]], 0))
    left_port = sock_left.getsockname()[1]
    right_port = sock_right.getsockname()[1]

    # Start the appropriate server type on sock_right.
    target = TcpServer if params["proto"] == SOCK_STREAM else UdpServer
    server = threading.Thread(
        target=target,
        args=(sock_right, left_port),
        name="SocketServer")
    server.start()
    # Wait for server to be ready before attempting to connect. TCP retries
    # hide this problem, but UDP will fail outright if the server socket has
    # not bound when we send.
    self.assertTrue(server_ready.wait(2.0), "Timed out waiting for server thread")

    with TapTwister(fd=self.tuns[netid].fileno(), validator=AssertEncrypted):
      sock_left.connect((remote_addr, right_port))
      sock_left.send("hello request")
      data = sock_left.recv(2048)
      self.assertEquals("hello response", data)
      if params["proto"] == SOCK_STREAM:
        sock_left.shutdown(SHUT_RD)
      sock_left.close()
      server.join()
    if server_error:
      raise server_error


@unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
class XfrmOutputMarkTest(multinetwork_base.MultiNetworkBaseTest):

  # TODO: delete this when we can inherit from a base class.
  def setUp(self):
    super(XfrmOutputMarkTest, self).setUp()
    self.xfrm = xfrm.Xfrm()
    self.xfrm.FlushSaInfo()

  # TODO: delete this when we can inherit from a base class.
  def tearDown(self):
    super(XfrmOutputMarkTest, self).tearDown()
    self.xfrm.FlushSaInfo()

  # TODO: delete this when we can inherit from a base class.
  def expectEspPacketOn(self, version, netid, spi, seq, length):
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    if version == 4:
      self.assertTrue(isinstance(packet, scapy.IP))
      self.assertEquals(IPPROTO_ESP, packet.proto)
    else:
      self.assertTrue(isinstance(packet, scapy.IPv6))
      self.assertEquals(IPPROTO_ESP, packet.nh)
    spi_seq = struct.pack("!II", spi, seq)
    self.assertEquals(spi_seq, str(packet.payload)[:len(spi_seq)])
    self.assertEquals(length, len(packet.payload))

  def _CheckTunnelModeOutputMark(self, version, netid, mark, expected_netid):
    """Tests sending UDP packets to tunnel mode SAs with output marks.

    Opens a UDP socket and binds it to a random netid, then sets up tunnel mode
    SAs with an output_mark of mark and sets a socket policy to use the SA.
    Then checks that sending on those SAs sends a packet on expected_netid,
    or, if expected_netid is zero, checks that sending returns ENETUNREACH.

    Args:
      version: 4 or 6.
      netid: An integer, the netid of the interface to source the tunnel from.
        Only affects the source address of the tunnel.
      mark: An integer, the output_mark to set in the SA.
      expected_netid: An integer, the netid to expect the kernel to send the
          packet on. If None, expect that sendto will fail with ENETUNREACH.
    """
    # Open a UDP socket and bind it to a random netid.
    family = {4: AF_INET, 6: AF_INET6}[version]
    s = socket(family, SOCK_DGRAM, 0)
    self.SelectInterface(s, random.choice(self.NETIDS), "mark")

    # For generality, pick a tunnel endpoint that's not the address we
    # connect the socket to.
    tunsrc = self.MyAddress(version, netid)
    tundst = {4: TUNNEL_ENDPOINT_IPV4, 6: TUNNEL_ENDPOINT_IPV6}[version]
    tun_addrs = (tunsrc, tundst)

    # Create a tunnel mode SA and use XFRM_OUTPUT_MARK to bind it to netid.
    spi = htonl(TEST_SPI * netid)
    reqid = 100 + spi
    self.xfrm.AddMinimalSaInfo(tunsrc, tundst, spi,
                               IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, reqid,
                               ALGO_CBC_AES_256, ENCRYPTION_KEY,
                               ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None,
                               None, output_mark=mark)


    # Set a socket policy to use it.
    ApplySocketPolicy(s, family, xfrm.XFRM_POLICY_OUT, spi, reqid,
                      tun_addrs=tun_addrs)

    # Send a packet and check that we see it on the wire.
    remoteaddr = self.GetRemoteAddress(version)

    packetlen = GetEspPacketLength(version, xfrm.XFRM_MODE_TUNNEL, IPPROTO_IP)

    if expected_netid is not None:
      s.sendto(net_test.UDP_PAYLOAD, (remoteaddr, 53))
      self.expectEspPacketOn(version, expected_netid, htonl(spi), 1, packetlen)
    else:
      with self.assertRaisesErrno(ENETUNREACH):
        s.sendto(net_test.UDP_PAYLOAD, (remoteaddr, 53))

  def testTunnelModeOutputMarkIPv4(self):
    for netid in self.NETIDS:
      self._CheckTunnelModeOutputMark(4, netid, netid, netid)

  def testTunnelModeOutputMarkIPv6(self):
    for netid in self.NETIDS:
      self._CheckTunnelModeOutputMark(6, netid, netid, netid)

  def testTunnelModeOutputNoMarkIPv4(self):
    netid = random.choice(self.NETIDS)
    self._CheckTunnelModeOutputMark(4, netid, 0, None)

  def testTunnelModeOutputNoMarkIPv6(self):
    netid = random.choice(self.NETIDS)
    self._CheckTunnelModeOutputMark(6, netid, 0, None)

  def testTunnelModeOutputInvalidMarkIPv4(self):
    netid = random.choice(self.NETIDS)
    self._CheckTunnelModeOutputMark(4, netid, 9999, None)

  def testTunnelModeOutputInvalidMarkIPv6(self):
    netid = random.choice(self.NETIDS)
    self._CheckTunnelModeOutputMark(6, netid, 9999, None)

  def testTunnelModeOutputMarkAttributes(self):
      mark = 1234567
      self.xfrm.AddMinimalSaInfo(TEST_ADDR1, TUNNEL_ENDPOINT_IPV6, 0x1234,
                                 IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, 100,
                                 ALGO_CBC_AES_256, ENCRYPTION_KEY,
                                 ALGO_HMAC_SHA1, AUTH_TRUNC_KEY, None, None,
                                 None, output_mark=mark)
      dump = self.xfrm.DumpSaInfo()
      self.assertEquals(1, len(dump))
      sainfo, attributes = dump[0]
      self.assertEquals(mark, attributes["XFRMA_OUTPUT_MARK"])


if __name__ == "__main__":
  XfrmTest.InjectTests()
  unittest.main()
