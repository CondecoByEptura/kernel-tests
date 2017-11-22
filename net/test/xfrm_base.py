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

from socket import *  # pylint: disable=wildcard-import
from scapy import all as scapy
import struct

import cstruct
import multinetwork_base
import net_test
import xfrm

_ENCRYPTION_KEY_256 = ("308146eb3bd84b044573d60f5a5fd159"
                       "57c7d4fe567a2120f35bae0f9869ec22".decode("hex"))
_AUTHENTICATION_KEY_128 = "af442892cdcd0ef650e9c299f9a8436a".decode("hex")

_ALGO_AUTH_NULL = xfrm.XfrmAlgoAuth(("digest_null", 0, 0))
_ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
_ALGO_CRYPT_NULL = xfrm.XfrmAlgo(("ecb(cipher_null)", 0))
_ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))

# Match all bits of the mark
MARK_MASK_ALL = 0xffffffff
ALL_ALGORITHMS = 0xffffffff

XFRM_ADDR_ANY = xfrm.PaddedAddress("::")


def ApplySocketPolicy(sock, family, direction, spi, reqid, tun_addrs):
  """Create and apply socket policy objects.

  AH is not supported. This is ESP only.

  Args:
    sock: The socket that needs a policy
    family: AF_INET or AF_INET6
    direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
    spi: 32-bit SPI in network byte order
    reqid: 32-bit ID matched against SAs
    tun_addrs: A tuple of (local, remote) addresses for tunnel mode, or None
      to request a transport mode SA.

  Return: a tuple of XfrmUserpolicyInfo, XfrmUserTmpl
  """
  # For transport mode, set template source and destination are empty.
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

  # Create a user policy that specifies that all outbound packets matching the
  # (essentially no-op) selector should be encrypted.
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


def GetEspPacketLength(mode, version, encap, payload):
  """Calculates encrypted length of a UDP packet with the given payload.

  Currently assumes ALGO_CBC_AES_256 and ALGO_HMAC_SHA1.

  Args:
    mode: XFRM_MODE_TRANSPORT or XFRM_MODE_TUNNEL.
    version: IPPROTO_IP for IPv4, IPPROTO_IPV6 for IPv6. The inner header.
    outer: The outer header. None for transport mode, IPPROTO_IP or IPPROTO_IPV6
      (TODO: support IPPROTO_UDP for UDP encap) for tunnel mode.
    payload: UDP payload bytes.

  Return: the packet length.

  Raises:
    NotImplementedError: unsupported combination.
  """
  if len(payload) != len(net_test.UDP_PAYLOAD):
    raise NotImplementedError("Only one payload length is supported.")

  # TODO: make this non-trivial, either using a more general matrix, or by
  # calculating sizes dynamically based on algorithm block sizes and padding.
  LENGTHS = {
      xfrm.XFRM_MODE_TUNNEL: {
          IPPROTO_IP: {
              4: 100,
              6: 132,
          },
      },
      xfrm.XFRM_MODE_TRANSPORT: {
          None: {
              6: 84,
          },
      },
  }

  try:
    return LENGTHS[mode][encap][version]
  except KeyError:
    raise NotImplementedError(
      "Unsupported combination mode=%s encap=%s version=%s" %
      (mode, encap, version))


def EncryptPacketWithNull(packet, spi, seq, tsrc_addr=None, tdst_addr=None):
  """Apply null encryption to a packet.

  This performs ESP encapsulation on the given packet. The returned packet will
  be tunnel mode if tsrc_addr and tdst_addr are provided.

  The input packet is assumed to be a UDP packet. The input packet *MUST* have
  its length and checksum fields in IP and UDP headers set appropriately. This
  can be done by "rebuilding" the scapy object. e.g.,
      ip6_packet = scapy.IPv6(str(ip6_packet))

  TODO: Support TCP

  Args:
    packet: a scapy.IPv6 or scapy.IP packet
    spi: security parameter index for ESP header
    seq: sequence number for ESP header
    tsrc_addr: (tunnel mode) outer source IP address in string form
    tdst_addr: (tunnel mode) outer destination IP address in string form

  Return:
    The encrypted packet (scapy.IPv6 or scapy.IP)
  """
  packet = packet.copy() # Don't modify original
  udp_layer = packet.getlayer(scapy.UDP)
  if not udp_layer:
    raise ValueError("Expected a UDP packet")
  # Build an ESP header.
  esp_hdr = scapy.Raw(xfrm.EspHdr((spi, seq)).Pack())
  esp_nexthdr = IPPROTO_UDP

  new_ip_layer = None
  inner_layer = udp_layer
  if tsrc_addr and tdst_addr:
    outer_version = net_test.GetAddressVersion(tsrc_addr)
    IpType = {4: scapy.IP, 6: scapy.IPv6}[outer_version]
    new_ip_layer = IpType(src=tsrc_addr, dst=tdst_addr)
    if type(packet) is scapy.IPv6:
      esp_nexthdr = IPPROTO_IPV6
    elif type(packet) is scapy.IP:
      esp_nexthdr = IPPROTO_IPIP
    inner_layer = packet

  # ESP padding per RFC 4303 section 2.4.
  # For a null cipher with a block size of 1, padding is only necessary to
  # ensure that the 1-byte Pad Length and Next Header fields are right aligned
  # on a 4-byte boundary.
  esplen = (len(inner_layer) + 2)  # payload length plus Pad Length and Next Header.
  padlen = (4 - esplen) % 4
  # The pad bytes are consecutive integers starting from 0x01.
  padding = "".join((chr(i) for i in xrange(1, padlen + 1)))
  trailer = padding + struct.pack("BB", padlen, esp_nexthdr)

  # Assemble the packet.
  esp_hdr.payload = inner_layer
  if new_ip_layer:
    new_ip_layer.payload = esp_hdr # plen is right here
    packet = new_ip_layer
  else:
    packet.payload = esp_hdr
  packet.add_payload(trailer) # plen is wrong here

  # Fix the IPv4/IPv6 headers.
  if type(packet) is scapy.IPv6:
    packet.nh = IPPROTO_ESP
    # Recompute plen.
    packet.plen = None
    packet = scapy.IPv6(str(packet))
  elif type(packet) is scapy.IP:
    packet.proto = IPPROTO_ESP
    # Recompute IPv4 len and checksum.
    packet.len = None
    packet.chksum = None
    packet = scapy.IP(str(packet))
  else:
    raise ValueError("First layer in packet should be IPv4 or IPv6: " + repr(packet))
  return packet


def DecryptPacketWithNull(packet):
  """Apply null decryption to a packet.

  This performs EPS decapsulation on the given packet. The input packet is
  assumed to be a UDP packet. This function will remove the ESP header and
  trailer bytes from an ESP packet.

  TODO: Support TCP

  Args:
    packet: a scapy.IPv6 or scapy.IP packet

  Returns:
    A tuple of decrypted packet (scapy.IPv6 or scapy.IP) and EspHdr
  """
  #packet = packet.copy() # avoid surprises
  esp_layer = packet.payload
  esp_hdr, esp_data = cstruct.Read(str(esp_layer), xfrm.EspHdr)
  # Parse and strip ESP trailer.
  esp_nexthdr = ord(esp_data[-1])
  trailer_len = ord(esp_data[-2]) + 2
  LayerType = {4: scapy.IP, 41: scapy.IPv6, 17: scapy.UDP}[esp_nexthdr]
  next_layer = LayerType(esp_data[:-trailer_len])
  if esp_nexthdr in (4, 41):
    # Tunnel mode decap is simple. Return the inner packet.
    return next_layer, esp_hdr

  # Cut out the ESP header.
  packet.payload = next_layer
  # Fix the IPv4/IPv6 headers.
  if type(packet) is scapy.IPv6:
    packet.nh = esp_nexthdr
    packet.plen -= (trailer_len + len(xfrm.EspHdr))
  elif type(packet) is scapy.IP:
    packet.proto = esp_nexthdr
    packet.len -= (trailer_len + len(xfrm.EspHdr))
    # Recompute IPv4 checksum.
    packet.chksum = None
    packet = scapy.IP(str(packet))
  else:
    raise ValueError("First layer in packet should be IPv4 or IPv6: " + repr(packet))
  return packet, esp_hdr


class XfrmBaseTest(multinetwork_base.MultiNetworkBaseTest):
  """Base test class for Xfrm tests

  Base test class for all XFRM-related testing. This class will clean
  up XFRM state before and after each test.
  """
  def setUp(self):
    # TODO: delete this when we're more diligent about deleting our SAs.
    super(XfrmBaseTest, self).setUp()
    self.xfrm = xfrm.Xfrm()
    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  def tearDown(self):
    super(XfrmBaseTest, self).tearDown()
    self.xfrm.FlushSaInfo()
    self.xfrm.FlushPolicyInfo()

  def _ExpectEspPacketOn(self, netid, spi, seq, length, src_addr, dst_addr):
    """Read a packet from a netid and verify its properties.

    Args:
      netid: netid from which to read an ESP packet
      spi: SPI of the ESP packet
      seq: sequence number of the ESP packet
      length: length of the packet's payload or None to skip this check
      src_addr: source address of the packet or None to skip this check
      dst_addr: destination address of the packet or None to skip this check

    Returns:
      scapy.IP/IPv6: the read packet
    """
    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    if length is not None:
      self.assertEquals(length, len(packet.payload), "Incorrect packet length.")
    if dst_addr is not None:
      self.assertEquals(dst_addr, packet.dst, "Mismatched destination address.")
    if src_addr is not None:
      self.assertEquals(src_addr, packet.src, "Mismatched source address.")
    # extract the ESP header
    esp_hdr, _ = cstruct.Read(str(packet.payload), xfrm.EspHdr)
    self.assertEquals(xfrm.EspHdr((spi, seq)), esp_hdr)
    return packet
