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

import cstruct
import multinetwork_base
import xfrm

_ENCRYPTION_KEY_256 = ("308146eb3bd84b044573d60f5a5fd159"
                       "57c7d4fe567a2120f35bae0f9869ec22".decode("hex"))
_AUTHENTICATION_KEY_128 = "af442892cdcd0ef650e9c299f9a8436a".decode("hex")

_ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
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
    tun_addrs: A tuple of two strings or None, the tunnel addresses.
      If None, requests a transport mode SA.
      If a tuple, specifies the local/remote endpoints of a tunnel mode SA.

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
