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
import itertools
from scapy import all as scapy
from socket import *  # pylint: disable=wildcard-import
import struct
import subprocess
import threading
import unittest

import csocket
import cstruct
import multinetwork_base
import net_test
import packets
import xfrm
import xfrm_base

ENCRYPTED_PAYLOAD = ("b1c74998efd6326faebe2061f00f2c750e90e76001664a80c287b150"
                     "59e74bf949769cc6af71e51b539e7de3a2a14cb05a231b969e035174"
                     "d98c5aa0cef1937db98889ec0d08fa408fecf616")

TEST_ADDR1 = "2001:4860:4860::8888"
TEST_ADDR2 = "2001:4860:4860::8844"

# IP addresses to use for tunnel endpoints. For generality, these should be
# different from the addresses we send packets to.
TUNNEL_ENDPOINTS = {4: "8.8.4.4", 6: TEST_ADDR2}

TEST_SPI = 0x1234
TEST_SPI2 = 0x1235

# TODO: COPY-PASTA. REFACTOR THIS OUT.

def InjectParameterizedTests(cls):
  """Inject parameterized test cases into this class.

  Because a library for parameterized testing is not available in
  net_test.rootfs.20150203, this does a minimal parameterization.

  This finds methods named like "ParamTestFoo" and replaces them with several
  "testFoo(*)" methods taking different parameter dicts. A set of test
  parameters is generated from every combination of inner and outer address
  families.

  The benefit of this approach is that an individually failing tests have a
  clearly separated stack trace, and one failed test doesn't prevent the rest
  from running.
  """
  param_test_names = [name for name in dir(cls) if name.startswith("ParamTest")]
  VERSIONS = (4, 6)
  ENCAP = (True, False)
  WITH_SA = (True, False)
  WITH_POL = (True, False)
  BLOCKING_POL = (True, False)

  # Tests all combinations of auth & crypt. Mutually exclusive with aead.
  for name, version, encap, with_sa, with_pol, blocking_pol in itertools.product(
      param_test_names, VERSIONS, ENCAP, WITH_SA, WITH_POL, BLOCKING_POL):

    # IPv6 with UDP encap is unsupported by the kernel. skip
    if version == 6 and encap:
      continue

    # Having a blocking, missing policy makes no sense. skip
    if not with_pol and blocking_pol:
      continue

    InjectSingleTest(cls, name, version, encap, with_sa, with_pol, blocking_pol)


def InjectSingleTest(cls, name, version, encap, with_sa, with_pol, blocking_pol):
  func = getattr(cls, name)

  def TestClosure(self):
    func(self, version, encap, with_sa, with_pol, blocking_pol)

  polString = "WithBlockingPol" if with_pol and blocking_pol else "WithPol" if with_pol and not blocking_pol else "NoPol"
  param_string = "IPv%d_%s_%s_%s" % (version, \
      "UDPEncap" if encap else "ESP", \
      "WithSA" if with_sa else "NoSA", \
      polString)
  new_name = "%s_%s" % (func.__name__.replace("ParamTest", "test"),
                        param_string)
  setattr(cls, new_name, TestClosure)

class XfrmFunctionalTest(xfrm_base.XfrmLazyTest):
  def _VerifyOutboundSocketPolicy(self, version, use_encap, with_sa, with_pol, blocking_pol):
    family = net_test.GetAddressFamily(version)
    netid = self.RandomNetid()
    local_addr = self.MyAddress(version, netid)
    remote_addr = self.GetRemoteAddress(version)

    # Create sending socket
    src_sock = net_test.UDPSocket(family)
    self.SelectInterface(src_sock, netid, "mark")
    src_sock.bind((local_addr, 0))
    src_port = src_sock.getsockname()[1]
    remote_port = 5555

    # Setup encap socket & template as needed.
    if use_encap:
      # Create encap socket
      encap_sock = net_test.UDPSocket(family)
      self.SelectInterface(encap_sock, netid, "mark")
      encap_sock.bind((local_addr, 0))
      encap_port = encap_sock.getsockname()[1]
      encap_sock.setsockopt(IPPROTO_UDP, xfrm.UDP_ENCAP, xfrm.UDP_ENCAP_ESPINUDP)
      remote_encap_port = 5556

      # Create Output encap template
      encap_tmpl = xfrm.XfrmEncapTmpl((xfrm.UDP_ENCAP_ESPINUDP, htons(encap_port),
                                       htons(remote_encap_port), 16 * "\x00"))
    else:
      encap_tmpl = None

    if with_sa:
      self.xfrm.AddSaInfo(
          local_addr, remote_addr, TEST_SPI, xfrm.XFRM_MODE_TRANSPORT, TEST_SPI,
          xfrm_base._ALGO_CRYPT_NULL, xfrm_base._ALGO_AUTH_NULL,
          None, encap_tmpl, None, None)
    if with_pol:
      if blocking_pol:
        xfrm_base.ApplyBlockingSocketPolicy(
            src_sock, family, xfrm.XFRM_POLICY_OUT, TEST_SPI, TEST_SPI, None)
      else:
        xfrm_base.ApplySocketPolicy(
            src_sock, family, xfrm.XFRM_POLICY_OUT, TEST_SPI, TEST_SPI, None)

    # Send and capture a packet.
    if blocking_pol:
      self.assertRaisesErrno(
          EPERM,
          src_sock.sendto, "TEST OUTPUT", (remote_addr, remote_port))
    elif not with_sa and with_pol:
      self.assertRaisesErrno(
          EAGAIN,
          src_sock.sendto, "TEST OUTPUT", (remote_addr, remote_port))
    else:
      src_sock.sendto("TEST OUTPUT", (remote_addr, remote_port))
      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      packet = packets[0]

      # Generate the expected packet before any IPsec applications
      IpType = {4: scapy.IP, 6: scapy.IPv6}[version]
      expected_pkt_base = (IpType(src=local_addr, dst=remote_addr) /
                  scapy.UDP(sport=src_port, dport=remote_port) /
                  "TEST OUTPUT")
      expected_pkt_base = IpType(str(expected_pkt_base)) # Compute length, checksum.

      if not with_pol:
        self.assertEquals(packet.load, expected_pkt_base.load)
      else:
        # Generate the expected packet after IPsec application
        expected_pkt = xfrm_base.EncryptPacketWithNull(expected_pkt_base, TEST_SPI, 1, None)

        if use_encap:
          # Perform UDP encapsulation manually as needed
          expected_pkt = (IpType(src=local_addr, dst=remote_addr) /
                      scapy.UDP(sport=encap_port, dport=remote_encap_port) /
                      expected_pkt.load)
          expected_pkt = IpType(str(expected_pkt)) # Compute length, checksum.

        self.assertEquals(packet.load, expected_pkt.load)

  def ParamTestOutput(self, version, use_encap, with_sa, with_pol, blocking_pol):
    self._VerifyOutboundSocketPolicy(version, use_encap, with_sa, with_pol, blocking_pol)

  def _VerifyInboundSocketPolicy(self, version, use_encap, with_sa, with_pol, blocking_pol):
    family = net_test.GetAddressFamily(version)
    netid = self.RandomNetid()
    local_addr = self.MyAddress(version, netid)
    remote_addr = self.GetRemoteAddress(version)

    # Create receiving socket
    rcv_sock = net_test.UDPSocket(family)
    self.SelectInterface(rcv_sock, netid, "mark")
    rcv_sock.bind((local_addr, 0))
    rcv_port = rcv_sock.getsockname()[1]
    csocket.SetSocketTimeout(rcv_sock, 100)
    remote_port = 5555

    # Setup encap socket & template as needed.
    if use_encap:
      # Create receiving socket
      encap_sock = net_test.UDPSocket(family)
      self.SelectInterface(encap_sock, netid, "mark")
      encap_sock.bind((local_addr, 0))
      encap_port = encap_sock.getsockname()[1]
      encap_sock.setsockopt(IPPROTO_UDP, xfrm.UDP_ENCAP, xfrm.UDP_ENCAP_ESPINUDP)
      remote_encap_port = 5556

      # Create Input SA
      encap_tmpl = xfrm.XfrmEncapTmpl((xfrm.UDP_ENCAP_ESPINUDP, htons(remote_encap_port),
                                      htons(encap_port), 16 * "\x00"))
    else:
      encap_tmpl = None

    if with_sa:
      self.xfrm.AddSaInfo(
          remote_addr, local_addr, TEST_SPI, xfrm.XFRM_MODE_TRANSPORT, TEST_SPI,
          xfrm_base._ALGO_CRYPT_NULL, xfrm_base._ALGO_AUTH_NULL,
          None, encap_tmpl, None, None)
    if with_pol:
      if blocking_pol:
        xfrm_base.ApplyBlockingSocketPolicy(
            rcv_sock, family, xfrm.XFRM_POLICY_IN, TEST_SPI, TEST_SPI, None)
      else:
        xfrm_base.ApplySocketPolicy(
            rcv_sock, family, xfrm.XFRM_POLICY_IN, TEST_SPI, TEST_SPI, None)


    # Create and receive an ESP packet.
    IpType = {4: scapy.IP, 6: scapy.IPv6}[version]
    input_pkt = (IpType(src=remote_addr, dst=local_addr) /
                 scapy.UDP(sport=remote_port, dport=rcv_port) /
                 "input hello")
    input_pkt = IpType(str(input_pkt)) # Compute length, checksum.
    input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, TEST_SPI, 1, None)

    if use_encap:
      # Perform UDP encapsulation manually
      input_pkt = (IpType(src=remote_addr, dst=local_addr) /
                  scapy.UDP(sport=remote_encap_port, dport=encap_port) /
                  input_pkt.load)
      input_pkt = IpType(str(input_pkt)) # Compute length, checksum.

    self.ReceivePacketOn(netid, input_pkt)

    if not with_sa or not with_pol or blocking_pol:
      self.assertRaisesErrno(
          EAGAIN,
          rcv_sock.recvfrom, 1024)
    else:
      self.ReceivePacketOn(netid, input_pkt)
      msg, addr = rcv_sock.recvfrom(1024)
      self.assertEquals("input hello", msg)
      self.assertEquals((remote_addr, remote_port), addr[:2])

  def ParamTestInput(self, version, use_encap, with_sa, with_pol, blocking_pol):
    self._VerifyInboundSocketPolicy(version, use_encap, with_sa, with_pol, blocking_pol)


if __name__ == "__main__":
  InjectParameterizedTests(XfrmFunctionalTest)
  unittest.main()
