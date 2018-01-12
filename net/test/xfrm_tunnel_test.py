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
from socket import *  # pylint: disable=wildcard-import

import itertools
import struct
import unittest

from scapy import all as scapy
from tun_twister import TunTwister
import csocket
import iproute
import multinetwork_base
import net_test
import xfrm
import xfrm_base

# Parameters to Set up VTI as a special network
_VTI_NETID = 50
_VTI_IFNAME = "test_vti"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI

_TEST_OKEY = _TEST_OUT_SPI + _VTI_NETID
_TEST_IKEY = _TEST_IN_SPI + _VTI_NETID


def _GetLocalInnerAddress(version):
  return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]


def _GetRemoteInnerAddress(version):
  return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]


def _GetRemoteOuterAddress(version):
  return {4: net_test.IPV4_ADDR, 6: net_test.IPV6_ADDR}[version]

def _GetNullAuthCryptTunnelModePkt(inner_version, src_inner, src_outer,
                                   src_port, dst_inner, dst_outer,
                                   dst_port, spi, seqNum, ip_hdr_options={}):
  ip_hdr_options.update({'src': src_inner, 'dst': dst_inner})

  # Build and receive an ESP packet destined for the inner socket
  IpType = {4: scapy.IP, 6: scapy.IPv6}[inner_version]
  input_pkt = (
      IpType(**ip_hdr_options) / scapy.UDP(sport=src_port, dport=dst_port) /
      net_test.UDP_PAYLOAD)
  input_pkt = IpType(str(input_pkt))  # Compute length, checksum.
  input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, spi, seqNum,
                                              (src_outer, dst_outer))

  return input_pkt

def _CreateReceiveSock(version, port=0):
  # Create a socket to receive packets.
  read_sock = socket(net_test.GetAddressFamily(version), SOCK_DGRAM, 0)
  read_sock.bind((net_test.GetWildcardAddress(version), port))
  # The second parameter of the tuple is the port number regardless of AF.
  local_port = read_sock.getsockname()[1]
  # Guard against the eventuality of the receive failing.
  net_test.SetNonBlocking(read_sock.fileno())

  return read_sock, local_port

def _SendPacket(testInstance, netid, version, remote, remote_port):
  # Send a packet out via the vti-backed network, bound for the port number
  # of the input socket.
  write_sock = socket(net_test.GetAddressFamily(version), SOCK_DGRAM, 0)
  testInstance.SelectInterface(write_sock, netid, "mark")
  write_sock.sendto(net_test.UDP_PAYLOAD, (remote, remote_port))
  local_port = write_sock.getsockname()[1]

  return local_port

def InjectParameterizedTests(cls):
  """Inject parameterized test cases into this class.

  Because a library for parameterized testing is not availble in
  net_test.rootfs.20150203, this does a minimal parameterization.

  This finds methods named like "ParamTestFoo" and replaces them with several
  "testFoo(*)" methods taking different parameter dicts. A set of test
  parameters is generated from every combination of inner and outer address
  families

  The benefit of this approach is that an individually failing tests have a
  clearly separated stack trace, and one failed test doesn't prevent the rest
  from running.
  """
  param_test_names = [name for name in dir(cls) if name.startswith("ParamTest")]
  VERSIONS = (4, 6)

  # Tests all combinations of auth & crypt. Mutually exclusive with aead.
  for name, inner_version, outer_version in itertools.product(
      param_test_names, VERSIONS, VERSIONS):
    InjectSingleTest(cls, name, inner_version, outer_version)

def InjectSingleTest(cls, name, inner_version, outer_version):
  func = getattr(cls, name)

  def TestClosure(self):
    func(self, inner_version, outer_version)

  param_string = "IPv%d_in_IPv%d" % (inner_version, outer_version)
  new_name = "%s_%s" % (func.__name__.replace("ParamTest", "test"),
                        param_string)
  setattr(cls, new_name, TestClosure)


class XfrmTunnelTest(xfrm_base.XfrmBaseTest):

  def _CheckTunnelOutput(self, inner_version, outer_version, underlying_netid,
                         netid, local_inner, remote_inner, local_outer,
                         remote_outer):

    self.CreateTunnel(xfrm.XFRM_POLICY_OUT,
                      xfrm.SrcDstSelector(local_inner, remote_inner),
                      local_outer, remote_outer, _TEST_OUT_SPI,
                      xfrm_base._ALGO_CBC_AES_256, xfrm_base._ALGO_HMAC_SHA1,
                      None, underlying_netid)

    _SendPacket(self, netid, inner_version, remote_inner, 53)
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1, None,
                            local_outer, remote_outer)

  def _CheckTunnelInput(self, inner_version, outer_version, underlying_netid,
                        netid, local_inner, remote_inner, local_outer,
                        remote_outer):

    self.CreateTunnel(xfrm.XFRM_POLICY_IN,
                      xfrm.SrcDstSelector(remote_inner,
                                          local_inner), remote_outer,
                      local_outer, _TEST_IN_SPI, xfrm_base._ALGO_CRYPT_NULL,
                      xfrm_base._ALGO_AUTH_NULL, None, None)

    # Create a socket to receive packets.
    read_sock, local_port = _CreateReceiveSock(inner_version)

    # Build and receive an ESP packet destined for the inner socket
    input_pkt = _GetNullAuthCryptTunnelModePkt(
        inner_version, remote_inner, remote_outer, 4500, local_inner,
        local_outer, local_port, _TEST_IN_SPI, 1)
    self.ReceivePacketOn(underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals(remote_inner, src[0])
    self.assertEquals(4500, src[1])

  def _TestTunnel(self, inner_version, outer_version, func):
    """Test a unidirectional XFRM Tunnel with explicit selectors"""
    # Select the underlying netid, which represents the external
    # interface from/to which to route ESP packets.
    u_netid = self.RandomNetid()
    # Select a random netid that will originate traffic locally and
    # which represents the logical tunnel network.
    netid = self.RandomNetid(exclude=u_netid)

    local_inner = self.MyAddress(inner_version, netid)
    remote_inner = _GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, u_netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)

    func(inner_version, outer_version, u_netid, netid, local_inner,
         remote_inner, local_outer, remote_outer)

  def ParamTestTunnelInput(self, inner_version, outer_version):
    self._TestTunnel(inner_version, outer_version, self._CheckTunnelInput)

  def ParamTestTunnelOutput(self, inner_version, outer_version):
    self._TestTunnel(inner_version, outer_version, self._CheckTunnelOutput)


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmVtiTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmVtiTest, self).setUp()
    # If the hard-coded netids are redefined this will catch the error.
    self.assertNotIn(_VTI_NETID, self.NETIDS,
                     "VTI netid %d already in use" % _VTI_NETID)
    self.iproute = iproute.IPRoute()
    self._QuietDeleteLink(_VTI_IFNAME)

  def tearDown(self):
    super(XfrmVtiTest, self).tearDown()
    self._QuietDeleteLink(_VTI_IFNAME)

  def _QuietDeleteLink(self, ifname):
    try:
      self.iproute.DeleteLink(ifname)
    except IOError:
      # The link was not present.
      pass

  def _SwapInterfaceAddress(self, ifname, old_addr, new_addr):
    """Exchange two addresses on a given interface.

    Args:
      ifname: Name of the interface
      old_addr: An address to be removed from the interface
      new_addr: An address to be added to an interface
    """
    version = 6 if ":" in new_addr else 4
    ifindex = net_test.GetInterfaceIndex(ifname)
    self.iproute.AddAddress(new_addr,
                            net_test.AddressLengthBits(version), ifindex)
    self.iproute.DelAddress(old_addr,
                            net_test.AddressLengthBits(version), ifindex)

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface."""
    for version in [4, 6]:
      netid = self.RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=_GetRemoteOuterAddress(version),
          o_key=_TEST_OKEY,
          i_key=_TEST_IKEY)
      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface.
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _SetupVtiNetwork(self, netid, ifname, is_add):
    """Setup rules and routes for a VTI Network.

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Bring up the interface so that we can start adding addresses
      # and routes.
      net_test.SetInterfaceUp(ifname)

      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the VTI, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      self.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % ifname, 0)
    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(ifname)
      table = netid

      # Set up routing rules.
      start, end = self.UidRangeForNetid(netid)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, ifname, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, netid, table,
                              self.PRIORITY_FWMARK)
      if is_add:
        self.iproute.AddAddress(
            _GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        self.iproute.DelAddress(
            _GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
    if not is_add:
      net_test.SetInterfaceDown(ifname)

  def _CreateVti(self, netid, vti_netid, ifname, outer_version, use_null_crypt):
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)
    self.iproute.CreateVirtualTunnelInterface(
        dev_name=ifname,
        local_addr=local_outer,
        remote_addr=remote_outer,
        i_key=_TEST_IKEY,
        o_key=_TEST_OKEY)

    self._SetupVtiNetwork(vti_netid, ifname, True)

    (auth_algo, crypt_algo) = ((xfrm_base._ALGO_AUTH_NULL,
                                xfrm_base._ALGO_CRYPT_NULL)
                               if use_null_crypt else
                               (xfrm_base._ALGO_HMAC_SHA1,
                                xfrm_base._ALGO_CBC_AES_256))

    # For the VTI, the selectors are wildcard since packets will only
    # be selected if they have the appropriate mark, hence the inner
    # addresses are wildcard.
    self.CreateTunnel(xfrm.XFRM_POLICY_OUT, None, local_outer, remote_outer,
                      _TEST_OUT_SPI, crypt_algo, auth_algo,
                      xfrm.ExactMatchMark(_TEST_OKEY), netid)

    self.CreateTunnel(xfrm.XFRM_POLICY_IN, None, remote_outer, local_outer,
                      _TEST_IN_SPI, crypt_algo, auth_algo,
                      xfrm.ExactMatchMark(_TEST_IKEY), None)

<<<<<<< HEAD
  def _CheckVtiIn(self, netid, vti_netid, iface, inner_version, outer_version,
                  local_inner, remote_inner, local_outer, remote_outer, rx, tx,
                  seqNum):
    read_sock, local_port = _CreateReceiveSock(inner_version)
=======
  def _CreateReceiveSock(self, version, port=0):
    # Create a socket to receive packets.
    read_sock = socket(net_test.GetAddressFamily(version), SOCK_DGRAM, 0)
    read_sock.bind((net_test.GetWildcardAddress(version), port))
    # The second parameter of the tuple is the port number regardless of AF.
    local_port = read_sock.getsockname()[1]
    # Guard against the eventuality of the receive failing.
    csocket.SetSocketTimeout(read_sock, 100)

    return read_sock, local_port

  def _CheckVtiIn(self, netid, vti_netid, iface, inner_version, outer_version,
                  local_inner, remote_inner, local_outer, remote_outer, rx, tx,
                  spi, seqNum, expect_fail=False):
    read_sock, local_port = self._CreateReceiveSock(inner_version)
>>>>>>> 7614d6e... [WIP] VTI rekey

    input_pkt = _GetNullAuthCryptTunnelModePkt(
        inner_version, remote_inner, remote_outer, 4500, local_inner,
        local_outer, local_port, spi, seqNum)
    self.ReceivePacketOn(netid, input_pkt)

    # Verify that the packet data and src are correct
    if expect_fail:
      self.assertRaisesErrno(EAGAIN, read_sock.recv, 4096)
    else:
      data, src = read_sock.recvfrom(4096)
      self.assertEquals(net_test.UDP_PAYLOAD, data)
      self.assertEquals(remote_inner, src[0])
      self.assertEquals(4500, src[1])

    rx += 1  # Expect one extra packet
    self.assertEquals((rx, tx), self.iproute.GetRxTxPackets(iface))
    return rx, tx, seqNum + 1

<<<<<<< HEAD
  def _CheckVtiOut(self, netid, vti_netid, iface, inner_version, outer_version,
                   local_inner, remote_inner, local_outer, remote_outer, rx, tx,
                   seqNum):
    local_port = _SendPacket(self, vti_netid, inner_version, remote_inner, 4500)
=======
  def _SendPacket(self, netid, version, remote, remote_port):
    # Send a packet out via the vti-backed network, bound for the port number
    # of the input socket.
    write_sock = socket(net_test.GetAddressFamily(version), SOCK_DGRAM, 0)
    self.SelectInterface(write_sock, netid, "mark")
    write_sock.sendto(net_test.UDP_PAYLOAD, (remote, remote_port))
    local_port = write_sock.getsockname()[1]

    return local_port

  def _CheckVtiOut(self, netid, vti_netid, iface, inner_version, outer_version,
                   local_inner, remote_inner, local_outer, remote_outer, rx, tx,
                   spi, seqNum):
    local_port = self._SendPacket(vti_netid, inner_version, remote_inner, 4500)
>>>>>>> 7614d6e... [WIP] VTI rekey

    # Read a tunneled IP packet on the underlying (outbound) network
    # verifying that it is an ESP packet.
    pkt = self._ExpectEspPacketOn(netid, spi, seqNum, None,
                                  local_outer, remote_outer)

    if inner_version == 4:
      ip_hdr_options = {
        'id': scapy.IP(pkt.load[8:]).id,
        'flags': scapy.IP(pkt.load[8:]).flags
      }
    else:
      ip_hdr_options = {'fl': scapy.IPv6(pkt.load[8:]).fl}

    expected = _GetNullAuthCryptTunnelModePkt(
        inner_version, local_inner, local_outer, local_port, remote_inner,
        remote_outer, 4500, spi, seqNum, ip_hdr_options)

    # Check outer header manually (Avoids having to overwrite id, flags or flow label)
    self.assertEquals(expected.src, pkt.src)
    self.assertEquals(expected.dst, pkt.dst)
    self.assertEquals(len(expected), len(pkt))

    # Check everything else
    self.assertEquals(str(expected.load), str(pkt.load))

    tx += 1  # Expect one extra packet
    self.assertEquals((rx, tx), self.iproute.GetRxTxPackets(iface))
    return rx, tx, seqNum + 1

  def _CheckVtiEncryption(self, netid, vti_netid, iface, inner_version,
                          outer_version, local_inner, remote_inner, local_outer,
<<<<<<< HEAD
                          remote_outer, tx, rx, seqNum):
    src_port = _SendPacket(self, vti_netid, inner_version, remote_inner, 4500)
=======
                          remote_outer, tx, rx, spi, seqNum):
    src_port = self._SendPacket(vti_netid, inner_version, remote_inner, 4500)
>>>>>>> 7614d6e... [WIP] VTI rekey

    # Make sure it appeared on the underlying interface
    pkt = self._ExpectEspPacketOn(netid, spi, seqNum, None,
                            local_outer, remote_outer)

    # Check that packet is not sent in plaintext
    self.assertTrue(str(net_test.UDP_PAYLOAD) not in str(pkt))

    # Check that the interface statistics recorded the outbound packet
    tx += 1  # Expect one packet to have been sent out
    self.assertEquals((rx, tx), self.iproute.GetRxTxPackets(iface))

    try:
      # Swap the interface addresses to pretend we are the remote
      self._SwapInterfaceAddress(
          iface, new_addr=remote_inner, old_addr=local_inner)

      # Swap the packet's IP headers and write it back to the underlying
      # network.
      pkt = TunTwister.TwistPacket(pkt)
      read_sock, local_port = _CreateReceiveSock(inner_version, 4500)
      self.ReceivePacketOn(netid, pkt)

      # Verify that the packet data and src are correct
      data, src = read_sock.recvfrom(4096)
      self.assertEquals(net_test.UDP_PAYLOAD, data)
      self.assertEquals(local_inner, src[0])
      self.assertEquals(src_port, src[1])

      # Check that the interface statistics recorded the inbound packet
      rx += 1  # Expect one packet to have been received
      self.assertEquals((rx, tx), self.iproute.GetRxTxPackets(iface))
      return rx, tx, seqNum + 1
    finally:
      # Swap the interface addresses to pretend we are the remote
      self._SwapInterfaceAddress(
          iface, new_addr=local_inner, old_addr=remote_inner)

  def _TestVti(self, inner_version, outer_version, spi, func, use_null_crypt):
    """Test packet input and output over a Virtual Tunnel Interface."""
    netid = self.RandomNetid()

    local_inner = _GetLocalInnerAddress(inner_version)
    remote_inner = _GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)

    try:
      self._CreateVti(netid, _VTI_NETID, _VTI_IFNAME, outer_version,
                      use_null_crypt)
      rx, tx, nextSeqNum = func(netid, _VTI_NETID, _VTI_IFNAME, inner_version,
                                outer_version, local_inner, remote_inner,
                                local_outer, remote_outer, 0, 0, spi, 1)
      rx, tx, nextSeqNum = func(netid, _VTI_NETID, _VTI_IFNAME, inner_version,
                                outer_version, local_inner, remote_inner,
                                local_outer, remote_outer, rx, tx, spi, nextSeqNum)
    finally:
      self._SetupVtiNetwork(_VTI_NETID, _VTI_IFNAME, False)

  def ParamTestVtiInput(self, inner_version, outer_version):
    self._TestVti(inner_version, outer_version, _TEST_IN_SPI, self._CheckVtiIn, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestVti(inner_version, outer_version, _TEST_OUT_SPI, self._CheckVtiOut, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestVti(inner_version, outer_version, _TEST_OUT_SPI, self._CheckVtiEncryption, False)

  def _CheckVtiRekey(self, netid, vti_netid, iface, inner_version,
                          outer_version, local_inner, remote_inner, local_outer,
                          remote_outer, tx, rx, seqNum):
    seq_num_in, seq_num_out = 1, 1

    # Check to make sure that both directions work before rekey
    tx, rx, seq_num_in = self._CheckVtiIn(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, _TEST_IN_SPI, seq_num_in)
    tx, rx, seq_num_out = self._CheckVtiOut(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, _TEST_OUT_SPI, seq_num_out)

    #
    # Rekey
    #
    new_seq_num_in, new_seq_num_out = 1, 1
    outer_family = AF_INET if outer_version == 4 else AF_INET6

    # Create new SA
    # Distinguish the new SAs with new SPIs.
    new_out_spi = _TEST_OUT_SPI + 0x8888
    new_in_spi = _TEST_IN_SPI + 0x8888

    self.xfrm.AddSaInfo(
        local_outer, remote_outer,
        new_out_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        xfrm.ExactMatchMark(_TEST_OKEY),
        netid)

    self.xfrm.AddSaInfo(
        remote_outer, local_outer,
        new_in_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        xfrm.ExactMatchMark(_TEST_IKEY),
        None)

    # Create new policies for IPv4 and IPv6.
    for sel in [xfrm.EmptySelector(AF_INET), xfrm.EmptySelector(AF_INET6)]:
      # Add SPI-specific output policy to enforce using new outbound SPI
      policy = xfrm_base.UserPolicy(xfrm.XFRM_POLICY_OUT, sel)
      tmpl = xfrm_base.UserTemplate(outer_family, new_out_spi, 0, (local_outer, remote_outer))
      self.xfrm.UpdatePolicyInfo(policy, tmpl, xfrm.ExactMatchMark(_TEST_OKEY))

      # Add permissive input policies to allow receive path to use both the
      # old and new SPIs
      policy = xfrm_base.UserPolicy(xfrm.XFRM_POLICY_IN, sel)
      tmpl = xfrm_base.UserTemplate(outer_family, 0, 0, (remote_outer, local_outer))
      self.xfrm.UpdatePolicyInfo(policy, tmpl, xfrm.ExactMatchMark(_TEST_IKEY))

    # Expect that the old SPI still works for inbound packets
    tx, rx, seq_num_in = self._CheckVtiIn(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, _TEST_IN_SPI, seq_num_in)

    # Test both paths with new SPIs, expect outbound to use new SPI
    tx, rx, new_seq_num_in = self._CheckVtiIn(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, new_in_spi, new_seq_num_in)
    tx, rx, new_seq_num_out = self._CheckVtiOut(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, new_out_spi, new_seq_num_out)

    # Delete old SPIs
    self.xfrm.DeleteSaInfo(local_outer, _TEST_IN_SPI, IPPROTO_ESP, xfrm.ExactMatchMark(_TEST_IKEY))
    self.xfrm.DeleteSaInfo(remote_outer, _TEST_OUT_SPI, IPPROTO_ESP, xfrm.ExactMatchMark(_TEST_OKEY))

    # Test both paths with new SPIs; should still work
    tx, rx, new_seq_num_in = self._CheckVtiIn(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, new_in_spi, new_seq_num_in)
    tx, rx, new_seq_num_out = self._CheckVtiOut(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, new_out_spi, new_seq_num_out)

    # Expect failure upon trying to receive a packet with the deleted SPI
    tx, rx, seq_num_in = self._CheckVtiIn(netid, vti_netid, iface, inner_version,
                     outer_version, local_inner, remote_inner, local_outer,
                     remote_outer, tx, rx, _TEST_IN_SPI, seq_num_in)

  def ParamTestVtiRekey(self, inner_version, outer_version):
    """Test Virtual Tunnel Interface rekey."""
    netid = self.RandomNetid()

    local_inner = _GetLocalInnerAddress(inner_version)
    remote_inner = _GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)

    try:
      self._CreateVti(netid, _VTI_NETID, _VTI_IFNAME, outer_version,
                      True)
      self._CheckVtiRekey(netid, _VTI_NETID, _VTI_IFNAME, inner_version,
                                outer_version, local_inner, remote_inner,
                                local_outer, remote_outer, 0, 0, 1)
    finally:
      self._SetupVtiNetwork(_VTI_NETID, _VTI_IFNAME, False)

if __name__ == "__main__":
  InjectParameterizedTests(XfrmTunnelTest)
  InjectParameterizedTests(XfrmVtiTest)
  unittest.main()
