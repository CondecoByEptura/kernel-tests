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

import random
import itertools
import struct
import unittest

from scapy import all as scapy
from tun_twister import TunTwister
import csocket
import iproute
import multinetwork_base
import net_test
import packets
import xfrm
import xfrm_base

# Parameters to Set up VTI as a special network
_VTI_NETID = 50
_VTI_IFNAME = "test_vti"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI

_TEST_OKEY = 2000000100
_TEST_IKEY = 2000000200

_TEST_REMOTE_PORT = 4500


def _GetLocalInnerAddress(version):
  return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]


def _GetRemoteInnerAddress(version):
  return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]


def _GetRemoteOuterAddress(version):
  return {4: net_test.IPV4_ADDR, 6: net_test.IPV6_ADDR}[version]

def _GetNullAuthCryptTunnelModePkt(inner_version, src_inner, src_outer,
                                   src_port, dst_inner, dst_outer,
                                   dst_port, spi, seq_num, ip_hdr_options={}):
  ip_hdr_options.update({'src': src_inner, 'dst': dst_inner})

  # Build and receive an ESP packet destined for the inner socket
  IpType = {4: scapy.IP, 6: scapy.IPv6}[inner_version]
  input_pkt = (
      IpType(**ip_hdr_options) / scapy.UDP(sport=src_port, dport=dst_port) /
      net_test.UDP_PAYLOAD)
  input_pkt = IpType(str(input_pkt))  # Compute length, checksum.
  input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, spi, seq_num,
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


class XfrmTunnelTest(xfrm_base.XfrmLazyTest):

  def _CheckTunnelOutput(self, inner_version, outer_version, underlying_netid,
                         netid, local_inner, remote_inner, local_outer,
                         remote_outer):

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT,
                           xfrm.SrcDstSelector(local_inner, remote_inner),
                           local_outer, remote_outer, _TEST_OUT_SPI,
                           xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1,
                           None, underlying_netid)

    _SendPacket(self, netid, inner_version, remote_inner, 53)
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1, None,
                            local_outer, remote_outer)

  def _CheckTunnelInput(self, inner_version, outer_version, underlying_netid,
                        netid, local_inner, remote_inner, local_outer,
                        remote_outer):

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN,
                           xfrm.SrcDstSelector(remote_inner, local_inner),
                           remote_outer, local_outer, _TEST_IN_SPI,
                           xfrm_base._ALGO_CRYPT_NULL,
                           xfrm_base._ALGO_AUTH_NULL, None, None)

    # Create a socket to receive packets.
    read_sock, local_port = _CreateReceiveSock(inner_version)

    # Build and receive an ESP packet destined for the inner socket
    input_pkt = _GetNullAuthCryptTunnelModePkt(
        inner_version, remote_inner, remote_outer, _TEST_REMOTE_PORT,
        local_inner, local_outer, local_port, _TEST_IN_SPI, 1)
    self.ReceivePacketOn(underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals(remote_inner, src[0])
    self.assertEquals(_TEST_REMOTE_PORT, src[1])

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


class VtiInterface(object):

  def __init__(self, iface, netid, underlying_netid, local, remote, version,
               use_null_crypt):
    self.iface = iface
    self.netid = netid
    self.underlying_netid = underlying_netid
    self.local, self.remote = local, remote
    self.version = version
    self.rx = self.tx = 0
    self.ikey = _TEST_IKEY + netid
    self.okey = _TEST_OKEY + netid
    self.out_spi = self.in_spi = random.randint(0, 0x7fffffff)

    self.iproute = iproute.IPRoute()
    self.xfrm = xfrm.Xfrm()

    self.SetupInterface()
    self.SetupXfrm(use_null_crypt)
    self.addrs = {}

  def Teardown(self):
    self.TeardownInterface()

  def SetupInterface(self):
    self.iproute.CreateVirtualTunnelInterface(
        self.iface, self.local, self.remote, self.ikey, self.okey)

  def TeardownInterface(self):
    self.iproute.DeleteLink(self.iface)

  def SetupXfrm(self, use_null_crypt):
    # Select algorithms:
    (auth_algo, crypt_algo) = ((xfrm_base._ALGO_AUTH_NULL,
                                xfrm_base._ALGO_CRYPT_NULL)
                               if use_null_crypt else
                               (xfrm_base._ALGO_HMAC_SHA1,
                                xfrm_base._ALGO_CBC_AES_256))

    # For the VTI, the selectors are wildcard since packets will only
    # be selected if they have the appropriate mark, hence the inner
    # addresses are wildcard.
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT, None, self.local, self.remote,
                           self.out_spi, crypt_algo, auth_algo,
                           xfrm.ExactMatchMark(self.okey),
                           self.underlying_netid)

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN, None, self.remote, self.local,
                           self.in_spi, crypt_algo, auth_algo,
                           xfrm.ExactMatchMark(self.ikey), None)


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmVtiTest(xfrm_base.XfrmLazyTest):

  @classmethod
  def setUpClass(cls):
    xfrm_base.XfrmBaseTest.setUpClass()
    # VTI interfaces use marks extensively, so configure realistic packet
    # marking rules to make the test representative.
    cls.SetInboundMarks(True)
    cls._SetInboundMarking(_VTI_NETID, _VTI_IFNAME, True)
    cls.SetMarkReflectSysctls(1)

  @classmethod
  def tearDownClass(cls):
    # The sysctls are restored by MultinetworkBaseTest.tearDownClass.
    cls._SetInboundMarking(_VTI_NETID, _VTI_IFNAME, False)
    cls.SetInboundMarks(False)
    xfrm_base.XfrmBaseTest.tearDownClass()

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

  def _SetupVtiNetwork(self, vti, is_add):
    """Setup rules and routes for a VTI Network.

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      netid: The netid of the VTI.
      ifname: The name of the VTI interface.
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the VTI, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      self.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % vti.iface, 0)
      net_test.SetInterfaceUp(vti.iface)

    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(vti.iface)
      table = vti.netid

      # Set up routing rules.
      start, end = self.UidRangeForNetid(vti.netid)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, vti.iface, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, vti.netid, table,
                              self.PRIORITY_FWMARK)

      # Configure IP addresses.
      if version == 4:
        addr = self._MyIPv4Address(vti.netid)
      else:
        addr = self.OnlinkPrefix(6, vti.netid) + "1"
      prefixlen = net_test.AddressLengthBits(version)
      vti.addrs[version] = addr
      if is_add:
        self.iproute.AddAddress(addr, prefixlen, ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        self.iproute.DelAddress(addr, prefixlen, ifindex)

  def assertReceivedPacket(self, vti):
    vti.rx += 1
    self.assertEquals((vti.rx, vti.tx), self.iproute.GetRxTxPackets(vti.iface))

  def assertSentPacket(self, vti):
    vti.tx += 1
    self.assertEquals((vti.rx, vti.tx), self.iproute.GetRxTxPackets(vti.iface))

  def _CreateVti(self, netid, vti_netid, ifname, outer_version, use_null_crypt):
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)
    vti = VtiInterface(ifname, vti_netid, netid, local_outer, remote_outer,
                       outer_version, use_null_crypt)
    self._SetupVtiNetwork(vti, True)
    return vti


  def _CheckVtiInput(self, vti, inner_version, local_inner, remote_inner,
                     seq_num):
    read_sock, local_port = _CreateReceiveSock(inner_version)

    input_pkt = _GetNullAuthCryptTunnelModePkt(
        inner_version, remote_inner, vti.remote, _TEST_REMOTE_PORT, local_inner,
        vti.local, local_port, vti.in_spi, seq_num)
    self.ReceivePacketOn(vti.underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals(remote_inner, src[0])
    self.assertEquals(_TEST_REMOTE_PORT, src[1])

    self.assertReceivedPacket(vti)
    return seq_num + 1

  def _CheckVtiOutput(self, vti, inner_version, local_inner, remote_inner,
                      seq_num):
    local_port = _SendPacket(self, vti.netid, inner_version, remote_inner,
                             _TEST_REMOTE_PORT)

    # Read a tunneled IP packet on the underlying (outbound) network
    # verifying that it is an ESP packet.
    pkt = self._ExpectEspPacketOn(vti.underlying_netid, vti.out_spi, seq_num,
                                  None, vti.local, vti.remote)

    if inner_version == 4:
      ip_hdr_options = {
        'id': scapy.IP(pkt.load[8:]).id,
        'flags': scapy.IP(pkt.load[8:]).flags
      }
    else:
      ip_hdr_options = {'fl': scapy.IPv6(pkt.load[8:]).fl}

    expected = _GetNullAuthCryptTunnelModePkt(
        inner_version, local_inner, vti.local, local_port, remote_inner,
        vti.remote, _TEST_REMOTE_PORT, vti.out_spi, seq_num, ip_hdr_options)

    # Check outer header manually (Avoids having to overwrite outer header's
    # id, flags or flow label)
    self.assertEquals(expected.src, pkt.src)
    self.assertEquals(expected.dst, pkt.dst)
    self.assertEquals(len(expected), len(pkt))

    # Check everything else
    self.assertEquals(str(expected.load), str(pkt.load))

    self.assertSentPacket(vti)
    return seq_num + 1

  def _CheckVtiEncryption(self, vti, inner_version, local_inner, remote_inner,
                          seq_num):
    src_port = _SendPacket(self, vti.netid, inner_version, remote_inner,
                           _TEST_REMOTE_PORT)

    # Make sure it appeared on the underlying interface
    pkt = self._ExpectEspPacketOn(vti.underlying_netid, vti.out_spi, seq_num,
                                  None, vti.local, vti.remote)

    # Check that packet is not sent in plaintext
    self.assertTrue(str(net_test.UDP_PAYLOAD) not in str(pkt))

    # Check that the interface statistics recorded the outbound packet
    self.assertSentPacket(vti)

    try:
      # Swap the interface addresses to pretend we are the remote
      # remote = _GetRemoteInnerAddress(inner_version)
      # local = vti.addrs[inner_version]
      self._SwapInterfaceAddress(
          vti.iface, new_addr=remote_inner, old_addr=local_inner)

      # Swap the packet's IP headers and write it back to the underlying
      # network.
      pkt = TunTwister.TwistPacket(pkt)
      read_sock, local_port = _CreateReceiveSock(inner_version,
                                                 _TEST_REMOTE_PORT)
      self.ReceivePacketOn(vti.underlying_netid, pkt)

      # Verify that the packet data and src are correct
      data, src = read_sock.recvfrom(4096)
      self.assertEquals(net_test.UDP_PAYLOAD, data)
      self.assertEquals(local_inner, src[0])
      self.assertEquals(src_port, src[1])

      # Check that the interface statistics recorded the inbound packet
      self.assertReceivedPacket(vti)
      return seq_num + 1
    finally:
      # Swap the interface addresses to pretend we are the remote
      self._SwapInterfaceAddress(
          vti.iface, new_addr=local_inner, old_addr=remote_inner)

  def _CheckVtiIcmp(self, vti, inner_version, local_inner, remote_inner,
                      seq_num):
    # Now attempt to provoke an ICMP error.
    # TODO: deduplicate with multinetwork_test.py.
    dst_prefix, intermediate = {
        4: ("172.19.", "172.16.9.12"),
        6: ("2001:db8::", "2001:db8::1")
    }[vti.version]

    local_port = _SendPacket(self, vti.netid, inner_version, remote_inner,
                             _TEST_REMOTE_PORT)
    self.assertSentPacket(vti)
    pkt = self._ExpectEspPacketOn(vti.underlying_netid, vti.out_spi, vti.tx,
                                  None, vti.local, vti.remote)
    myaddr = self.MyAddress(vti.version, vti.underlying_netid)
    _, toobig = packets.ICMPPacketTooBig(vti.version, intermediate, myaddr, pkt)
    self.ReceivePacketOn(vti.underlying_netid, toobig)

    # Check that the packet too big reduced the MTU.
    routes = self.iproute.GetRoutes(vti.remote, 0, vti.underlying_netid, None)
    self.assertEquals(1, len(routes))
    rtmsg, attributes = routes[0]
    self.assertEquals(iproute.RTN_UNICAST, rtmsg.type)
    self.assertEquals(1280, attributes["RTA_METRICS"]["RTAX_MTU"])

    # Clear PMTU information so that future tests don't have to worry about it.
    self.InvalidateDstCache(vti.version, vti.underlying_netid)

    return seq_num + 1

  def _TestVti(self, vti_netid, vti_ifname, inner_version, outer_version, func,
               use_null_crypt):
    """Test packet input and output over a Virtual Tunnel Interface."""
    netid = self.RandomNetid()

    try:
      vti = self._CreateVti(netid, _VTI_NETID, _VTI_IFNAME, outer_version,
                            use_null_crypt)

      local_inner = vti.addrs[inner_version]
      remote_inner = _GetRemoteInnerAddress(inner_version)

      next_seq_num = func(vti, inner_version, local_inner, remote_inner, 1)
      next_seq_num = func(vti, inner_version, local_inner, remote_inner,
                                  next_seq_num)
    finally:
      self._SetupVtiNetwork(vti, False)

  def ParamTestVtiInput(self, inner_version, outer_version):
    self._TestVti(_VTI_NETID, _VTI_IFNAME, inner_version, outer_version,
                  self._CheckVtiInput, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestVti(_VTI_NETID, _VTI_IFNAME, inner_version, outer_version,
                  self._CheckVtiOutput, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestVti(_VTI_NETID, _VTI_IFNAME, inner_version, outer_version,
                  self._CheckVtiEncryption, False)

  def ParamTestVtiIcmp(self, inner_version, outer_version):
    self._TestVti(_VTI_NETID, _VTI_IFNAME, inner_version, outer_version,
                  self._CheckVtiIcmp, False)


if __name__ == "__main__":
  InjectParameterizedTests(XfrmTunnelTest)
  InjectParameterizedTests(XfrmVtiTest)
  unittest.main()
