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

_LOOPBACK_IFINDEX = 1
_TEST_XFRM_IFNAME = "ipsec42"
_TEST_XFRM_NETID = 42

# Does the kernel support xfrmi interfaces?
def HaveXfrmInterfaces():
  try:
    i = iproute.IPRoute()
    i.CreateXfrmInterface(_TEST_XFRM_IFNAME, _TEST_XFRM_NETID,
                          _LOOPBACK_IFINDEX)
    i.DeleteLink(_TEST_XFRM_IFNAME)
    try:
      i.GetIfIndex(_TEST_XFRM_IFNAME)
      assert "Interface should not exist!!1"
    except IOError:
      pass
    return True
  except IOError:
    return False

HAVE_XFRM_INTERFACES = HaveXfrmInterfaces()

# Parameters to Set up VTI as a special network
_BASE_TUNNEL_INTF_NETID = {4: 40, 6: 60}
_BASE_VTI_OKEY = 2000000100
_BASE_VTI_IKEY = 2000000200

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI

_TEST_OKEY = 2000000100
_TEST_IKEY = 2000000200

_TEST_REMOTE_PORT = 1234


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
  # Send a packet out via the tunnel-backed network, bound for the port number
  # of the input socket.
  write_sock = socket(net_test.GetAddressFamily(version), SOCK_DGRAM, 0)
  testInstance.SelectInterface(write_sock, netid, "mark")
  write_sock.sendto(net_test.UDP_PAYLOAD, (remote, remote_port))
  local_port = write_sock.getsockname()[1]

  return local_port


def InjectTests():
  InjectParameterizedTests(XfrmTunnelTest)
  InjectParameterizedTests(XfrmInterfaceTest)
  InjectParameterizedTests(XfrmVtiTest)


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
                           None, underlying_netid, None)

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
                           xfrm_base._ALGO_AUTH_NULL, None, None, None)

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
    self.assertEquals((remote_inner, _TEST_REMOTE_PORT), src[:2])

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
class XfrmAddDeleteVtiTest(xfrm_base.XfrmBaseTest):
  def verifyVtiInfoData(self, vti_info_data, version, local_addr, remote_addr, ikey, okey):
    self.assertEquals(vti_info_data["IFLA_VTI_IKEY"], ikey)
    self.assertEquals(vti_info_data["IFLA_VTI_OKEY"], okey)

    family = AF_INET if version == 4 else AF_INET6
    self.assertEquals(inet_ntop(family, vti_info_data["IFLA_VTI_LOCAL"]), local_addr)
    self.assertEquals(inet_ntop(family, vti_info_data["IFLA_VTI_REMOTE"]), remote_addr)

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface."""
    for version in [4, 6]:
      netid = self.RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_TEST_XFRM_IFNAME,
          local_addr=local_addr,
          remote_addr=_GetRemoteOuterAddress(version),
          o_key=_TEST_OKEY,
          i_key=_TEST_IKEY)
<<<<<<< HEAD
      self.verifyVtiInfoData(self.iproute.GetVtiInfoData(_TEST_XFRM_IFNAME),
                             version, local_addr, _GetRemoteOuterAddress(version),
                             _TEST_IKEY, _TEST_OKEY)
=======
      self.verifyVtiInfoData(
          self.iproute.GetVtiInfoData(_TEST_XFRM_IFNAME), version, local_addr,
          _GetRemoteOuterAddress(version), _TEST_IKEY, _TEST_OKEY)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

      new_remote_addr = {4: net_test.IPV4_ADDR2, 6: net_test.IPV6_ADDR2}
      new_okey = _TEST_OKEY + _TEST_XFRM_NETID
      new_ikey = _TEST_IKEY + _TEST_XFRM_NETID
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_TEST_XFRM_IFNAME,
          local_addr=local_addr,
          remote_addr=new_remote_addr[version],
          o_key=new_okey,
          i_key=new_ikey,
          is_update=True)

<<<<<<< HEAD
      self.verifyVtiInfoData(self.iproute.GetVtiInfoData(_TEST_XFRM_IFNAME),
                             version, local_addr, new_remote_addr[version],
                             new_ikey, new_okey)
=======
      self.verifyVtiInfoData(
          self.iproute.GetVtiInfoData(_TEST_XFRM_IFNAME), version, local_addr,
          new_remote_addr[version], new_ikey, new_okey)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

      if_index = self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)

      # Validate that the netlink interface matches the ioctl interface.
      self.assertEquals(net_test.GetInterfaceIndex(_TEST_XFRM_IFNAME), if_index)
      self.iproute.DeleteLink(_TEST_XFRM_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)

  def _QuietDeleteLink(self, ifname):
    try:
      self.iproute.DeleteLink(ifname)
    except IOError:
      # The link was not present.
      pass

  def tearDown(self):
    super(XfrmAddDeleteVtiTest, self).tearDown()
    self._QuietDeleteLink(_TEST_XFRM_IFNAME)


class VtiInterface(object):

  def __init__(self, iface, netid, underlying_netid, _, local, remote, version):
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
    # Default to use crypt; tests that want to use null_crypt should re-setup
    self.SetupXfrm(False)
    self.addrs = {}

  def Teardown(self):
    self.TeardownXfrm()
    self.TeardownInterface()

  def SetupInterface(self):
    return self.iproute.CreateVirtualTunnelInterface(
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
                           self.underlying_netid, None)

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN, None, self.remote, self.local,
                           self.in_spi, crypt_algo, auth_algo,
<<<<<<< HEAD
                           xfrm.ExactMatchMark(self.ikey), None, None)
=======
                           xfrm.ExactMatchMark(self.ikey), None, None, "mark")
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

  def TeardownXfrm(self):
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_OUT, None, self.remote,
                           self.out_spi, self.okey, None)
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_IN, None, self.local,
                           self.in_spi, self.ikey, None)

  def Rekey(self, outer_family, new_out_spi, new_in_spi):
    self.xfrm.AddSaInfo(
        self.local, self.remote,
        new_out_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        xfrm.ExactMatchMark(self.okey),
        self.underlying_netid)

    self.xfrm.AddSaInfo(
        self.remote, self.local,
        new_in_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        xfrm.ExactMatchMark(self.ikey),
        None)

    # Create new policies for IPv4 and IPv6.
    for sel in [xfrm.EmptySelector(AF_INET), xfrm.EmptySelector(AF_INET6)]:
      # Add SPI-specific output policy to enforce using new outbound SPI
      policy = xfrm.UserPolicy(xfrm.XFRM_POLICY_OUT, sel)
      tmpl = xfrm.UserTemplate(outer_family, new_out_spi, 0,
                                    (self.local, self.remote))
      self.xfrm.UpdatePolicyInfo(policy, tmpl, xfrm.ExactMatchMark(self.okey),
                                 0)

  def DeleteOldSaInfo(self, outer_family, old_in_spi, old_out_spi):
    self.xfrm.DeleteSaInfo(self.local, old_in_spi, IPPROTO_ESP,
                           xfrm.ExactMatchMark(self.ikey))
    self.xfrm.DeleteSaInfo(self.remote, old_out_spi, IPPROTO_ESP,
                           xfrm.ExactMatchMark(self.okey))


@unittest.skipUnless(HAVE_XFRM_INTERFACES, "XFRM interfaces unsupported")
class XfrmAddDeleteXfrmInterfaceTest(xfrm_base.XfrmBaseTest):
  """Test the creation of an XFRM Interface."""

  def testAddXfrmInterface(self):
    self.iproute.CreateXfrmInterface(_TEST_XFRM_IFNAME, _TEST_XFRM_NETID,
                                     _LOOPBACK_IFINDEX)
    if_index = self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)
    net_test.SetInterfaceUp(_TEST_XFRM_IFNAME)

    # Validate that the netlink interface matches the ioctl interface.
    self.assertEquals(net_test.GetInterfaceIndex(_TEST_XFRM_IFNAME), if_index)
    self.iproute.DeleteLink(_TEST_XFRM_IFNAME)
    with self.assertRaises(IOError):
      self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)


class XfrmInterface(object):

  def __init__(self, iface, netid, underlying_netid, ifindex, local, remote,
               version):
    self.iface = iface
    self.netid = netid
    self.underlying_netid = underlying_netid
    self.ifindex = ifindex
    self.local, self.remote = local, remote
    self.version = version
    self.rx = self.tx = 0
    self.xfrm_if_id = netid
    self.out_spi = self.in_spi = random.randint(0, 0x7fffffff)
    self.xfrm_if_id = self.netid

    self.iproute = iproute.IPRoute()
    self.xfrm = xfrm.Xfrm()

    self.SetupInterface()
    self.SetupXfrm(False)
    self.addrs = {}

  def Teardown(self):
    self.TeardownXfrm()
    self.TeardownInterface()

  def SetupInterface(self):
    """Create an XFRM interface."""
    return self.iproute.CreateXfrmInterface(self.iface, self.netid, self.ifindex)

  def TeardownInterface(self):
    self.iproute.DeleteLink(self.iface)

  def SetupXfrm(self, use_null_crypt):
    # Select algorithms:
    (auth_algo, crypt_algo) = ((xfrm_base._ALGO_AUTH_NULL,
                                xfrm_base._ALGO_CRYPT_NULL)
                               if use_null_crypt else
                               (xfrm_base._ALGO_HMAC_SHA1,
                                xfrm_base._ALGO_CBC_AES_256))

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT, None, self.local, self.remote,
                           self.out_spi, crypt_algo, auth_algo, None,
                           self.underlying_netid, self.xfrm_if_id)
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN, None, self.remote, self.local,
                           self.in_spi, crypt_algo, auth_algo, None, None,
<<<<<<< HEAD
                           self.xfrm_if_id)
=======
                           self.xfrm_if_id, "ifid")
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption


  def TeardownXfrm(self):
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_OUT, None, self.remote,
                           self.out_spi, None, self.xfrm_if_id)
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_IN, None, self.local,
                           self.in_spi, None, self.xfrm_if_id)

  def Rekey(self, outer_family, new_out_spi, new_in_spi):
    self.xfrm.AddSaInfo(
        self.local, self.remote,
        new_out_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        None,
        self.underlying_netid,
        xfrm_if_id=self.xfrm_if_id)

    self.xfrm.AddSaInfo(
        self.remote, self.local,
        new_in_spi, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CRYPT_NULL,
        xfrm_base._ALGO_AUTH_NULL,
        None,
        None,
        None,
        None,
        xfrm_if_id=self.xfrm_if_id)

    # Create new policies for IPv4 and IPv6.
    for sel in [xfrm.EmptySelector(AF_INET), xfrm.EmptySelector(AF_INET6)]:
      # Add SPI-specific output policy to enforce using new outbound SPI
      policy = xfrm.UserPolicy(xfrm.XFRM_POLICY_OUT, sel)
      tmpl = xfrm.UserTemplate(outer_family, new_out_spi, 0,
                                    (self.local, self.remote))
      self.xfrm.UpdatePolicyInfo(policy, tmpl, None, self.xfrm_if_id)

  def DeleteOldSaInfo(self, outer_family, old_in_spi, old_out_spi):
    self.xfrm.DeleteSaInfo(self.local, old_in_spi, IPPROTO_ESP, None,
                           self.xfrm_if_id)
    self.xfrm.DeleteSaInfo(self.remote, old_out_spi, IPPROTO_ESP, None,
                           self.xfrm_if_id)


class XfrmTunnelBase(xfrm_base.XfrmBaseTest):

  @classmethod
  def setUpClass(cls):
    xfrm_base.XfrmBaseTest.setUpClass()
    # Tunnel interfaces use marks extensively, so configure realistic packet
    # marking rules to make the test representative, make PMTUD work, etc.
    cls.SetInboundMarks(True)
    cls.SetMarkReflectSysctls(1)

    cls.tunnelIntfs = {}
    cls.tunnelIntf6s = {}
    for i, underlying_netid in enumerate(cls.tuns):
      for version in 4, 6:
        netid = _BASE_TUNNEL_INTF_NETID[version] + i
        iface = "ipsec%s" % netid
        local = cls.MyAddress(version, underlying_netid)
        if version == 4:
          remote, null_crypt_remote = \
              (net_test.IPV4_ADDR, net_test.IPV4_ADDR2) if (i % 2) else \
              (net_test.IPV4_ADDR2, net_test.IPV4_ADDR)
        else:
          remote, null_crypt_remote = \
              (net_test.IPV6_ADDR, net_test.IPV6_ADDR2) if (i % 2) else \
              (net_test.IPV6_ADDR2, net_test.IPV6_ADDR)

        ifindex = cls.ifindices[underlying_netid]
        intf = cls.INTERFACE_CLASS(iface, netid, underlying_netid, ifindex,
                                   local, remote, version)
        cls._SetInboundMarking(netid, iface, True)
        cls._SetupTunnelIntfNetwork(intf, True)

        if version == 4:
          cls.tunnelIntfs[netid] = intf
        else:
          cls.tunnelIntf6s[netid] = intf

  @classmethod
  def tearDownClass(cls):
    # The sysctls are restored by MultinetworkBaseTest.tearDownClass.
    cls.SetInboundMarks(False)
    for intf in cls.tunnelIntfs.values() + cls.tunnelIntf6s.values():
      cls._SetInboundMarking(intf.netid, intf.iface, False)
      cls._SetupTunnelIntfNetwork(intf, False)
      intf.Teardown()
    xfrm_base.XfrmBaseTest.tearDownClass()

  def randomTunnelIntf(self, outer_version):
    version_dict = self.__class__.tunnelIntfs if outer_version == 4 else self.__class__.tunnelIntf6s
    return random.choice(version_dict.values())

  def setUp(self):
    multinetwork_base.MultiNetworkBaseTest.setUp(self)
    self.iproute = iproute.IPRoute()
    self.xfrm = xfrm.Xfrm()

  def tearDown(self):
    multinetwork_base.MultiNetworkBaseTest.tearDown(self)

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

  @classmethod
  def _SetupTunnelIntfNetwork(cls, intf, is_add):
    """Setup rules and routes for a Tunnel Interface (VTI or XFRM-I).

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for an interface to behave like an Android
    Network for purposes of testing.

    Args:
      intf: A VtiInterface or XfrmInterface, the interface to set up.
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the Interface, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      cls.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % intf.iface, 0)
      net_test.SetInterfaceUp(intf.iface)

    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(intf.iface)
      table = intf.netid

      # Set up routing rules.
      start, end = cls.UidRangeForNetid(intf.netid)
      cls.iproute.UidRangeRule(version, is_add, start, end, table,
                                cls.PRIORITY_UID)
      cls.iproute.OifRule(version, is_add, intf.iface, table, cls.PRIORITY_OIF)
      cls.iproute.FwmarkRule(version, is_add, intf.netid, cls.NETID_FWMASK,
                              table, cls.PRIORITY_FWMARK)

      # Configure IP addresses.
      if version == 4:
        addr = cls._MyIPv4Address(intf.netid)
      else:
        addr = cls.OnlinkPrefix(6, intf.netid) + "1"
      prefixlen = net_test.AddressLengthBits(version)
      intf.addrs[version] = addr
      if is_add:
        cls.iproute.AddAddress(addr, prefixlen, ifindex)
        cls.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        cls.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        cls.iproute.DelAddress(addr, prefixlen, ifindex)

  def assertReceivedPacket(self, intf):
    intf.rx += 1
    self.assertEquals((intf.rx, intf.tx), self.iproute.GetRxTxPackets(
        intf.iface))

  def assertSentPacket(self, intf):
    intf.tx += 1
    self.assertEquals((intf.rx, intf.tx), self.iproute.GetRxTxPackets(
        intf.iface))

  def ParamTestNonIpsecInput(self, inner_version, outer_version):
    netid = self.RandomNetid()
    local_addr = self.MyAddress(inner_version, netid)
    remote_addr = self.GetRemoteSocketAddress(inner_version)

    read_sock = net_test.UDPSocket(net_test.GetAddressFamily(inner_version))
    read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
    local_port = read_sock.getsockname()[1]
    # Guard against the eventuality of the receive failing.
    net_test.SetNonBlocking(read_sock.fileno())

    IpType = {4: scapy.IP, 6: scapy.IPv6}[inner_version]
    input_pkt = (IpType(src=remote_addr, dst=local_addr) /
                scapy.UDP(sport=_TEST_REMOTE_PORT, dport=local_port) / net_test.UDP_PAYLOAD)
    self.ReceivePacketOn(netid, input_pkt)

    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals((remote_addr, _TEST_REMOTE_PORT), src[:2])

  def ParamTestNonIpsecOutputConnected(self, inner_version, outer_version):
    netid = self.RandomNetid()
    local_addr = self.MyAddress(inner_version, netid)
    remote_addr = self.GetRemoteSocketAddress(inner_version)

    local_port = _SendPacket(self, netid, inner_version, remote_addr,
                             _TEST_REMOTE_PORT)

    packets = self.ReadAllPacketsOn(netid)
    self.assertEquals(1, len(packets))
    packet = packets[0]
    self.assertEquals(remote_addr, packet.dst)
    self.assertEquals(local_addr, packet.src)
    self.assertEquals(net_test.UDP_PAYLOAD, packet.load)

  def ParamTestNonIpsecOutputUnconnected(self, inner_version, outer_version):
    netid = self.RandomNetid()
    local_addr = self.MyAddress(inner_version, netid)
    remote_addr = self.GetRemoteSocketAddress(inner_version)

    try:
      self.__class__.SetDefaultNetwork(netid)

      write_sock = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      write_sock.sendto(net_test.UDP_PAYLOAD, (remote_addr, _TEST_REMOTE_PORT))

      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      packet = packets[0]
      self.assertEquals(remote_addr, packet.dst)
      self.assertEquals(local_addr, packet.src)
      self.assertEquals(net_test.UDP_PAYLOAD, packet.load)
    finally:
      self.__class__.ClearDefaultNetwork()

  def _CheckIntfInput(self, intf, inner_version, local_inner, remote_inner,
<<<<<<< HEAD
                     seq_num):
=======
                      spi, seq_num, expect_fail=False):
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    read_sock, local_port = _CreateReceiveSock(inner_version)

    input_pkt = _GetNullAuthCryptTunnelModePkt(
        inner_version, remote_inner, intf.remote, _TEST_REMOTE_PORT,
<<<<<<< HEAD
        local_inner, intf.local, local_port, intf.in_spi, seq_num)
    self.ReceivePacketOn(intf.underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    self.assertReceivedPacket(intf)
    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals((remote_inner, _TEST_REMOTE_PORT), src[:2])
=======
        local_inner, intf.local, local_port, spi, seq_num)
    self.ReceivePacketOn(intf.underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    if expect_fail:
      self.assertRaisesErrno(EAGAIN, read_sock.recv, 4096)
    else:
      self.assertReceivedPacket(intf)
      data, src = read_sock.recvfrom(4096)
      self.assertEquals(net_test.UDP_PAYLOAD, data)
      self.assertEquals((remote_inner, _TEST_REMOTE_PORT), src[:2])
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

    return seq_num + 1

  def _CheckIntfOutput(self, intf, inner_version, local_inner, remote_inner,
<<<<<<< HEAD
                      seq_num):
=======
                       spi, seq_num):
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    local_port = _SendPacket(self, intf.netid, inner_version, remote_inner,
                             _TEST_REMOTE_PORT)

    # Read a tunneled IP packet on the underlying (outbound) network
    # verifying that it is an ESP packet.
<<<<<<< HEAD
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, intf.out_spi, seq_num,
                                  None, intf.local, intf.remote)
=======
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, spi, seq_num, None,
                                  intf.local, intf.remote)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    self.assertSentPacket(intf)

    if inner_version == 4:
      ip_hdr_options = {
        'id': scapy.IP(str(pkt.payload)[8:]).id,
        'flags': scapy.IP(str(pkt.payload)[8:]).flags
      }
    else:
      ip_hdr_options = {'fl': scapy.IPv6(str(pkt.payload)[8:]).fl}

    expected = _GetNullAuthCryptTunnelModePkt(
        inner_version, local_inner, intf.local, local_port, remote_inner,
<<<<<<< HEAD
        intf.remote, _TEST_REMOTE_PORT, intf.out_spi, seq_num, ip_hdr_options)
=======
        intf.remote, _TEST_REMOTE_PORT, spi, seq_num, ip_hdr_options)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

    # Check outer header manually (Avoids having to overwrite outer header's
    # id, flags or flow label)
    self.assertEquals(expected.src, pkt.src)
    self.assertEquals(expected.dst, pkt.dst)
    self.assertEquals(len(expected), len(pkt))

    # Check everything else
    self.assertEquals(str(expected.payload), str(pkt.payload))

    return seq_num + 1

  def _CheckIntfEncryption(self, intf, inner_version, local_inner, remote_inner,
<<<<<<< HEAD
                          seq_num):
=======
                           spi, seq_num):
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    src_port = _SendPacket(self, intf.netid, inner_version, remote_inner,
                           _TEST_REMOTE_PORT)

    # Make sure it appeared on the underlying interface
<<<<<<< HEAD
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, intf.out_spi, seq_num,
                                  None, intf.local, intf.remote)
=======
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, spi, seq_num, None,
                                  intf.local, intf.remote)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

    # Check that packet is not sent in plaintext
    self.assertTrue(str(net_test.UDP_PAYLOAD) not in str(pkt))

    # Check that the interface statistics recorded the outbound packet
    self.assertSentPacket(intf)

    try:
      # Swap the interface addresses to pretend we are the remote
      # remote = _GetRemoteInnerAddress(inner_version)
      # local = intf.addrs[inner_version]
      self._SwapInterfaceAddress(
          intf.iface, new_addr=remote_inner, old_addr=local_inner)

      # Swap the packet's IP headers and write it back to the underlying
      # network.
      pkt = TunTwister.TwistPacket(pkt)
      read_sock, local_port = _CreateReceiveSock(inner_version,
                                                 _TEST_REMOTE_PORT)
      self.ReceivePacketOn(intf.underlying_netid, pkt)

      # Verify that the packet data and src are correct
      data, src = read_sock.recvfrom(4096)
      self.assertEquals(net_test.UDP_PAYLOAD, data)
      self.assertEquals((local_inner, src_port), src[:2])

      # Check that the interface statistics recorded the inbound packet
      self.assertReceivedPacket(intf)
      return seq_num + 1
    finally:
      # Swap the interface addresses to pretend we are the remote
      self._SwapInterfaceAddress(
          intf.iface, new_addr=local_inner, old_addr=remote_inner)

<<<<<<< HEAD
  def _CheckIntfIcmp(self, intf, inner_version, local_inner, remote_inner,
                    seq_num):
=======
  def _CheckIntfIcmp(self, intf, inner_version, local_inner, remote_inner, spi,
                     seq_num):
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    # Now attempt to provoke an ICMP error.
    # TODO: deduplicate with multinetwork_test.py.
    dst_prefix, intermediate = {
        4: ("172.19.", "172.16.9.12"),
        6: ("2001:db8::", "2001:db8::1")
    }[intf.version]
<<<<<<< HEAD

    local_port = _SendPacket(self, intf.netid, inner_version, remote_inner,
                             _TEST_REMOTE_PORT)
    self.assertSentPacket(intf)
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, intf.out_spi, seq_num,
                                  None, intf.local, intf.remote)

=======

    local_port = _SendPacket(self, intf.netid, inner_version, remote_inner,
                             _TEST_REMOTE_PORT)
    self.assertSentPacket(intf)
    pkt = self._ExpectEspPacketOn(intf.underlying_netid, intf.out_spi, seq_num,
                                  None, intf.local, intf.remote)

>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    myaddr = self.MyAddress(intf.version, intf.underlying_netid)
    _, toobig = packets.ICMPPacketTooBig(intf.version, intermediate, myaddr,
                                         pkt)
    self.ReceivePacketOn(intf.underlying_netid, toobig)

    # Check that the packet too big reduced the MTU.
    routes = self.iproute.GetRoutes(intf.remote, 0, intf.underlying_netid, None)
    self.assertEquals(1, len(routes))
    rtmsg, attributes = routes[0]
    self.assertEquals(iproute.RTN_UNICAST, rtmsg.type)
    self.assertEquals(packets.PTB_MTU, attributes["RTA_METRICS"]["RTAX_MTU"])

    # Clear PMTU information so that future tests don't have to worry about it.
    self.InvalidateDstCache(intf.version, intf.underlying_netid)

    return seq_num + 1
<<<<<<< HEAD

  def _TestIntf(self, inner_version, outer_version, func, use_null_crypt):
=======

  def _TestIntf(self, inner_version, outer_version, direction, func,
               use_null_crypt):
    """Test packet input and output over a Virtual Tunnel Interface."""
    intf = self.randomTunnelIntf(outer_version)

    try:
      # Some tests require that the out_seq_num and in_seq_num are the same
      # (Specifically encrypted tests), rebuild SAs to ensure seq_num is 1
      intf.TeardownXfrm()
      intf.SetupXfrm(use_null_crypt)

      local_inner = intf.addrs[inner_version]
      remote_inner = _GetRemoteInnerAddress(inner_version)
      spi = {
          xfrm.XFRM_POLICY_IN: intf.in_spi,
          xfrm.XFRM_POLICY_OUT: intf.out_spi
      }[direction]

      next_seq_num = func(intf, inner_version, local_inner, remote_inner, spi,
                          1)
      next_seq_num = func(intf, inner_version, local_inner, remote_inner, spi,
                          next_seq_num)
    finally:
      if use_null_crypt:
        intf.TeardownXfrm()
        intf.SetupXfrm(False)

  def _CheckIntfRekey(self, intf, inner_version, local_inner, remote_inner):
    seq_num_in = seq_num_out = 1

    old_out_spi = intf.out_spi
    old_in_spi = intf.in_spi

    # Check to make sure that both directions work before rekey
    seq_num_in = self._CheckIntfInput(intf, inner_version, local_inner,
                                     remote_inner, old_in_spi, seq_num_in)
    seq_num_out = self._CheckIntfOutput(intf, inner_version, local_inner,
                                       remote_inner, old_out_spi, seq_num_out)

    # Rekey
    new_seq_num_in, new_seq_num_out = 1, 1
    outer_family = net_test.GetAddressFamily(intf.version)

    # Create new SA
    # Distinguish the new SAs with new SPIs.
    new_out_spi = old_out_spi + 1
    new_in_spi = old_in_spi + 1

    # Perform Rekey
    intf.Rekey(outer_family, new_out_spi, new_in_spi)

    # Update Interface object
    intf.out_spi = new_out_spi
    intf.in_spi = new_in_spi

    # Expect that the old SPI still works for inbound packets
    seq_num_in = self._CheckIntfInput(intf, inner_version, local_inner,
                                     remote_inner, old_in_spi, seq_num_in)

    # Test both paths with new SPIs, expect outbound to use new SPI
    new_seq_num_in = self._CheckIntfInput(intf, inner_version, local_inner,
                                         remote_inner, new_in_spi,
                                         new_seq_num_in)
    new_seq_num_out = self._CheckIntfOutput(intf, inner_version, local_inner,
                                           remote_inner, new_out_spi,
                                           new_seq_num_out)

    # Delete old SAs
    intf.DeleteOldSaInfo(outer_family, old_in_spi, old_out_spi)

    # Test both paths with new SPIs; should still work
    new_seq_num_in = self._CheckIntfInput(intf, inner_version, local_inner,
                                         remote_inner, new_in_spi,
                                         new_seq_num_in)
    new_seq_num_out = self._CheckIntfOutput(intf, inner_version, local_inner,
                                           remote_inner, new_out_spi,
                                           new_seq_num_out)

    # Expect failure upon trying to receive a packet with the deleted SPI
    seq_num_in = self._CheckIntfInput(intf, inner_version, local_inner,
                                      remote_inner, old_in_spi, seq_num_in,
                                      True)

  def _TestIntfRekey(self, inner_version, outer_version):
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption
    """Test packet input and output over a Virtual Tunnel Interface."""
    intf = self.randomTunnelIntf(outer_version)

    try:
<<<<<<< HEAD
      intf.TeardownXfrm()
      intf.SetupXfrm(use_null_crypt)
=======
      # Always use null_crypt, so we can check input and output separately
      intf.TeardownXfrm()
      intf.SetupXfrm(True)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption

      local_inner = intf.addrs[inner_version]
      remote_inner = _GetRemoteInnerAddress(inner_version)

<<<<<<< HEAD
      next_seq_num = func(intf, inner_version, local_inner, remote_inner, 1)
      next_seq_num = func(intf, inner_version, local_inner, remote_inner,
                          next_seq_num)
    finally:
      if use_null_crypt:
        intf.TeardownXfrm()
        intf.SetupXfrm(False)
=======
      self._CheckIntfRekey(intf, inner_version, local_inner, remote_inner)
    finally:
      intf.TeardownXfrm()
      intf.SetupXfrm(False)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmVtiTest(XfrmTunnelBase):

  INTERFACE_CLASS = VtiInterface
<<<<<<< HEAD

  def ParamTestVtiInput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfInput, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfOutput, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfEncryption,
                   False)

  def ParamTestVtiIcmp(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfIcmp, False)
=======

  def ParamTestVtiInput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_IN,
                   self._CheckIntfInput, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_OUT,
                   self._CheckIntfOutput, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_IN,
                   self._CheckIntfEncryption, False)

  def ParamTestVtiIcmp(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_OUT,
                   self._CheckIntfIcmp, False)

  def ParamTestVtiRekey(self, inner_version, outer_version):
    self._TestIntfRekey(inner_version, outer_version)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption


@unittest.skipUnless(HAVE_XFRM_INTERFACES, "XFRM interfaces unsupported")
class XfrmInterfaceTest(XfrmTunnelBase):

  INTERFACE_CLASS = XfrmInterface

  def ParamTestVtiInput(self, inner_version, outer_version):
<<<<<<< HEAD
    self._TestIntf(inner_version, outer_version, self._CheckIntfInput, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfOutput, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfEncryption,
                   False)

  def ParamTestVtiIcmp(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, self._CheckIntfIcmp, False)
=======
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_IN,
                  self._CheckIntfInput, True)

  def ParamTestVtiOutput(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_OUT,
                  self._CheckIntfOutput, True)

  def ParamTestVtiInOutEncrypted(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_IN,
                  self._CheckIntfEncryption, False)

  def ParamTestVtiIcmp(self, inner_version, outer_version):
    self._TestIntf(inner_version, outer_version, xfrm.XFRM_POLICY_OUT,
                  self._CheckIntfIcmp, False)

  def ParamTestVtiRekey(self, inner_version, outer_version):
    self._TestIntfRekey(inner_version, outer_version)
>>>>>>> 0fd5ae0... Refactor VTI tests to support null encryption


if __name__ == "__main__":
  InjectTests()
  unittest.main()
