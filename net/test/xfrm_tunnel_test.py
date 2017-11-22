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

from contextlib import contextmanager
from scapy import all as scapy
import struct
import subprocess
import unittest

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
_TEST_IN_SPI = 0x7654

_TEST_OKEY = _TEST_OUT_SPI + _VTI_NETID
_TEST_IKEY = _TEST_IN_SPI + _VTI_NETID


class StatMonitor(object):
  def __init__(self):
    self._last_stats = self._get_stats()
    self._keys = sorted(self._last_stats.keys())

  def Check(self):
    new_stats = self._get_stats()
    for k in self._keys:
      d = new_stats[k] - self._last_stats[k]
      if d:
        print "%s +%d" % (k, d)
    self._last_stats = new_stats

  def _get_stats(self):
    stats = {}
    with open("/proc/net/xfrm_stat") as f:
      for line in f:
        key, val = line.split()
        stats[key] = int(val)
    return stats

@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmTunnelTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmTunnelTest, self).setUp()
    # If the hard-coded netids are redefined this will catch the error.
    self.assertNotIn(_VTI_NETID, self.NETIDS,
                     "VTI netid %d already in use" % _VTI_NETID)
    self.iproute = iproute.IPRoute()
    self._QuietDeleteLink(_VTI_IFNAME)

  def tearDown(self):
    super(XfrmTunnelTest, self).tearDown()
    self._QuietDeleteLink(_VTI_IFNAME)

  @staticmethod
  def _GetLocalInnerAddress(version):
    return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]

  @staticmethod
  def _GetRemoteInnerAddress(version):
    return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]

  def _GetRemoteOuterAddress(self, version):
    return self.GetRemoteAddress(version)

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

  def _CreateXfrmTunnelTransform(self, direction, inner_family, src_addr, src_prefixlen, dst_addr, dst_prefixlen, outer_family, tsrc_addr, tdst_addr, spi, crypt, crypt_key, auth, auth_key, mark=None, output_mark=None, priority=100, reqid=0):
    self.xfrm.AddMinimalSaInfo(tsrc_addr, tdst_addr, htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, reqid, crypt, crypt_key, auth, auth_key, None, mark, xfrm_base.MARK_MASK_ALL if mark is not None else None, output_mark, sel_family=inner_family)

  def _DestroyXfrmTunnelTransform(self, direction, inner_family, src_addr, src_prefixlen, dst_addr, dst_prefixlen, outer_family, tsrc_addr, tdst_addr, spi, crypt, crypt_key, auth, auth_key, mark=None, output_mark=None, priority=100):
    self.xfrm.DeleteSaInfo(tdst_addr, spi, IPPROTO_ESP)

  def _CreateXfrmTunnelPolicy(self, direction, inner_family, src_addr, src_prefixlen, dst_addr, dst_prefixlen, outer_family, tsrc_addr, tdst_addr, spi, crypt, crypt_key, auth, auth_key, mark=None, output_mark=None, priority=100, reqid=0):
    sel = xfrm.XfrmSelector(daddr=xfrm.PaddedAddress(dst_addr), saddr=xfrm.PaddedAddress(src_addr), prefixlen_d=dst_prefixlen, prefixlen_s=src_prefixlen, family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo( sel=sel, lft=xfrm.NO_LIFETIME_CFG, curlft=xfrm.NO_LIFETIME_CUR, priority=priority, index=0, dir=direction, action=xfrm.XFRM_POLICY_ALLOW, flags=xfrm.XFRM_POLICY_LOCALOK, share=xfrm.XFRM_SHARE_ANY)

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId( daddr=xfrm.PaddedAddress(tdst_addr), spi=htonl(spi), proto=IPPROTO_ESP)
    tmpl = xfrm.XfrmUserTmpl(id=xfrmid, family=outer_family, saddr=xfrm.PaddedAddress(tsrc_addr), reqid=reqid, mode=xfrm.XFRM_MODE_TUNNEL, share=xfrm.XFRM_SHARE_ANY, optional=0,  aalgos=xfrm_base.ALL_ALGORITHMS, ealgos=xfrm_base.ALL_ALGORITHMS, calgos=xfrm_base.ALL_ALGORITHMS)

    self.xfrm.AddPolicyInfo(policy, [tmpl], xfrm.XfrmMark((mark, xfrm_base.MARK_MASK_ALL)) if mark else None)

  def _UpdateXfrmTunnelPolicy(self, direction, inner_family, src_addr, src_prefixlen, dst_addr, dst_prefixlen, outer_family, tsrc_addr, tdst_addr, spis, crypt, crypt_key, auth, auth_key, mark=None, output_mark=None, priority=100, reqids=[]):
    sel = xfrm.XfrmSelector(daddr=xfrm.PaddedAddress(dst_addr), saddr=xfrm.PaddedAddress(src_addr), prefixlen_d=dst_prefixlen, prefixlen_s=src_prefixlen, family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo( sel=sel, lft=xfrm.NO_LIFETIME_CFG, curlft=xfrm.NO_LIFETIME_CUR, priority=priority, index=0, dir=direction, action=xfrm.XFRM_POLICY_ALLOW, flags=xfrm.XFRM_POLICY_LOCALOK, share=xfrm.XFRM_SHARE_ANY)

    tmpls = []
    for spi, reqid in zip(spis, reqids):
      # Create a template that specifies the SPI and the protocol.
      xfrmid = xfrm.XfrmId(daddr=xfrm.PaddedAddress(tdst_addr), spi=htonl(spi), proto=IPPROTO_ESP)
      tmpl = xfrm.XfrmUserTmpl(id=xfrmid, family=outer_family, saddr=xfrm.PaddedAddress(tsrc_addr), reqid=reqid, mode=xfrm.XFRM_MODE_TUNNEL, share=xfrm.XFRM_SHARE_ANY, optional=0,  aalgos=xfrm_base.ALL_ALGORITHMS, ealgos=xfrm_base.ALL_ALGORITHMS, calgos=xfrm_base.ALL_ALGORITHMS)
      tmpls.append(tmpl)

    self.xfrm.UpdatePolicyInfo(policy, tmpls, xfrm.XfrmMark((mark, xfrm_base.MARK_MASK_ALL)) if mark else None)

  def _CreateXfrmTunnel(self, direction, inner_family, src_addr, src_prefixlen, dst_addr, dst_prefixlen, outer_family, tsrc_addr, tdst_addr, spi, crypt, crypt_key, auth, auth_key, mark=None, output_mark=None, priority=100, index=0):
    """Create an XFRM Tunnel Consisting of a Policy and an SA.

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.

    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      inner_family: The address family (AF_INET or AF_INET6) of the tunneled
        packets
      src_addr: The source address of the inner packets to be tunneled
      src_prefixlen: The number of bits in src_addr to match
      dst_addr: The destination address of the inner packets to be tunneled
      dst_prefixlen: The number of bits in dst_addr to match
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      crypt: An XfrmAlgo struct specifying encryption algorithm
      crypt_key: Encryption key
      auth: An XfrmAlgoAuth struct specifying authentication algorithm
      auth_key: Authentication key
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
      output_mark: The mark used to select the underlying network for packets
        outbound from xfrm.
      priority: XFRM policy priority (default 100)
    """
    self.xfrm.AddMinimalSaInfo(
        tsrc_addr,
        tdst_addr,
        htonl(spi),
        IPPROTO_ESP,
        xfrm.XFRM_MODE_TUNNEL,
        0,
        crypt,
        crypt_key,
        auth,
        auth_key,
        None,
        mark,
        xfrm_base.MARK_MASK_ALL if mark is not None else None,
        output_mark,
        sel_family=inner_family)

    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        prefixlen_d=dst_prefixlen,
        prefixlen_s=src_prefixlen,
        family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo(
        sel=sel,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        priority=priority,
        index=index,
        dir=direction,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_ANY)

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId(
        daddr=xfrm.PaddedAddress(tdst_addr),
        #spi=htonl(spi),
        proto=IPPROTO_ESP)
    tmpl = xfrm.XfrmUserTmpl(
        id=xfrmid,
        family=outer_family,
        saddr=xfrm.PaddedAddress(tsrc_addr),
        reqid=0,
        mode=xfrm.XFRM_MODE_TUNNEL,
        share=xfrm.XFRM_SHARE_ANY,
        optional=0,  # require
        aalgos=xfrm_base.ALL_ALGORITHMS,  # auth algos
        ealgos=xfrm_base.ALL_ALGORITHMS,  # encryption algos
        calgos=xfrm_base.ALL_ALGORITHMS)  # compression algos


    #print policy, tmpl
    self.xfrm.AddPolicyInfo(policy, [tmpl],
                            xfrm.XfrmMark((mark, xfrm_base.MARK_MASK_ALL))
                            if mark else None)

  def _UpdateXfrmTunnel(self,
                        direction,
                        inner_family,
                        src_addr,
                        src_prefixlen,
                        dst_addr,
                        dst_prefixlen,
                        outer_family,
                        tsrc_addr,
                        tdst_addr,
                        spi,
                        crypt,
                        crypt_key,
                        auth,
                        auth_key,
                        mark=None,
                        output_mark=None,
                        priority=100):
    """Update the Policy of an XFRM Tunnel.

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.

    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      inner_family: The address family (AF_INET or AF_INET6) of the tunneled
        packets
      src_addr: The source address of the inner packets to be tunneled
      src_prefixlen: The number of bits in src_addr to match
      dst_addr: The destination address of the inner packets to be tunneled
      dst_prefixlen: The number of bits in dst_addr to match
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      crypt: An XfrmAlgo struct specifying encryption algorithm
      crypt_key: Encryption key
      auth: An XfrmAlgoAuth struct specifying authentication algorithm
      auth_key: Authentication key
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
      output_mark: The mark used to select the underlying network for packets
        outbound from xfrm.
      priority: XFRM policy priority (default 100)
    """
    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        prefixlen_d=dst_prefixlen,
        prefixlen_s=src_prefixlen,
        family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo(
        sel=sel,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        priority=priority,
        index=0,
        dir=direction,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_ANY)

    tmpls = []
    for spi in spis:
      # Create a template that specifies the SPI and the protocol.
      xfrmid = xfrm.XfrmId(
          daddr=xfrm.PaddedAddress(tdst_addr), spi=htonl(spi), proto=IPPROTO_ESP)
      tmpl = xfrm.XfrmUserTmpl(
          id=xfrmid,
          family=outer_family,
          saddr=xfrm.PaddedAddress(tsrc_addr),
          reqid=0,
          mode=xfrm.XFRM_MODE_TUNNEL,
          share=xfrm.XFRM_SHARE_ANY,
          optional=0,  # require
          aalgos=xfrm_base.ALL_ALGORITHMS,  # auth algos
          ealgos=xfrm_base.ALL_ALGORITHMS,  # encryption algos
          calgos=xfrm_base.ALL_ALGORITHMS)  # compression algos
      tmpls.append(tmpl)


    #print policy, tmpl
    self.xfrm.UpdatePolicyInfo(policy, tmpls,
                            xfrm.XfrmMark((mark, xfrm_base.MARK_MASK_ALL))
                            if mark else None)

  def _CheckTunnelOutput(self, inner_version, outer_version):
    """Test a bi-directional XFRM Tunnel with explicit selectors"""
    # Select the underlying netid, which represents the external
    # interface from/to which to route ESP packets.
    underlying_netid = self.RandomNetid()
    # Select a random netid that will originate traffic locally and
    # which represents the logical tunnel network.
    netid = self.RandomNetid(exclude=underlying_netid)

    local_inner = self.MyAddress(inner_version, netid)
    remote_inner = self._GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, underlying_netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    self._CreateXfrmTunnel(
        direction=xfrm.XFRM_POLICY_OUT,
        inner_family=net_test.GetAddressFamily(inner_version),
        src_addr=local_inner,
        src_prefixlen=net_test.AddressLengthBits(inner_version),
        dst_addr=remote_inner,
        dst_prefixlen=net_test.AddressLengthBits(inner_version),
        outer_family=net_test.GetAddressFamily(outer_version),
        tsrc_addr=local_outer,
        tdst_addr=remote_outer,
        mark=None,
        spi=_TEST_OUT_SPI,
        crypt=xfrm_base._ALGO_CBC_AES_256,
        crypt_key=xfrm_base._ENCRYPTION_KEY_256,
        auth=xfrm_base._ALGO_HMAC_SHA1,
        auth_key=xfrm_base._AUTHENTICATION_KEY_128,
        output_mark=underlying_netid)

    write_sock = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    # Select an interface, which provides the source address of the inner
    # packet.
    self.SelectInterface(write_sock, netid, "mark")
    write_sock.sendto(net_test.UDP_PAYLOAD, (remote_inner, 53))
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1, None,
                            local_outer, remote_outer)

  # TODO: Add support for the input path.

  def testIpv4InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(4, 4)

  def testIpv4InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(4, 6)

  def testIpv6InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(6, 4)

  def testIpv6InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(6, 6)

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface."""
    for version in [4, 6]:
      netid = self.RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=self._GetRemoteOuterAddress(version),
          o_key=_TEST_OKEY,
          i_key=_TEST_IKEY)
      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface.
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _SetupVtiNetwork(self, ifname, is_add):
    """Setup rules and routes for a VTI Network.

    Takes an interface and depending on the boolean value of is_add, either adds
    or removes the rules and routes for a VTI to behave like an Android Network
    for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Bring up the interface so that we can start adding addresses
      # and routes.
      net_test.SetInterfaceUp(_VTI_IFNAME)

      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the VTI, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      self.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % _VTI_IFNAME, 0)
    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(ifname)
      table = _VTI_NETID

      # Set up routing rules.
      start, end = self.UidRangeForNetid(_VTI_NETID)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, ifname, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, _VTI_NETID, table,
                              self.PRIORITY_FWMARK)
      if is_add:
        self.iproute.AddAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        self.iproute.DelAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
    if not is_add:
      net_test.SetInterfaceDown(_VTI_IFNAME)

  @contextmanager
  def _VtiNetwork(self, ifname):
    """Context manager to help tear down VTI networks."""
    self._SetupVtiNetwork(ifname, True)
    try:
      yield
    finally:
      self._SetupVtiNetwork(ifname, False)

  # TODO: Should we completely re-write this using null encryption and null
  # authentication? We could then assemble and disassemble packets for each
  # direction individually. This approach would improve debuggability, avoid the
  # complexity of the twister, and allow the test to more-closely validate
  # deployable configurations.
  def _CheckVtiOutput(self, inner_version, outer_version):
    """Test packet input and output over a Virtual Tunnel Interface."""
    netid = self.RandomNetid()
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    self.iproute.CreateVirtualTunnelInterface(
        dev_name=_VTI_IFNAME,
        local_addr=local_outer,
        remote_addr=remote_outer,
        i_key=_TEST_IKEY,
        o_key=_TEST_OKEY)
    self._SetupVtiNetwork(_VTI_IFNAME, True)

    try:
      # For the VTI, the selectors are wildcard since packets will only
      # be selected if they have the appropriate mark, hence the inner
      # addresses are wildcard.
      inner_addr = net_test.GetWildcardAddress(inner_version)
      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          inner_family=net_test.GetAddressFamily(inner_version),
          src_addr=inner_addr,
          src_prefixlen=0,
          dst_addr=inner_addr,
          dst_prefixlen=0,
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=local_outer,
          tdst_addr=remote_outer,
          mark=_TEST_OKEY,
          spi=_TEST_OUT_SPI,
          crypt=xfrm_base._ALGO_CBC_AES_256,
          crypt_key=xfrm_base._ENCRYPTION_KEY_256,
          auth=xfrm_base._ALGO_HMAC_SHA1,
          auth_key=xfrm_base._AUTHENTICATION_KEY_128,
          output_mark=netid)

      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          inner_family=net_test.GetAddressFamily(inner_version),
          src_addr=inner_addr,
          src_prefixlen=0,
          dst_addr=inner_addr,
          dst_prefixlen=0,
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=remote_outer,
          tdst_addr=local_outer,
          mark=_TEST_IKEY,
          spi=_TEST_IN_SPI,
          crypt=xfrm_base._ALGO_CBC_AES_256,
          crypt_key=xfrm_base._ENCRYPTION_KEY_256,
          auth=xfrm_base._ALGO_HMAC_SHA1,
          auth_key=xfrm_base._AUTHENTICATION_KEY_128)

      # Create a socket to receive packets.
      read_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
      # The second parameter of the tuple is the port number regardless of AF.
      port = read_sock.getsockname()[1]
      # Guard against the eventuality of the receive failing.
      csocket.SetSocketTimeout(read_sock, 100)

      # Send a packet out via the vti-backed network, bound for the port number
      # of the input socket.
      write_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      self.SelectInterface(write_sock, _VTI_NETID, "mark")
      write_sock.sendto(net_test.UDP_PAYLOAD,
                        (self._GetRemoteInnerAddress(inner_version), port))

      # Read a tunneled IP packet on the underlying (outbound) network
      # verifying that it is an ESP packet.
      pkt = self._ExpectEspPacketOn(netid, _TEST_OUT_SPI, 1, None, local_outer,
                                    remote_outer)

      # Perform an address switcheroo so that the inner address of the remote
      # end of the tunnel is now the address on the local VTI interface; this
      # way, the twisted inner packet finds a destination via the VTI once
      # decrypted.
      remote = self._GetRemoteInnerAddress(inner_version)
      local = self._GetLocalInnerAddress(inner_version)
      self._SwapInterfaceAddress(_VTI_IFNAME, new_addr=remote, old_addr=local)
      try:
        # Swap the packet's IP headers and write it back to the
        # underlying network.
        pkt = TunTwister.TwistPacket(pkt)
        self.ReceivePacketOn(netid, pkt)
        # Receive the decrypted packet on the dest port number.
        read_packet = read_sock.recv(4096)
        self.assertEquals(read_packet, net_test.UDP_PAYLOAD)
      finally:
        # Unwind the switcheroo
        self._SwapInterfaceAddress(_VTI_IFNAME, new_addr=local, old_addr=remote)

    finally:
      self._SetupVtiNetwork(_VTI_IFNAME, False)

  def testIpv4InIpv4VtiOutput(self):
    self._CheckVtiOutput(4, 4)

  def testIpv4InIpv6VtiOutput(self):
    self._CheckVtiOutput(4, 6)

  def testIpv6InIpv4VtiOutput(self):
    self._CheckVtiOutput(6, 4)

  def testIpv6InIpv6VtiOutput(self):
    self._CheckVtiOutput(6, 6)

  def testVtiRekey(self):
    inner_version, outer_version = 6, 6
    netid = self.RandomNetid()
    # First, set up VTI, SAs, and policy.
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    local_inner = self._GetLocalInnerAddress(inner_version)
    remote_inner = self._GetRemoteInnerAddress(inner_version)
    self.iproute.CreateVirtualTunnelInterface(
        dev_name=_VTI_IFNAME,
        local_addr=local_outer,
        remote_addr=remote_outer,
        i_key=_TEST_IKEY,
        o_key=_TEST_OKEY)
    with self._VtiNetwork(_VTI_IFNAME):
      # For the VTI, the selectors are wildcard since packets will only
      # be selected if they have the appropriate mark, hence the inner
      # addresses are wildcard.
      inner_addr = net_test.GetWildcardAddress(inner_version)
      self._CreateXfrmTunnel(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=_TEST_OUT_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=1,  index=0)
      ##self._CreateXfrmTunnelTransform(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=_TEST_OUT_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=1, reqid=1)
      ##self._CreateXfrmTunnelPolicy(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=_TEST_OUT_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=1, reqid=1)

      self._CreateXfrmTunnel(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spi=_TEST_IN_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=1,  index=0)
      ##self._CreateXfrmTunnelTransform(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spi=_TEST_IN_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=1, reqid=2)
      ##self._CreateXfrmTunnelPolicy(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spi=_TEST_IN_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=1, reqid=2)

      # Now check that two-way traffic is working.
      sock = net_test.UDPSocket(net_test.GetAddressFamily(inner_version))
      self.SelectInterface(sock, _VTI_NETID, "mark")
      sock.bind((inner_addr, 0))
      local_port = sock.getsockname()[1]

      # Send UDP message.
      sock.sendto("output hello", (self._GetRemoteInnerAddress(inner_version), 5555))
      # Capture ESP packet.
      packets = self.ReadAllPacketsOn(netid)
      self.assertEquals(1, len(packets))
      output_pkt = packets[0]
      # Verify ESP packet.
      decrypted_output_pkt, esp_hdr = xfrm_base.DecryptPacketWithNull(output_pkt)
      self.assertEquals(local_outer, output_pkt.src)
      self.assertEquals(remote_outer, output_pkt.dst)
      self.assertEquals(local_inner, decrypted_output_pkt.src)
      self.assertEquals(remote_inner, decrypted_output_pkt.dst)
      # TODO: assert UDP layer

      # Create an ESP packet.
      IpType = {4: scapy.IP, 6: scapy.IPv6}[inner_version]
      input_pkt = (IpType(src=remote_inner, dst=local_inner) /
                   scapy.UDP(sport=5555, dport=local_port) /
                   "input hello")
      input_pkt = IpType(str(input_pkt)) # Compute length, checksum.
      # TODO: Why is the extra endian flip needed?
      encrypted_input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, htonl(_TEST_IN_SPI), 1, remote_outer, local_outer)
      # Inject the ESP packet.
      self.ReceivePacketOn(netid, encrypted_input_pkt)
      # Verify UDP message.
      msg, addr = sock.recvfrom(1024)
      self.assertEquals("input hello", msg)
      self.assertEquals((remote_inner, 5555), addr[:2])

      # BEGIN REKEY
      # Create new SAs and policy, with higher priority.
      # Distinguish the new SAs with new SPIs.
      new_out_spi = _TEST_OUT_SPI + 0x8888
      new_in_spi = _TEST_IN_SPI + 0x8888
      #subprocess.call("ip xfrm policy show".split())

      stats = StatMonitor()

      ##print 'MAKE IT DON\'T BREAK IT'
      ##subprocess.call("ip xfrm state show".split())
      ##subprocess.call("ip xfrm policy show".split())

      ##self._CreateXfrmTunnel(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=new_out_spi, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=2,  index=0)
      self._CreateXfrmTunnelTransform(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=new_out_spi, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=2, reqid=3)
      ##self._DestroyXfrmTunnelTransform(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spi=_TEST_OUT_SPI, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=1)

      ##self._UpdateXfrmTunnelPolicy(direction=xfrm.XFRM_POLICY_OUT, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=local_outer, tdst_addr=remote_outer, mark=_TEST_OKEY, spis=[_TEST_OUT_SPI, new_out_spi], crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", output_mark=netid, priority=2, reqids=[1, 3])

      ##self._CreateXfrmTunnel(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spi=new_in_spi, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=2,  index=0)
      self._CreateXfrmTunnelTransform(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spi=new_in_spi, crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=2, reqid=4)

      ##self._UpdateXfrmTunnelPolicy(direction=xfrm.XFRM_POLICY_IN, inner_family=net_test.GetAddressFamily(inner_version), src_addr=inner_addr, src_prefixlen=0, dst_addr=inner_addr, dst_prefixlen=0, outer_family=net_test.GetAddressFamily(outer_version), tsrc_addr=remote_outer, tdst_addr=local_outer, mark=_TEST_IKEY, spis=[_TEST_IN_SPI, new_in_spi], crypt=xfrm_base._ALGO_CRYPT_NULL, crypt_key="", auth=xfrm_base._ALGO_AUTH_NULL, auth_key="", priority=2, reqids=[2, 4])

      stats.Check()

      # check input side with old key/spi
      # Create an ESP packet.
      input_pkt = (IpType(src=remote_inner, dst=local_inner) /
                   scapy.UDP(sport=5555, dport=local_port) /
                   "input hello2")
      input_pkt = IpType(str(input_pkt)) # Compute length, checksum.
      # TODO: Why is the extra endian flip needed?
      encrypted_input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, htonl(_TEST_IN_SPI), 2, remote_outer, local_outer)
      # Inject the ESP packet.
      ##print 'INPUT ON OLD SPI'
      ##print str(encrypted_input_pkt).encode('hex')
      ##encrypted_input_pkt.show()
      self.ReceivePacketOn(netid, encrypted_input_pkt)
      stats.Check()
      # Verify UDP message.
      msg, addr = sock.recvfrom(1024)
      self.assertEquals("input hello2", msg)
      self.assertEquals((remote_inner, 5555), addr[:2])

      # check input with new key/spi
      input_pkt = (IpType(src=remote_inner, dst=local_inner) /
                   scapy.UDP(sport=5555, dport=local_port) /
                   "input hello3")
      input_pkt = IpType(str(input_pkt)) # Compute length, checksum.
      encrypted_input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, htonl(new_in_spi), 1, remote_outer, local_outer)
      # Inject the ESP packet.
      ##print 'INPUT ON NEW SPI'
      ##print str(encrypted_input_pkt).encode('hex')
      ##encrypted_input_pkt.show()
      self.ReceivePacketOn(netid, encrypted_input_pkt)
      stats.Check()
      # Verify UDP message.
      msg, addr = sock.recvfrom(1024)
      self.assertEquals("input hello3", msg)
      self.assertEquals((remote_inner, 5555), addr[:2])

      # check output side with new key/spi
      # Send UDP message.
      sock.sendto("output hello2", (self._GetRemoteInnerAddress(inner_version), 5555))
      stats.Check()
      # Capture ESP packet.
      packets = self.ReadAllPacketsOn(netid)
      stats.Check()
      self.assertEquals(1, len(packets))
      output_pkt = packets[0]
      # Verify ESP packet.
      decrypted_output_pkt, esp_hdr = xfrm_base.DecryptPacketWithNull(output_pkt)
      print 'NEW OUTPUT PACKET'
      ##print str(output_pkt).encode('hex')
      output_pkt.show()
      ##print esp_hdr
      ##print str(decrypted_output_pkt).encode('hex')
      ##decrypted_output_pkt.show()

      self.assertEquals("output hello2", str(decrypted_output_pkt[scapy.UDP].payload))
      ## This fails! The old output SA takes priority and needs to be deleted.
      #self.assertEquals(htonl(new_out_spi), esp_hdr.spi)

      # delete old SAs
      # confirm input with old SPI broken


if __name__ == "__main__":
  unittest.main()
