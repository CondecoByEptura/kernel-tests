#!/usr/bin/python3
#
# Copyright 2023 The Android Open Source Project
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

import cstruct
import csocket
import multinetwork_base
import net_test
import packets
import socket
import struct
import unittest

from scapy import all as scapy

MRT6_BASE = 200
MRT6_INIT = MRT6_BASE # Activate the kernel mroute code
MRT6_DONE = (MRT6_BASE+1) # Shutdown the kernel mroute
MRT6_ADD_MIF = (MRT6_BASE+2) # Add a virtual interface
MRT6_DEL_MIF = (MRT6_BASE+3) # Delete a virtual interface
MRT6_ADD_MFC = (MRT6_BASE+4) # Add a multicast forwarding entry
MRT6_DEL_MFC = (MRT6_BASE+5) # Delete a multicast forwarding entry

ICMP6_FILTER = 1

IPV6_MULTICAST_ADDR = "ff05::12"

Mif6ctl = cstruct.Struct("mif6ctl", "HBBHI",
                          "mif6c_mifi, mif6c_flags, vifc_threshold, "
                          "mif6c_pifi, vifc_rate_limit")

Mf6cctl = cstruct.Struct("mf6cctl", "SSH8I", "source, group, iif, oifset0, oifset1, "
                         "oifset2, oifset3, oifset4, oifset5, oifset6, oifset7",
                         [csocket.SockaddrIn6, csocket.SockaddrIn6])

class MulticastRoutingTest(multinetwork_base.MultiNetworkBaseTest):

  @classmethod
  def setUpClass(cls):
    super(MulticastRoutingTest, cls).setUpClass()
    cls.virtualIndexes = {}
    index = 0
    for netid in cls.NETIDS:
        cls.virtualIndexes[netid] = index
        index += 1

  @classmethod
  def tearDownClass(cls):
    super(MulticastRoutingTest, cls).tearDownClass()

  def setUp(self):
    super(MulticastRoutingTest, self).setUp()
    # create a socket for multicast routing configurations
    self.sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_INIT, 1)
    # filter all icmp6 sockets
    icmp6_filter = bytearray(32) # u_int32_t icmp6_filt[8]
    self.sock.setsockopt(socket.IPPROTO_ICMPV6, ICMP6_FILTER, icmp6_filter)

    # add the interfaces as multicast interfaces
    for netid in self.NETIDS:
        self.AddMulticastInterface(netid)

  def tearDown(self):
    super(MulticastRoutingTest, self).tearDown()

    # remove the interfaces as multicast interfaces
    for netid in self.NETIDS:
        self.RemoveMulticastInterface(netid)

    self.sock.close()
    del self.sock

  def MakeMif6ctl(self, mifi, pifi):
    return Mif6ctl((mifi, 0, 1, pifi, 0)).Pack()

  def AddMulticastInterface(self, netid):
    mif6ctl = self.MakeMif6ctl(self.virtualIndexes[netid], self.ifindices[netid])
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_ADD_MIF, mif6ctl)

  def RemoveMulticastInterface(self, netid):
    mif6ctl = self.MakeMif6ctl(self.virtualIndexes[netid], self.ifindices[netid])
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_DEL_MIF, mif6ctl)

  def MakeMf6cctl(self, src, group, iif, oifs):
    source_ip = socket.inet_pton(socket.AF_INET6, src)
    sockaddr_in6_source = csocket.SockaddrIn6((socket.AF_INET6, 0, 0, source_ip, 0))
    group_ip = socket.inet_pton(socket.AF_INET6, group)
    sockaddr_in6_group = csocket.SockaddrIn6((socket.AF_INET6, 0, 0, group_ip, 0))
    return Mf6cctl((sockaddr_in6_source, sockaddr_in6_group, iif, *oifs)).Pack()

  def EnableSourceToGroupRouting(self, iif_netid, oif_netids):
    srcaddr = self.MyAddress(6, iif_netid)
    iif_virtual_index = self.virtualIndexes[iif_netid]
    oifs = [0] * 8
    for oif_netid in oif_netids:
        oifs[0] |= (1 << self.virtualIndexes[oif_netid])
    mf6cctl = self.MakeMf6cctl(srcaddr , IPV6_MULTICAST_ADDR, iif_virtual_index, oifs)
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_ADD_MFC, mf6cctl)

  def MulticastSocket(self):
    s = net_test.IPv6PingSocket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 64)
    return s

  def SendMulticastPingPacket(self, netid):
    s = self.MulticastSocket()
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.ifindices[netid])
    mysockaddr = self.MySocketAddress(6, netid)
    s.bind((mysockaddr, packets.PING_IDENT))
    dstsockaddr = IPV6_MULTICAST_ADDR
    s.sendto(net_test.IPV6_PING + packets.PING_PAYLOAD, (dstsockaddr, 0))
    s.close()

  def CheckMulticastPingPacket(self, netid, expected):
    msg = "IPv6 ping request expected on %s" % (self.GetInterfaceName(netid))
    self.ExpectPacketOn(netid, msg, expected)

  def Icmpv6EchoRequest(self, netid, hoplimit):
    srcaddr = self.MyAddress(6, netid)
    dstaddr = IPV6_MULTICAST_ADDR
    msg = (scapy.IPv6(src=srcaddr, dst=dstaddr, hlim=hoplimit) /
           scapy.ICMPv6EchoRequest(id=packets.PING_IDENT, seq=packets.PING_SEQ,
                                   data=packets.PING_PAYLOAD))
    return msg

  # send a ping packet to iif, check it's forwarded to oifs
  def CheckPingForwarding(self, iif_netid, oif_netids):
    self.SendMulticastPingPacket(iif_netid)
    expected_original = self.Icmpv6EchoRequest(iif_netid, 64)
    self.CheckMulticastPingPacket(iif_netid, expected_original)
    expected_forwarded = self.Icmpv6EchoRequest(iif_netid, 63)
    for oif_netid in oif_netids:
        self.CheckMulticastPingPacket(oif_netid, expected_forwarded)

  def testEnableSrcToGroupForwarding(self):
    # enable forwarding (S, G) from if0 to if1:
    self.EnableSourceToGroupRouting(self.NETIDS[0], [self.NETIDS[1]])

    self.CheckPingForwarding(self.NETIDS[0], [self.NETIDS[1]])

  def testEnable3InterfacesSrcToGroupForwarding(self):
    # enable forwarding (S, G) from if0 to if1 and if2
    self.EnableSourceToGroupRouting(self.NETIDS[0], [self.NETIDS[1], self.NETIDS[2]])
    # enable forwarding (S, G) from if1 to if0 and if2
    self.EnableSourceToGroupRouting(self.NETIDS[1], [self.NETIDS[0], self.NETIDS[2]])
    # enable forwarding (S, G) from if2 to if0 and if1
    self.EnableSourceToGroupRouting(self.NETIDS[2], [self.NETIDS[0], self.NETIDS[1]])

    self.CheckPingForwarding(self.NETIDS[0], [self.NETIDS[1], self.NETIDS[2]])
    self.CheckPingForwarding(self.NETIDS[1], [self.NETIDS[0], self.NETIDS[2]])
    self.CheckPingForwarding(self.NETIDS[2], [self.NETIDS[0], self.NETIDS[1]])

if __name__ == "__main__":
  unittest.main()
