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

import multinetwork_base
import net_test
import packets
import socket
import struct
import subprocess
import unittest

from scapy import all as scapy

MRT6_BASE = 200
MRT6_INIT = MRT6_BASE # Activate the kernel mroute code
MRT6_DONE = (MRT6_BASE+1) # Shutdown the kernel mroute
MRT6_ADD_MIF = (MRT6_BASE+2) # Add a virtual interface
MRT6_DEL_MIF = (MRT6_BASE+3) # Delete a virtual interface
MRT6_ADD_MFC = (MRT6_BASE+4) # Add a multicast forwarding entry
MRT6_DEL_MFC = (MRT6_BASE+5) # Delete a multicast forwarding entry
MRT6_ADD_MFC_PROXY = (MRT6_BASE+10) # Add a (*,*|G) mfc entry
MRT6_DEL_MFC_PROXY = (MRT6_BASE+11) # Del a (*,*|G) mfc entry

ICMP6_FILTER = 1

IPV6_MULTICAST_ADDR = "ff05::12"

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
    cls.virtualIndexes = None

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
    self.sock = None

  def MakeMif6ctl(self, mifi, pifi):
    # struct mif6ctl {
    #     mifi_t mif6c_mifi; /* Index of MIF */
    #     unsigned char mif6c_flags; /* MIFF_ flags */
    #     unsigned char vifc_threshold; /* ttl limit */
    #     __u16 mif6c_pifi; /* the index of the physical IF */
    #     unsigned int vifc_rate_limit; /* Rate limiter values (NI) */
    # };
    fmt = "HBBHI"
    res = struct.pack(fmt, mifi, 0, 1, pifi, 0)
    assert struct.calcsize(fmt) == 12
    return res

  def AddMulticastInterface(self, netid):
    mif6ctl = self.MakeMif6ctl(self.virtualIndexes[netid], self.ifindices[netid])
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_ADD_MIF, mif6ctl)

  def RemoveMulticastInterface(self, netid):
    mif6ctl = self.MakeMif6ctl(self.virtualIndexes[netid], self.ifindices[netid])
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_DEL_MIF, mif6ctl)

  def MakeMf6cctl(self, src, group, iif, oifs):
    # struct mf6cctl {
    #     struct sockaddr_in6 mf6cc_origin; /* Origin of mcast */
    #     struct sockaddr_in6 mf6cc_mcastgrp; /* Group in question */
    #     mifi_t mf6cc_parent; /* Where it arrived */
    #     struct if_set mf6cc_ifset; /* Where it is going */
    # };
    # struct sockaddr_in6 {
    #     unsigned short int sin6_family; /* AF_INET6 */
    #     __be16 sin6_port; /* Transport layer port # */
    #     __be32 sin6_flowinfo; /* IPv6 flow information */
    #     struct in6_addr sin6_addr; /* IPv6 address */
    #     __u32	sin6_scope_id; /* scope id (new in RFC2553) */
    # };
    # struct in6_addr {
    #     union {
    #         __u8 u6_addr8[16];
    #     } in6_u;
    # };
    source_ip = socket.inet_pton(socket.AF_INET6, src)
    sockaddr_in6_source = struct.pack("HHI16sI", socket.AF_INET6, 0, 0, source_ip, 0)
    group_ip = socket.inet_pton(socket.AF_INET6, group)
    sockaddr_in6_group = struct.pack("HHI16sI", socket.AF_INET6, 0, 0, group_ip, 0)
    struct_mf6cctl = struct.pack("28s28sH" + "I" * 8,
                                 sockaddr_in6_source, sockaddr_in6_group, iif, *oifs)
    return struct_mf6cctl

  def EnableAnyToGroupRouting(self, iif_netid, oif_netids):
    iif_virtual_index = self.virtualIndexes[iif_netid]
    oifs = [0] * 8
    # include both iif and oif in oifs as required by a (*, G) MFC
    oifs[0] |= (1 << iif_virtual_index)
    for oif_netid in oif_netids:
        oifs[0] |= (1 << self.virtualIndexes[oif_netid])
    mf6cctl = self.MakeMf6cctl("::" , IPV6_MULTICAST_ADDR, iif_virtual_index, oifs)
    self.sock.setsockopt(socket.IPPROTO_IPV6, MRT6_ADD_MFC_PROXY, mf6cctl)

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

  def testEnableAnyToGroupForwarding(self):
    # enable forwarding (*, G) from if0 to if1:
    self.EnableAnyToGroupRouting(self.NETIDS[0], [self.NETIDS[1]])

    self.CheckPingForwarding(self.NETIDS[0], [self.NETIDS[1]])

  @unittest.skipUnless(False, "skipping: waiting for kernel fix b/308390709")
  def testEnableBidirectionalAnyToGroupForwarding(self):
    # enable forwarding (*, G) from if0 to if1
    self.EnableAnyToGroupRouting(self.NETIDS[0], [self.NETIDS[1]])
    # enable forwarding (*, G) from if1 to if0
    self.EnableAnyToGroupRouting(self.NETIDS[1], [self.NETIDS[0]])
    result = subprocess.run(['ip', '-6', 'mroute'], stdout=subprocess.PIPE)
    print(result.stdout.decode())

    self.CheckPingForwarding(self.NETIDS[0], [self.NETIDS[1]])

    self.CheckPingForwarding(self.NETIDS[1], [self.NETIDS[0]])

  @unittest.skipUnless(False, "skipping: waiting for kernel fix b/308390709")
  def testEnable3InterfacesAnyToGroupForwarding(self):
    # enable forwarding (*, G) from if0 to if1 and if2
    self.EnableAnyToGroupRouting(self.NETIDS[0], [self.NETIDS[1], self.NETIDS[2]])
    # enable forwarding (*, G) from if1 to if0 and if2
    self.EnableAnyToGroupRouting(self.NETIDS[1], [self.NETIDS[0], self.NETIDS[2]])
    # enable forwarding (*, G) from if2 to if0 and if1
    self.EnableAnyToGroupRouting(self.NETIDS[2], [self.NETIDS[0], self.NETIDS[1]])
    result = subprocess.run(['ip', '-6', 'mroute'], stdout=subprocess.PIPE)
    print(result.stdout.decode())

    self.CheckPingForwarding(self.NETIDS[0], [self.NETIDS[1], self.NETIDS[2]])

    self.CheckPingForwarding(self.NETIDS[1], [self.NETIDS[0], self.NETIDS[2]])

    self.CheckPingForwarding(self.NETIDS[2], [self.NETIDS[0], self.NETIDS[1]])

if __name__ == "__main__":
  unittest.main()
