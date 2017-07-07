#!/usr/bin/python
#
# Copyright 2015 The Android Open Source Project
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

import itertools
import random
import unittest

from socket import *

import multinetwork_base
import net_test
import packets
import time

class ForwardingTest(multinetwork_base.MultiNetworkBaseTest):
  """Checks that IPv6 forwarding doesn't crash the system.

  Relevant kernel commits:
    upstream net-next:
      e7eadb4 ipv6: inet6_sk() should use sk_fullsock()
    android-3.10:
      feee3c1 ipv6: inet6_sk() should use sk_fullsock()
      cdab04e net: add sk_fullsock() helper
    android-3.18:
      8246f18 ipv6: inet6_sk() should use sk_fullsock()
      bea19db net: add sk_fullsock() helper
  """

  TCP_TIME_WAIT = 6

  def ForwardBetweenInterfaces(self, enabled, iface1, iface2):
    for iif, oif in itertools.permutations([iface1, iface2]):
      #print("iif: %s, oif: %s\n", self.GetInterfaceName(iif), self.GetInterfaceName(oif))
      self.iproute.IifRule(6, enabled, self.GetInterfaceName(iif),
                           self._TableForNetid(oif), self.PRIORITY_IIF)

  def setUp(self):
    self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 1)

  def tearDown(self):
    self.SetSysctl("/proc/sys/net/ipv6/conf/all/forwarding", 0)

  def CheckForwardingCrashUdp(self, netid, iface1, iface2):
    version = 6
    # Create a UDP socket and bind to it
    s = net_test.UDPSocket(AF_INET6)
    self.SetSocketMark(s, netid)
    addr = {4: "0.0.0.0", 5: "::", 6: "::"}[version]
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((addr, 53))

    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)

    try:
      print "Deleting the address ", myaddr, " from netid: ", netid
      self.iproute.DelAddress(myaddr, 64, self.ifindices[netid])
      print "Sending packet over iface: ", self.GetInterfaceName(netid)
      desc, udp_pkt = packets.UDPWithOptions(version, myaddr, remoteaddr, 53)
      desc_fwded, udp_fwd = packets.UDPWithOptions2(version, myaddr, remoteaddr, 53)
      msg = "Sent %s, expected %s" % (desc, desc_fwded)
      #self._ReceiveAndExpectResponse(iface1, udp_pkt, udp_fwd, msg)
      self.ReceivePacketOn(iface1, udp_pkt)
      self.ExpectPacketOn(iface2, msg, udp_fwd)
      #s.sendto(net_test.UDP_PAYLOAD, (remoteaddr, 53))
    finally:
      self.SendRA(netid)
      s.close()

    print "\n\n"

  def CheckForwardingCrash(self, netid, iface1, iface2):
    version = 6
    listensocket = net_test.IPv6TCPSocket()
    self.SetSocketMark(listensocket, netid)
    listenport = net_test.BindRandomPort(version, listensocket)

    remoteaddr = self.GetRemoteAddress(version)
    myaddr = self.MyAddress(version, netid)

    desc, syn = packets.SYN(listenport, version, remoteaddr, myaddr)
    synack_desc, synack = packets.SYNACK(version, myaddr, remoteaddr, syn)
    msg = "Sent %s, expected %s" % (desc, synack_desc)
    reply = self._ReceiveAndExpectResponse(netid, syn, synack, msg)

    establishing_ack = packets.ACK(version, remoteaddr, myaddr, reply)[1]
    self.ReceivePacketOn(netid, establishing_ack)
    accepted, peer = listensocket.accept()
    remoteport = accepted.getpeername()[1]

    accepted.close()
    desc, fin = packets.FIN(version, myaddr, remoteaddr, establishing_ack)
    self.ExpectPacketOn(netid, msg + ": expecting %s after close" % desc, fin)

    desc, finack = packets.FIN(version, remoteaddr, myaddr, fin)
    self.ReceivePacketOn(netid, finack)

    # Check our socket is now in TIME_WAIT.
    sockets = self.ReadProcNetSocket("tcp6")
    mysrc = "%s:%04X" % (net_test.FormatSockStatAddress(myaddr), listenport)
    mydst = "%s:%04X" % (net_test.FormatSockStatAddress(remoteaddr), remoteport)
    state = None
    sockets = [s for s in sockets if s[0] == mysrc and s[1] == mydst]
    self.assertEquals(1, len(sockets))
    self.assertEquals("%02X" % self.TCP_TIME_WAIT, sockets[0][2])

    # Remove our IP address.
    print "myaddr: ", myaddr
    try:
      print "Deleting the address ", myaddr, " from netid: ", netid
      self.iproute.DelAddress(myaddr, 64, self.ifindices[netid])

      self.ReceivePacketOn(iface1, finack)
      self.ReceivePacketOn(iface1, establishing_ack)
      self.ReceivePacketOn(iface1, establishing_ack)
      # No crashes? Good.

    finally:
      # Put back our IP address.
      self.SendRA(netid)
      listensocket.close()

    print "\n\n"

  def testCrash(self):
    #iif = 250
    #oif = 100

    # Run the test a few times as it doesn't crash/hang the first time.
    for netids in itertools.permutations(self.tuns):
      # Pick an interface to send traffic on and two to forward traffic between.
      #netid, iface1, iface2 = random.sample(netids, 3)
      netid, iif, oif = random.sample(netids, 3)
      print "netid: ", netid
      print("iif: %s, oif: %s\n", self.GetInterfaceName(iif), self.GetInterfaceName(oif))
      #print "netid: ", netid, "iface1: ", iface1, "iface2: ", iface2
      self.ForwardBetweenInterfaces(True, iif, oif)
      try:
        #time.sleep(15)
        self.CheckForwardingCrashUdp(netid, iif, oif)
      finally:
        self.ForwardBetweenInterfaces(False, iif, oif)


if __name__ == "__main__":
  unittest.main()
