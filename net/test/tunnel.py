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
"""Partial implementation of the RTNETLINK LINK/TUNNEL interface."""

# pylint: disable=g-bad-todo

import socket

import cstruct
import netlink
import net_test

### rtnetlink constants. See include/uapi/linux/rtnetlink.h.
# Message types.
RTM_NEWLINK = 16
RTM_DELLINK = RTM_NEWLINK + 1
RTM_GETLINK = RTM_DELLINK + 1
RTM_SETLINK = RTM_GETLINK + 1

# linux/if_tunnel.h
IFLA_VTI_UNSPEC = 0
IFLA_VTI_LINK = 1
IFLA_VTI_IKEY = 2
IFLA_VTI_OKEY = 3
IFLA_VTI_LOCAL = 4
IFLA_VTI_REMOTE = 5

# linux/include/uapi/if_link.h
IFLA_UNSPEC = 0
IFLA_ADDRESS = 1
IFLA_BROADCAST = 2
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_LINK = 5
IFLA_QDISC = 6
IFLA_STATS = 7
IFLA_COST = 8
IFLA_PRIORITY = 9
IFLA_MASTER = 10
IFLA_WIRELESS = 11
IFLA_PROTINFO = 12
IFLA_TXQLEN = 13
IFLA_MAP = 14
IFLA_WEIGHT = 15
IFLA_OPERSTATE = 16
IFLA_LINKMODE = 17
IFLA_LINKINFO = 18
IFLA_NET_NS_PID = 19
IFLA_IFALIAS = 20

# linux/include/uapi/if_link.h
IFLA_INFO_UNSPEC = 0
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
IFLA_INFO_XSTATS = 3

# include/uapi/linux/rtnetlink.h - struct ifinfomsg
IfInfoMsg = cstruct.Struct(
    "IfInfo", "BBHiII",
    "ifi_family __ifi_pad ifi_type ifi_index ifi_flags ifi_change")


class IPTunnel(netlink.NetlinkSocket):
  """Netlink functions for creating IP Tunnels"""

  def __init__(self):
    super(IPTunnel, self).__init__(netlink.NETLINK_ROUTE)

  # TODO: IPv6
  def CreateVti(self, dev_name, local_addr, remote_addr, i_key=None,
                o_key=None):
    """
    "he said, with a grin,
     documentation is bad!
     no users: no bugs."
    -Anonymous VTI Developer

    The VTI Newlink structure is a series of nested netlink
    attributes following a mostly-ignored 'struct ifinfomsg':

    NLMSGHDR (type=RTM_NEWLINK)
    |
    |-{IfInfoMsg}
    |
    |-IFLA_IFNAME = <user-provided ifname>
    |
    |-IFLA_LINKINFO
      |
      |-IFLA_INFO_KIND = "vti"
      |
      |-IFLA_INFO_DATA
        |
        |-IFLA_VTI_LOCAL = <local addr>
        |-IFLA_VTI_REMOTE = <remote addr>
        |-IFLA_VTI_LINK = ????
        |-IFLA_VTI_OKEY = [outbound mark]
        |-IFLA_VTI_IKEY = [inbound mark]
    """

    ifinfo = IfInfoMsg(ifi_family=socket.AF_UNSPEC).Pack()
    ifinfo += self._NlAttrStr(IFLA_IFNAME, dev_name)

    linkinfo = self._NlAttrStr(IFLA_INFO_KIND, "vti")

    ifdata = self._NlAttrIPAddress(IFLA_VTI_LOCAL, socket.AF_INET, local_addr)
    ifdata += self._NlAttrIPAddress(IFLA_VTI_REMOTE, socket.AF_INET,
                                    remote_addr)
    if i_key is not None:
      ifdata += self._NlAttrU32(IFLA_VTI_IKEY, i_key)
    if o_key is not None:
      ifdata += self._NlAttrU32(IFLA_VTI_OKEY, o_key)
    linkinfo += self._NlAttr(IFLA_INFO_DATA, ifdata)

    ifinfo += self._NlAttr(IFLA_LINKINFO, linkinfo)

    flags = netlink.NLM_F_REQUEST | netlink.NLM_F_CREATE | netlink.NLM_F_ACK
    return self._SendNlRequest(RTM_NEWLINK, ifinfo, flags)

  def DeleteTunnel(self, dev_name):
    ifinfo = IfInfoMsg(ifi_family=socket.AF_UNSPEC).Pack()
    ifinfo += self._NlAttrStr(IFLA_IFNAME, dev_name)
    flags = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK
    return self._SendNlRequest(RTM_DELLINK, ifinfo, flags)

  def GetIfIndex(self, dev_name):
    ifinfo = IfInfoMsg(ifi_family=socket.AF_UNSPEC).Pack()
    ifinfo += self._NlAttrStr(IFLA_IFNAME, dev_name)
    self._SendNlRequest(RTM_GETLINK, ifinfo, netlink.NLM_F_REQUEST)
    hdr, data = cstruct.Read(self._Recv(), netlink.NLMsgHdr)
    if hdr.type == RTM_NEWLINK:
      return IfInfoMsg(data).ifi_index
    elif hdr.type == netlink.NLMSG_ERROR:
      error = netlink.NLMsgErr(data).error
      raise IOError(error, os.strerror(-error))
