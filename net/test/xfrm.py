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

"""Partial Python implementation of sock_diag functionality."""

# pylint: disable=g-bad-todo

import errno
import os
from socket import *  # pylint: disable=wildcard-import
import struct

import csocket
import cstruct
import net_test
import netlink

IP_IPSEC_POLICY = 16
IP_XFRM_POLICY = 17
IPV6_IPSEC_POLICY = 34
IPV6_XFRM_POLICY = 35

# Actions.
XFRM_POLICY_ALLOW = 0
XFRM_POLICY_BLOCK = 1

XFRM_POLICY_IN = 0
XFRM_POLICY_OUT = 1

XFRM_SHARE_ANY     = 0  #  /* No limitations */
XFRM_SHARE_SESSION = 1  #  /* For this session only */
XFRM_SHARE_USER    = 2  #  /* For this user only */
XFRM_SHARE_UNIQUE  = 3  #  /* Use once */

# Modes
XFRM_MODE_TRANSPORT = 0
XFRM_MODE_TUNNEL = 1
XFRM_MODE_ROUTEOPTIMIZATION = 2
XFRM_MODE_IN_TRIGGER = 3
XFRM_MODE_BEET = 4
XFRM_MODE_MAX = 5

# Flags.
XFRM_POLICY_LOCALOK = 1
XFRM_POLICY_ICMP = 2


# Data structure formats.
# These aren't constants, they're classes. So, pylint: disable=invalid-name
XfrmSelector = cstruct.Struct(
    "XfrmSelector", "=16s16sHHHHHBBBxxxiI",
    "daddr saddr dport dport_mask sport sport_mask "
    "family prefixlen_d prefixlen_s proto ifindex user")

XfrmLifetimeCfg = cstruct.Struct(
    "XfrmLifetimeCfg", "=QQQQQQQQ",
    "soft_byte hard_byte soft_packet hard_packet "
    "soft_add_expires hard_add_expires soft_use_expires hard_use_expires")

XfrmLifetimeCur = cstruct.Struct(
    "XfrmLifetimeCur", "=QQQQ", "bytes packets add_time use_time")

XfrmUserpolicyInfo = cstruct.Struct(
    "XfrmUserpolicyInfo", "=SSSIIBBBBxxxx",
    "sel lft curlft priority index dir action flags share",
    [XfrmSelector, XfrmLifetimeCfg, XfrmLifetimeCur])

XfrmId = cstruct.Struct("XfrmId", "=16sIBxxx", "daddr spi proto")

XfrmUserTmpl = cstruct.Struct(
    "XfrmUserTmpl", "=SHxx16sIBBBxIII",
    "id family saddr reqid mode share optional aalgos ealgos calgos",
    [XfrmId])


def RawAddress(addr):
  """Converts an IP address string to binary format."""
  family = AF_INET6 if ":" in addr else AF_INET
  return inet_pton(family, addr)

def PaddedAddress(addr):
  """Converts an IP address string to binary format for InetDiagSockId."""
  padded = RawAddress(addr)
  if len(padded) < 16:
    padded += "\x00" * (16 - len(padded))
  return padded


if __name__ == "__main__":
  pass
