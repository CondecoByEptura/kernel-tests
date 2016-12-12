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

import contextlib
import errno
import fcntl
import resource
import os
from socket import *  # pylint: disable=wildcard-import
import struct
import threading
import time
import unittest

import csocket
import cstruct
import net_test

IPV4_LOOPBACK_ADDR = "127.0.0.1"
IPV6_LOOPBACK_ADDR = "::1"
LOOPBACK_DEV = "lo"
LOOPBACK_IFINDEX = 1

SIOCKILLADDR = 0x8939

DEFAULT_TCP_PORT = 8001
DEFAULT_BUFFER_SIZE = 20
DEFAULT_TEST_MESSAGE = "TCP NUKE ADDR TEST"
DEFAULT_TEST_RUNS = 100
HASH_TEST_RUNS = 4000
HASH_TEST_NOFILE = 16384


Ifreq = cstruct.Struct("Ifreq", "=16s16s", "name data")
In6Ifreq = cstruct.Struct("In6Ifreq", "=16sIi", "addr prefixlen ifindex")

def KillAddrIoctl(addr):
  """Calls the SIOCKILLADDR ioctl on the provided IP address.

  Args:
    addr The IP address to pass to the ioctl.

  Raises:
    ValueError: If addr is of an unsupported address family.
  """
  family, _, _, _, _ = getaddrinfo(addr, None, AF_UNSPEC, SOCK_DGRAM, 0,
                                   AI_NUMERICHOST)[0]
  if family == AF_INET6:
    addr = inet_pton(AF_INET6, addr)
    ifreq = In6Ifreq((addr, 128, LOOPBACK_IFINDEX)).Pack()
  elif family == AF_INET:
    addr = inet_pton(AF_INET, addr)
    sockaddr = csocket.SockaddrIn((AF_INET, 0, addr)).Pack()
    ifreq = Ifreq((LOOPBACK_DEV, sockaddr)).Pack()
  else:
    raise ValueError('Address family %r not supported.' % family)
  datagram_socket = socket(family, SOCK_DGRAM)
  try:
    fcntl.ioctl(datagram_socket.fileno(), SIOCKILLADDR, ifreq)
  finally:
    datagram_socket.close()

# For convenience.
def CreateIPv4SocketPair():
  return net_test.CreateSocketPair(AF_INET, SOCK_STREAM, IPV4_LOOPBACK_ADDR)

def CreateIPv6SocketPair():
  return net_test.CreateSocketPair(AF_INET6, SOCK_STREAM, IPV6_LOOPBACK_ADDR)


class TcpNukeAddrTest(net_test.NetworkTest):

  def CheckNukeAddrUnsupported(self, socketpair, addr):
    """Tests that SIOCKILLADDR no longer exists."""
    s1, s2 = socketpair
    self.assertRaisesErrno(errno.ENOTTY, KillAddrIoctl, addr)
    data = "foo"
    try:
      self.assertEquals(len(data), s1.send(data))
      self.assertEquals(data, s2.recv(4096))
      self.assertSocketsNotClosed(socketpair)
    finally:
      s1.close()
      s2.close()

  def assertSocketsNotClosed(self, socketpair):
    for sock in socketpair:
      self.assertTrue(sock.getpeername())

  def testIpv4Unsupported(self):
    self.CheckNukeAddrUnsupported(CreateIPv4SocketPair(), IPV4_LOOPBACK_ADDR)
    self.CheckNukeAddrUnsupported(CreateIPv4SocketPair(), "0.0.0.0")

  def testIpv6Unsupported(self):
    self.CheckNukeAddrUnsupported(CreateIPv6SocketPair(), IPV6_LOOPBACK_ADDR)
    self.CheckNukeAddrUnsupported(CreateIPv4SocketPair(), "::")


if __name__ == "__main__":
  unittest.main()
