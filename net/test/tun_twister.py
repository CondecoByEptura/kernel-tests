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
"""A utility for "twisting" packets on a tun/tap interface.

TunTwister echoes packets on a tun/tap while swapping the source and destination
at the ethernet and IP layers. This allows sockets to effectively loop back
packets through the full networking stack, avoiding any shortcuts the kernel may
take for actual IP loopback. Additionally, TunTwister can inspect each packet to
assert testing invariants.
"""

import os
import select
import threading
from scapy import all as scapy


class TunTwister(object):
  """Test util for tun/tap interfaces.

  A TunTwister will read packets from the tun/tap file descriptor, swap the
  source and dest of the ethernet and IP headers, and write them back. Setting
  up routing such that packets will be routed to the tun/tap interface is beyond
  the scope of this class.

  A TunTwister will not begin work until Start() is called. Packet processing
  happens in another thread, which must be stopped at the end of your test by
  calling Stop(). TunTwister objects are not reusable.

  Packet inspection can be done with a validator function. This can be any
  function that takes a scapy packet object as its only argument.

  EXAMPLE:
    def testFeatureFoo(self):
      my_tun = MakeTunInterface()
      def ValidatePortNumber(packet):
        self.assertEquals(8080, packet.getlayer(scapy.UDP).sport)
        self.assertEquals(8080, packet.getlayer(scapy.UDP).dport)

      twister = TunTwister(tun_fd=my_tun, validator=ValidatePortNumber)
      twister.Start()
      sock = socket(AF_INET, SOCK_DGRAM, 0)
      sock.bind(("0.0.0.0", 8080))
      sock.sendto("hello", ("1.2.3.4", 8080))
      data, addr = sock.recvfrom(1024)
      self.assertEquals("hello", data)
      self.assertEquals(("1.2.3.4", 8080), addr)
      twister.Stop()
  """
  _TUN = 0
  _TAP = 1

  def __init__(self, tun_fd=None, tap_fd=None, validator=None):
    """Construct a TunTwister.

    The TunTwister will listen on a TUN or a TAP, depending on which one is
    provided. The validator function is called with each packet *before*
    twisting.

    Args:
      tun_fd: File descriptor of a TUN interface.
      tap_fd: File descriptor of a TAP interface.
      validator: Function taking one scapy object argument.
    Raises:
      ValueError: if none or both of tun_fd and tap_fd are set.
    """
    if tun_fd and tap_fd:
      raise ValueError("Must provide one of tun_fd or tap_fd")
    if tun_fd:
      self._fd = tun_fd
      self._type = self._TUN
    elif tap_fd:
      self._fd = tap_fd
      self._type = self._TAP
    else:
      raise ValueError("Must provide a tun_fd or tap_fd")
    # Use a pipe to signal the thread to exit.
    self._pipe_r, self._pipe_w = os.pipe()
    self._thread = threading.Thread(target=self._RunLoop)
    self._validator = validator

  def Start(self):
    """Begin twisting packets on the tun/tap."""
    self._thread.start()

  def Stop(self):
    """Halt twisting of packets on the tun/tap."""
    if not self._thread.isAlive():
      return
    os.write(self._pipe_w, "\x00")
    os.close(self._pipe_w)
    self._thread.join(1.0)
    os.close(self._pipe_r)
    if self._thread.isAlive():
      raise RuntimeError("Thread did not exit gracefully")

  def _RunLoop(self):
    while True:
      read_fds, _, _ = select.select([self._fd, self._pipe_r], [], [], 2.0)
      if self._pipe_r in read_fds:
        self._Flush()
        return
      if self._fd in read_fds:
        self._ProcessPacket()

  def _Flush(self):
    """Ensure no packets are left in the buffer."""
    p = select.poll()
    p.register(self._fd, select.POLLIN)
    while p.poll(0.1):
      self._ProcessPacket()

  def _ProcessPacket(self):
    """Read, twist, and write one packet on the tun/tap."""
    bytes_in = os.read(self._fd, 2048)
    if self._type == TunTwister._TAP:
      packet = scapy.Ether(bytes_in)
    else:
      packet = self._DecodeIpPacket(bytes_in)
    if self._validator:
      self._validator(packet)
    packet = self._TwistPacket(packet)
    os.write(self._fd, packet.build())

  @staticmethod
  def _TwistPacket(packet):
    """Swap the src and dst in ethernet and IP headers."""
    if isinstance(packet, scapy.Ether):
      eth_layer = packet
      ip_layer = packet.payload
    else:
      eth_layer = None
      ip_layer = packet

    ip_type = type(ip_layer)
    if ip_type not in (scapy.IP, scapy.IPv6):
      raise TypeError("Expected an IPv4 or IPv6 packet.")
    ip_layer.src, ip_layer.dst = ip_layer.dst, ip_layer.src
    ip_layer = ip_type(ip_layer.build())  # Fix the IP checksum.

    if eth_layer:
      eth_layer.src, eth_layer.dst = eth_layer.dst, eth_layer.src
      eth_layer.payload = ip_layer
      packet = eth_layer
    else:
      packet = ip_layer

    return packet

  @staticmethod
  def _DecodeIpPacket(packet_bytes):
    """Decode 'packet_bytes' as an IPv4 or IPv6 scapy object."""
    ip_ver = (ord(packet_bytes[0]) & 0xF0) >> 4
    if ip_ver == 4:
      return scapy.IP(packet_bytes)
    elif ip_ver == 6:
      return scapy.IPv6(packet_bytes)
    else:
      raise ValueError("packet_bytes is not a valid IPv4 or IPv6 packet")
