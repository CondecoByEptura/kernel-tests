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

TODO(misterikkit): Rest of the description.
"""

import os
from select import select
import threading
from scapy import all as scapy


class Error(Exception):
  pass


class TunTwister(object):
  _TUN = 0
  _TAP = 1

  def __init__(self, tun_fd=None, tap_fd=None, validator=None):
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
    self._thread = threading.Thread(target=self.RunLoop)

  def Start(self):
    if self._thread.isAlive():
      raise Exception("Thread is already running")
    self._thread.start()

  def Stop(self):
    if not self._thread.isAlive():
      raise Exception("Thread is not running")
    os.write(self._pipe_w, "\x00")
    self._thread.join(1.0)
    if self._thread.isAlive():
      raise Exception("Thread did not exit gracefully")

  def RunLoop(self):
    while True:
      read_fds, _, _ = select([self._fd, self._pipe_r], [], [], 10.0)
      if self._pipe_r in read_fds:
        os.read(self._pipe_r, 128)  # Flush the pipe.
        return
      if self._fd in read_fds:
        self.ProcessPacket()

  def ProcessPacket(self):
    """Read, twist, and write one packet on the tun/tap."""
    bytes_in = os.read(self._fd, 1024)
    if self._type == TunTwister._TAP:
      packet = scapy.Ether(bytes_in)
    else:
      packet = self._GuessIpVersion(bytes_in)
    packet = self._TwistPacket(packet)
    os.write(self._fd, packet.build())

  @staticmethod
  def _TwistPacket(packet):
    if type(packet) is scapy.Ether:
      eth_layer = packet
      ip_layer = packet.payload
    else:
      eth_layer = None
      ip_layer = packet

    ip_type = type(ip_layer)
    if ip_type not in (scapy.IP, scapy.IPv6):
      raise TypeError("Expected an IPv4 or IPv6 packet.")
    ip_layer.src, ip_layer.dst = ip_layer.dst, ip_layer.src
    # Fix the IP checksum
    ip_layer = ip_type(ip_layer.build())

    if eth_layer:
      eth_layer.src, eth_layer.dst = eth_layer.dst, eth_layer.src
      eth_layer.payload = ip_layer
      packet = eth_layer
    else:
      packet = ip_layer

    return packet

  # TODO: rename this
  @staticmethod
  def _GuessIpVersion(packet_bytes):
    ip_ver = (ord(packet_bytes[0]) & 0xF0) >> 4
    if ip_ver == 4:
      return scapy.IP(packet_bytes)
    elif ip_ver == 6:
      return scapy.IPv6(packet_bytes)
    else:
      raise ValueError("ip_packet is not a valid IPv4 or IPv6 packet")
