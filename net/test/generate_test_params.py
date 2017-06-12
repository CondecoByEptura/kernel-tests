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
"""Generate XFRM socket policy test parameters.

This modules generates a series of test parameters and formats them as a JSON
object. The parameters are not generated on the fly because they rely on python
modules not available/updated in net_test.rootfs.20150203.
"""

import sys
from collections import defaultdict
import os
import json
from scapy import all as scapy


# Various constant fields used in test packets.
SPI_OUT = 0xBEEFCAFE
MSG_OUT = "hello from local"
REQ_OUT = 456
SPI_IN = 0xF00DFACE
MSG_IN = "hello from remote"
REQ_IN = 123

# TODO: v6
LOCAL_ADDR = "10.0.100.2"
LOCAL_PORT = 6666
REMOTE_ADDR = "8.8.8.8"
REMOTE_PORT = 7777

# Tuple of name, key size.
CRYPT_ALGS = [
    ("AES-CBC", 256),
    ("AES-CBC", 192),
    ("AES-CBC", 128),
]
# Names used by XFRM.
CRYPT_NAMES = {
    "AES-CBC":"cbc(aes)",
}
# Tuple of name, key size, truncation length.
# TODO: More truncation lengths.
AUTH_ALGS = [
    ("HMAC-MD5-96", 128, 96),
    ("HMAC-SHA1-96", 160, 96),
    ("SHA2-256-128", 256, 128),
    ("SHA2-384-192", 384, 192),
    ("SHA2-512-256", 512, 256),
]
# Names used by XFRM.
AUTH_NAMES = {
    "HMAC-MD5-96": "hmac(md5)",
    "HMAC-SHA1-96": "hmac(sha1)",
    "SHA2-256-128": "hmac(sha256)",
    "SHA2-384-192": "hmac(sha384)",
    "SHA2-512-256": "hmac(sha512)",
}

PROTOS = [scapy.UDP, scapy.TCP]


# Recursively nesting defaultdict helper.
NestedDict = lambda: defaultdict(NestedDict)


def MakeKey(len_bits):
  """Generate a key of the given length.

  This doesn't need to be securely random because the keys are used in tests.
  """
  assert len_bits % 8 == 0, (
      "Key length unexpected. Wanted a multiple of 8, got {}".format(len_bits))
  return os.urandom(len_bits / 8)

def MakeUdpOut():
  return scapy.UDP(sport=LOCAL_PORT, dport = REMOTE_PORT) / MSG_OUT
def MakeUdpIn():
  return scapy.UDP(sport=REMOTE_PORT, dport=LOCAL_PORT) / MSG_IN
def MakeTcpOut():
  return scapy.TCP(sport=LOCAL_PORT, dport=REMOTE_PORT, flags="S") / ""
def MakeTcpIn():
  return scapy.TCP(sport=REMOTE_PORT, dport=LOCAL_PORT, flags="S") / ""


def GenerateTest(ealgo, ekey_size, aalgo, akey_size, atrunc_len,proto):
  ekey_in = MakeKey(ekey_size)
  akey_in = MakeKey(akey_size)
  ekey_out = MakeKey(ekey_size)
  akey_out = MakeKey(akey_size)
  if proto == scapy.UDP:
    payload_in = MakeUdpIn()
    payload_out = MakeUdpOut()
    payload_type = "UDP"
  elif proto == scapy.TCP:
    payload_in = MakeTcpIn()
    payload_out = MakeTcpOut()
    payload_type = "TCP"
  sa_in = scapy.SecurityAssociation(
      proto=scapy.ESP,
      spi=SPI_IN,
      crypt_algo=ealgo,
      crypt_key=ekey_in,
      auth_algo=aalgo,
      auth_key=akey_in)
  # Put a dummy IP header on the payload which will be discarded.
  esp_in = sa_in.encrypt(scapy.IP(src="1.1.1.1", dst="2.2.2.2") / payload_in)
  params = NestedDict()
  params["IN"]["crypt"]["algo"] = CRYPT_NAMES[ealgo]
  params["IN"]["crypt"]["key"] = ekey_in.encode("hex")
  params["IN"]["auth"]["algo"] = AUTH_NAMES[aalgo]
  params["IN"]["auth"]["key"] = akey_in.encode("hex")
  params["IN"]["sa"]["spi"] = sa_in.spi
  params["IN"]["auth"]["trunc_len"] = atrunc_len
  params["IN"]["packet"]["inner_type"] = payload_type
  params["IN"]["packet"]["expected_data"] = payload_in.payload.build()
  params["IN"]["packet"]["esp_input"] = esp_in.getlayer(scapy.ESP).build().encode("hex")
  params["name"] = "{}-{} {}-{}-{} {}".format(CRYPT_NAMES[ealgo], ekey_size, AUTH_NAMES[aalgo], akey_size, atrunc_len, proto.__name__)
  return params


def GenerateTestParameters():
  tests = []
  for ealgo, ekey_size in CRYPT_ALGS:
    for aalgo, akey_size, atrunc_len in AUTH_ALGS:
      for proto in PROTOS:
        tests.append(GenerateTest(ealgo, ekey_size, aalgo, akey_size, atrunc_len, proto))
  return tests


def main():
  json.dump(GenerateTestParameters(), sys.stdout, indent=2)


if __name__ == '__main__':
  main()
