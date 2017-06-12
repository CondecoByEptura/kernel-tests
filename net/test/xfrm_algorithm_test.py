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

import json
import unittest
from scapy import all as scapy
from socket import *  # pylint: disable=wildcard-import
from functools import wraps

import multinetwork_base
import xfrm


class DotDict(dict):
  """A modified dict class that allows access through the dot operator.

  This is a convenience for working with JSON objects. e.g.
      my_obj = json.loads(text, object_hook=DotDict)
      my_obj[0].id.name  # Instead of my_obj[0]["id"]["name"]
  """

  def __getattr__(self, field):
    value = self[field]
    if type(value) is unicode:
      # Force unicode strings (default) into plain strings.
      return value.encode("utf-8")
    return value

  def __setattr__(self, field, value):
    self[field] = value


class XfrmAlgorithmTest(multinetwork_base.MultiNetworkBaseTest):

  def setUp(self):
    super(XfrmAlgorithmTest, self).setUp()
    self.xfrm = xfrm.Xfrm()
    # TODO: warn if there is anything that needs cleaning up.
    self.xfrm.FlushSaInfo()

  def tearDown(self):
    super(XfrmAlgorithmTest, self).tearDown()
    # TODO: assert that state and policy have been cleaned up.
    self.xfrm.FlushSaInfo()

  # Wouldn't it be nice if we could use @parameterized?
  # TODO: Figure out some cheap approximation of @parameterized.
  @classmethod
  def InjectTests(cls):
    """Inject parameterized test cases into this class.

    Because a library for parameterized testing is not availble in
    net_test.rootfs.20150203, this does a minimal parameterization. An array of
    parameter objects is read from 'xfrm_algorithm_tests.json' and one test
    method is added to the class for each one.

    The benefit of this approach is that an individually failing tests have a
    clearly separated stack trace, and one failed test doesn't prevent the rest
    from running.

    TODO: How to @skip selectively?
    """
    with file("xfrm_algorithm_tests.json") as f:
      test_parameters = json.load(f, object_hook=DotDict, encoding="utf-8")
    for params in test_parameters:

      @wraps(cls.RunAlgorithmTest)
      def runWithParams(self):
        self.RunAlgorithmTest(params)

      assert "name" in params, "Missing name: " + params
      runWithParams.__name__ = "testAlgorithm({})".format(params.name)
      assert not hasattr(
          cls, runWithParams.__name__), "Duplicate test name: " + params.name
      setattr(cls, runWithParams.__name__, runWithParams)

  def RunAlgorithmTest(self, params):
    pkt = scapy.IP(params.IN.ipv4_payload.decode("hex"))
    ekey = params.IN.crypt.key
    akey = params.IN.auth.key
    assert type(akey) is str, repr(akey)
    ealgo = xfrm.XfrmAlgo(name=params.IN.crypt.algo, key_len=8 * len(ekey))
    aalgo = xfrm.XfrmAlgoAuth(
        name=params.IN.auth.algo,
        key_len=8 * len(akey),
        trunc_len=params.IN.auth.trunc_len)

    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    remote_addr = self.GetRemoteAddress(4)

    # Open a socket and bind to the expected port.
    s = socket(AF_INET, SOCK_DGRAM, 0)
    s.bind(("0.0.0.0", 7777))

    # Create an inbound SA.
    # SPI in XfrmId is expected in network byte order.
    self.xfrm.AddMinimalSaInfo(
        src=remote_addr,
        dst=local_addr,
        spi=htonl(0xdeadbeef),
        proto=IPPROTO_ESP,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        reqid=314,
        encryption=ealgo,
        encryption_key=ekey,
        auth_trunc=aalgo,
        auth_trunc_key=akey,
        encap=None)
    # TODO: write rest of test


XfrmAlgorithmTest.InjectTests()  # Injecting must come before unittest.main().

if __name__ == "__main__":
  unittest.main()
