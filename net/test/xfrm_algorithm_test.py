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

import multinetwork_base
import xfrm

XFRM_ADDR_ANY = 16 * "\x00"
ALL_ALGORITHMS = 0xffffffff


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
      test_parameters = json.load(f, object_hook=DotDict)
    for params in test_parameters:
      assert "name" in params, "Missing name: " + params
      # Create the test case method.
      def TestClosure(self):
        self.RunAlgorithmTest(params)

      TestClosure.__name__ = "testAlgorithm({})".format(params.name)
      assert not hasattr(
          cls, TestClosure.__name__), "Duplicate test name: " + params.name
      # Add the method to this class.
      setattr(cls, TestClosure.__name__, TestClosure)

  def RunAlgorithmTest(self, params):
    # Determine network parameters.
    netid = self.NETIDS[0]
    local_addr = self.MyAddress(4, netid)
    remote_addr = self.GetRemoteAddress(4)

    # Unpack test parameters.
    pkt_in = scapy.IP(src=remote_addr, dst=local_addr) / params.IN.packet.esp_input.decode("hex")
    ekey = params.IN.crypt.key.decode("hex")
    akey = params.IN.auth.key.decode("hex")
    ealgo = xfrm.XfrmAlgo(name=params.IN.crypt.algo, key_len=8 * len(ekey))
    aalgo = xfrm.XfrmAlgoAuth(
        name=params.IN.auth.algo,
        key_len=8 * len(akey),
        trunc_len=params.IN.auth.trunc_len)


    # Open a socket and bind to the expected port.
    if params.IN.packet.inner_type == "UDP":
      s = socket(AF_INET, SOCK_DGRAM, 0)
    elif params.IN.packet.inner_type == "TCP":
      s = socket(AF_INET, SOCK_STREAM, 0)
    else:
      self.fail("Unexpected socket type")
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
    # Create an inbound socket policy.
    selector = xfrm.XfrmSelector(
        daddr=XFRM_ADDR_ANY, saddr=XFRM_ADDR_ANY, family=AF_INET)
    policy = xfrm.XfrmUserpolicyInfo(
        sel=selector,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        dir=xfrm.XFRM_POLICY_IN,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_UNIQUE)
    # SPI in XfrmId is expected in network byte order.
    xfrmid = xfrm.XfrmId(
        daddr=XFRM_ADDR_ANY, spi=htonl(0xdeadbeef), proto=IPPROTO_ESP)
    template = xfrm.XfrmUserTmpl(
        id=xfrmid,
        family=AF_INET,
        saddr=XFRM_ADDR_ANY,
        reqid=314,
        mode=xfrm.XFRM_MODE_TRANSPORT,
        share=xfrm.XFRM_SHARE_UNIQUE,
        optional=0,  #require
        aalgos=ALL_ALGORITHMS,
        ealgos=ALL_ALGORITHMS,
        calgos=ALL_ALGORITHMS)

    # Apply the inbound socket policy.
    opt_data = policy.Pack() + template.Pack()
    s.setsockopt(IPPROTO_IP, xfrm.IP_XFRM_POLICY, opt_data)

    # Decrypt and read the packet!
    self.ReceivePacketOn(netid, pkt)
    s.settimeout(1)
    msg, remote_sockaddr = s.recvfrom(4000)
    self.assertEquals("hello", msg)
    self.assertEquals(remote_addr, remote_sockaddr[0])
    self.assertEquals(6666, remote_sockaddr[1])


XfrmAlgorithmTest.InjectTests()  # Injecting must come before unittest.main().

if __name__ == "__main__":
  unittest.main()
