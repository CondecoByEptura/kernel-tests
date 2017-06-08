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

import multinetwork_base
import random
import struct
import xfrm

class XfrmBaseTest(multinetwork_base.MultiNetworkBaseTest):
  _ENCRYPTION_KEY_256 = ("308146eb3bd84b044573d60f5a5fd159"
                     "57c7d4fe567a2120f35bae0f9869ec22".decode("hex"))
  _AUTHENTICATION_KEY_128 = "af442892cdcd0ef650e9c299f9a8436a".decode("hex")

  _ALL_ALGORITHMS = 0xffffffff
  _ALGO_CBC_AES_256 = xfrm.XfrmAlgo(("cbc(aes)", 256))
  _ALGO_HMAC_SHA1 = xfrm.XfrmAlgoAuth(("hmac(sha1)", 128, 96))

  def setUp(self):
    super(XfrmBaseTest, self).setUp()

  def tearDown(self):
    super(XfrmBaseTest, self).tearDown()

  def _RandomNetid(self):
      return random.choice(self.NETIDS)
