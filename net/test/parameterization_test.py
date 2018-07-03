#!/usr/bin/python
#
# Copyright 2018 The Android Open Source Project
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
import unittest

import net_test
import util


def InjectTests():
  ParmeterizationTest.InjectTests()


# This test class ensures that the Parameterized Test generator in utils.py
# works properly. It injects test methods into itself, and ensures that they
# are generated as expected, and that the TestClosures being run are properly
# defined, and running different parameterized tests each time.
class ParmeterizationTest(net_test.NetworkTest):
  tests_run_list = list()

  @staticmethod
  def NameGenerator(a, b, c):
    return str(a) + "_" + str(b) + "_" + str(c)

  @classmethod
  def InjectTests(cls):
    PARAMS_A = (1, 2)
    PARAMS_B = (3, 4)
    PARAMS_C = (5, 6)

    param_list = itertools.product(PARAMS_A, PARAMS_B, PARAMS_C)
    util.InjectParameterizedTest(cls, param_list, cls.NameGenerator)

  def ParamTestDummyFunc(self, a, b, c):
    self.tests_run_list.append(
        "testDummyFunc_" + ParmeterizationTest.NameGenerator(a, b, c))

  def testParameterization(self):
    # Get a list of added functions
    test_names = [
        name for name in dir(self.__class__) if name.startswith("testDummyFunc")
    ]

    # Verify that the count is correct - this implicitly verifies that the
    # names are different for each test iteration.
    self.assertEqual(8, len(test_names))

    # Start a clean list, and run all the tests.
    self.tests_run_list = list()
    for test_name in test_names:
      getattr(self, test_name)()

    # Make sure all tests have been run with the correct parameters
    for test_name in test_names:
      self.assertTrue(test_name in self.tests_run_list)


if __name__ == "__main__":
  ParmeterizationTest.InjectTests()
  unittest.main()
