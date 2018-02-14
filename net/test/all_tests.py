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

from importlib import import_module
import inspect
import sys
import unittest

test_modules = [
    'anycast_test',
    'bpf_test',
    'csocket_test',
    'cstruct_test',
    'forwarding_test',
    'leak_test',
    'multinetwork_test',
    'neighbour_test',
    'pf_key_test',
    'ping6_test',
    'qtaguid_test',
    'removed_feature_test',
    'resilient_rs_test',
    'sock_diag_test',
    'srcaddr_selection_test',
    'tcp_fastopen_test',
    'tcp_nuke_addr_test',
    'tcp_test',
    'xfrm_test',
    'xfrm_tunnel_test',
]

parameterized_test_modules = [
    'xfrm_algorithm_test',
]

def isTestClass(x):
  return inspect.isclass(x) and x.__name__.endswith("Test")

if __name__ == '__main__':
  loader = unittest.defaultTestLoader
  test_suite = loader.loadTestsFromNames(test_modules)

  # Trigger parameterized test injections
  for name in parameterized_test_modules:
    # Get module
    module = import_module(name)

    # Get classes in module
    testClasses = inspect.getmembers(module, isTestClass)

    # Inject tests for each test class in module
    for testClass in testClasses:
      injectTestsMethod = getattr(testClass[1], "InjectTests", None)
      if injectTestsMethod is None:
        raise TypeError("Parameterized test %s was missing InjectTests method" % testClass[0])
      injectTestsMethod()

      # Manually add to test suite
      test_suite.addTest(unittest.TestLoader().loadTestsFromTestCase(testClass[1]))

  runner = unittest.TextTestRunner(verbosity=2)
  sys.exit(runner.run(test_suite))
