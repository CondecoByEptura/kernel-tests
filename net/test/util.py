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

def GetPadLength(block_size, length):
  return (block_size - (length % block_size)) % block_size

def InjectParameterizedTest(cls, param_list, name_generator):
  """Injects parameterized tests into the provided class

  This method searches for all tests that start with the name "ParamTest",
  and injects a test method for each pair of parameters in param_list. Names
  are generated via the use of the name_generator.

  Args:
    cls: the class for which to inject all paramterized tests
    param_list: a 2d array of parameters for each test run
    name_generator: the function to generate parameterized test names
  """
  param_test_names = [name for name in dir(cls) if name.startswith("ParamTest")]

  # Parameterize each test method starting with "ParamTest"
  for test_name in param_test_names:
    func = getattr(cls, test_name)

    for params in param_list:
      # Generate the actual test method.
      def TestClosure(self):
        func(self, *params)

      # Give the test method a readable, debuggable name.
      param_string = name_generator(*params)
      new_name = "%s_%s" % (func.__name__.replace("ParamTest", "test"),
                            param_string)
      new_name = new_name.replace("(", "-").replace(")", "")  # remove parens

      # Inject the test method
      setattr(cls, new_name, TestClosure)