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
  param_test_names = [name for name in dir(cls) if name.startswith("ParamTest")]

  for test_name in param_test_names:
    func = getattr(cls, test_name)

    for params in param_list:
      def TestClosure(self):
        func(self, *params)

      param_string = name_generator(*params)
      new_name = "%s_%s" % (func.__name__.replace("ParamTest", "test"),
                            param_string)
      new_name = new_name.replace("(", "-").replace(")", "")  # remove parens

      setattr(cls, new_name, TestClosure)