#!/usr/bin/python
#
# Copyright 2016 The Android Open Source Project
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

import os
import re
import unittest


class TraceEventTest(unittest.TestCase):
  """Test to verify trace event formats.

  Relevant kernel commits:
    android-3.4:  ff9bc1a trace: net: use %pK for kernel pointers
    android-3.10: 0020e17 trace: net: use %pK for kernel pointers
    android-3.14: a851f1b trace: net: use %pK for kernel pointers
    android-3.18: 6c038b6 trace: net: use %pK for kernel pointers
    android-4.1:  e064d11 trace: net: use %pK for kernel pointers
    android-4.4:  676b8ef trace: net: use %pK for kernel pointers
  """
  SUSPECT_POINTER_FORMAT = re.compile("%p[^KMm]")
  TRACING_BASE_PATH = "/debug/tracing/events"
  FORMAT_FILE_NAME = "format";
  # This list should be kept in sync with wifi-events.rc.
  TRACE_EVENTS = (
      "cfg80211/cfg80211_gtk_rekey_notify",
      "cfg80211/rdev_add_key",
      "cfg80211/rdev_assoc",
      "cfg80211/rdev_auth",
      "cfg80211/rdev_connect",
      "cfg80211/rdev_set_default_key",
      "cfg80211/rdev_set_power_mgmt",
      "cfg80211/rdev_set_rekey_data",
      "net/net_dev_queue",
      "net/net_dev_xmit",
      "net/netif_rx",
      "net/netif_receive_skb",
  )

  def testEventsDoNotExposeSuspectPointers(self):
    for trace_event in self.TRACE_EVENTS:
      trace_event_format_path = os.path.join(
          self.TRACING_BASE_PATH, trace_event, self.FORMAT_FILE_NAME)
      self.assertTrue(os.path.exists(trace_event_format_path),
                      "Missing path " + trace_event_format_path)
      with open(trace_event_format_path) as trace_event_format_file:
        trace_event_description = trace_event_format_file.read()
        self.assertFalse(
            self.SUSPECT_POINTER_FORMAT.search(trace_event_description),
            "Suspicious pointer format found for %s, in %s" % (
                trace_event, trace_event_description))


if __name__ == "__main__":
  unittest.main()
