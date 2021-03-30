#!/bin/sh
#
# Copyright (C) 2021 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

trap "echo $? >${exitcode}" ERR EXIT

setup_networking() {
  # Bring up QEMU SLIRP networking
  ip link set dev eth0 up
  ip addr add 10.0.2.15/24 broadcast 10.0.2.255 dev eth0
  ip route add default via 10.0.2.2 dev eth0
  echo "nameserver 10.0.2.3" >>/etc/resolv.conf
}

cleanup() {
  echo "nameserver 127.0.0.1" >/etc/resolv.conf
  rm -f /root/* || true
  echo 0 >"${exitcode}"
  poweroff -f
}
