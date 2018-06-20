#!/bin/sh
#
# Copyright (C) 2018 The Android Open Source Project
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

cleanup() {
  # Read-only root breaks booting via init
  cat >/etc/fstab << EOF
tmpfs /tmp     tmpfs defaults 0 0
tmpfs /var/log tmpfs defaults 0 0
tmpfs /var/tmp tmpfs defaults 0 0
EOF

  # Keep systemd happy (this also works for legacy init)
  ln -sf ../proc/self/mounts /etc/mtab

  # Remove comtaminants coming from the debootstrap process
  echo vm >/etc/hostname
  echo "nameserver 127.0.0.1" >/etc/resolv.conf

  # Put the helper net_test.sh script into place
  mv /root/net_test.sh /sbin/net_test.sh

  # Make sure the /host mountpoint exists for net_test.sh
  mkdir /host

  # Disable the root password
  passwd -d root

  # Clean up any junk created by the imaging process
  rm -rf /var/lib/apt/lists/* /var/log/bootstrap.log /root/* /tmp/*
  find /var/log -type f -exec rm -f '{}' ';'
}
