#!/bin/bash
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

set -e
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

. $SCRIPT_DIR/common.sh
. $SCRIPT_DIR/bullseye-common.sh

# So isc-dhcp-client can work with a read-only rootfs..
cat >>/etc/fstab <<EOF
tmpfs /var/lib/dhcp tmpfs defaults 0 0
EOF

# Bring up networking one time with dhclient
mount /var/lib/dhcp
dhclient eth0
echo "nameserver 8.8.8.8"  >/run/resolvconf/resolv.conf
echo "nameserver 8.8.4.4" >>/run/resolvconf/resolv.conf

update_apt_sources bullseye

# Set up automatic DHCP for future boots
cat >/etc/systemd/network/dhcp.network <<EOF
[Match]
Name=en*

[Network]
DHCP=yes
EOF

# Mask the NetworkManaher-wait-online service to prevent hangs
systemctl mask NetworkManager-wait-online.service

# Add a default user and put them in the right group
addgroup --system cvdnetwork
useradd -m -G cvdnetwork,kvm,sudo -d /home/vsoc-01 --shell /bin/bash vsoc-01

# Set a root password so SSH can work
echo -e "cuttlefish\ncuttlefish" | passwd
echo -e "cuttlefish\ncuttlefish" | passwd vsoc-01

# Fetch android-cuttlefish and build it for cuttlefish-common
git clone https://github.com/google/android-cuttlefish.git /usr/src/android-cuttlefish
cd /usr/src/android-cuttlefish
  apt-get install -y -f libc6:amd64 qemu-user-static
  dpkg-buildpackage -d -uc -us
cd -
cd /usr/src
  apt-get install -y -f ./cuttlefish-common_*.deb
  # Tidy up the mess we left behind, leaving just the source tarballs
  rm -rf android-cuttlefish *.buildinfo *.changes *.deb *.dsc
cd -

get_installed_packages >/root/originally-installed
setup_and_build_iptables
get_installed_packages >/root/installed
remove_installed_packages /root/originally-installed /root/installed
install_and_cleanup_iptables

create_systemd_getty_symlinks ttyS0 hvc1

cleanup
