#!/bin/bash
#
# Copyright (C) 2022 The Android Open Source Project
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

. $SCRIPT_DIR/bullseye-common.sh

arch=$(uname -m)
[ "${arch}" = "x86_64" ] && arch=amd64

setup_dynamic_networking "en*" ""

if [ "${arch}" = "amd64" ]; then
  # Install apt-key for packages.cloud.google.com
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -

  # Enable cloud-sdk repository
  cat >/etc/apt/sources.list.d/google-cloud-sdk.list <<EOF
deb https://packages.cloud.google.com/apt cloud-sdk main
EOF
fi

update_apt_sources "bullseye bullseye-backports"

if [ "${arch}" = "amd64" ]; then
  # Enable non-free for the NVIDIA driver
  add-apt-repository non-free
  apt-get update
fi

setup_cuttlefish_user

# Get kernel and QEMU from backports
for package in linux-image-cloud-${arch} qemu-system-arm qemu-system-x86; do
  apt-get install -y -t bullseye-backports ${package}
done

# Compute the linux-image-cloud version installed
kver=$(dpkg -s linux-image-cloud-${arch} | \
       grep ^Version: | cut -d: -f2 | tr -d ' ')
ksrcver=$(echo ${kernel_version} | cut -d. -f-2)

# Get kernel headers and sources from backports
for package in linux-headers-${kver}-${arch} linux-source-${ksrcver}; do
  apt-get install -y -t bullseye-backports ${package}
done

if [ "${arch}" = "amd64" ]; then
  # Get NVIDIA driver and dependencies from backports/non-free
  for package in firmware-misc-nonfree libglvnd-dev libvulkan1 nvidia-driver; do
    apt-get install -y -t bullseye-backports ${package}
  done
fi

get_installed_packages >/root/originally-installed

setup_and_build_cuttlefish

get_installed_packages >/root/installed

remove_installed_packages /root/originally-installed /root/installed

install_and_cleanup_cuttlefish

create_systemd_getty_symlinks ttyS0 hvc1

apt-get purge -y vim-tiny
bullseye_cleanup
