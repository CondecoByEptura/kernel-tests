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

# Install required tool/packages
apt-get update
apt-get install xz-utils -y

if [ "${arch}" = "amd64" ]; then
  # apt-key error, need gnupg package install
  apt-get install curl -y
  apt-get install gnupg -y

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
  # add-apt-repository non-free
  # we need "contrib" as well
  sed -e "s/$/ contrib non-free/" -i /etc/apt/sources.list
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
# ksrcver=$(echo ${kernel_version} | cut -d. -f-2)
# ${kernel_version} is missing, probably it is a typo
ksrcver=$(echo ${kver} | cut -d. -f-2)

# if it can't find headers by original method, this is the new method to defind headers
headers=$(apt-cache search linux-headers-${kver}-${arch})
if [ "${headers}" = "" ]; then
  headers=$(dpkg -s linux-image-cloud-${arch} | \
    grep ^Depends: | cut -d: -f2 | cut -f2 -d" " | \
    sed "s/image/headers/" | sed "s/cloud-//")
fi

# Get kernel headers and sources from backports
for package in ${headers} linux-source-${ksrcver}; do
  apt-get install -y -t bullseye-backports ${package}
done

if [ "${arch}" = "amd64" ]; then
  # Get NVIDIA driver and dependencies from backports/non-free
  for package in firmware-misc-nonfree libglvnd-dev libvulkan1; do
    apt-get install -y -t bullseye-backports ${package}
  done

  # NVIDIA driver needs dkms which requires /dev/fd
  if [ ! -d /dev/fd ]; then
    ln -s /proc/self/fd /dev/fd
  fi
  # add noninteractive because config-keyboard package will ask 22+ keyboard options
  DEBIAN_FRONTEND=noninteractive apt-get install -y -t bullseye-backports nvidia-driver
fi

get_installed_packages >/root/originally-installed

setup_and_build_cuttlefish

get_installed_packages >/root/installed

remove_installed_packages /root/originally-installed /root/installed

install_and_cleanup_cuttlefish

create_systemd_getty_symlinks ttyS0 hvc1

apt-get purge -y vim-tiny
bullseye_cleanup
