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
nvidia_arch=${arch}
[ "${arch}" = "x86_64" ] && arch=amd64
[ "${arch}" = "aarch64" ] && arch=arm64

setup_dynamic_networking "eth0" ""

# NVIDIA driver needs dkms which requires /dev/fd
if [ ! -d /dev/fd ]; then
 ln -s /proc/self/fd /dev/fd
fi

update_apt_sources "bullseye bullseye-backports"

setup_cuttlefish_user

# Get kernel and QEMU from backports
for package in linux-image-cloud-${arch} qemu-system-arm qemu-system-x86; do
  apt-get install -y -t bullseye-backports ${package}
done

get_installed_packages >/root/originally-installed

# Using "Depends:" is more reliable than "Version:", because it works for
# backported ("bpo") kernels as well. NOTE: "Package" can be used instead
# if we don't install the metapackage ("linux-image-cloud-${arch}") but a
# specific version in the future
kmodver=$(dpkg -s linux-image-cloud-${arch} | grep ^Depends: | \
          cut -d: -f2 | cut -d" " -f2 | sed 's/linux-image-//')

# Install headers from backports, to match the linux-image (removed below)
apt-get install -y -t bullseye-backports $(echo linux-headers-${kmodver})

# Dependencies for nvidia-installer (removed below)
apt-get install -y dkms libglvnd-dev libc6-dev pkg-config

nvidia_version=515.65.01
wget -q https://us.download.nvidia.com/tesla/${nvidia_version}/NVIDIA-Linux-${nvidia_arch}-${nvidia_version}.run
chmod a+x NVIDIA-Linux-${nvidia_arch}-${nvidia_version}.run
./NVIDIA-Linux-${nvidia_arch}-${nvidia_version}.run -x
cd NVIDIA-Linux-${nvidia_arch}-${nvidia_version}
if [[ "${nvidia_arch}" = "x86_64" ]]; then
  installer_flags="--no-install-compat32-libs"
else
  installer_flags=""
fi
./nvidia-installer ${installer_flags} --silent --no-backup --no-wine-files \
                   --install-libglvnd --dkms -k "${kmodver}"
cd -
rm -rf NVIDIA-Linux-${nvidia_arch}-${nvidia_version}*

get_installed_packages >/root/installed

remove_installed_packages /root/originally-installed /root/installed

setup_and_build_cuttlefish

install_and_cleanup_cuttlefish

# ttyAMA0 for ampere/gigabyte
# ttyS0 for GCE t2a
# hvc1 for nested Cuttlefish (login console only)
create_systemd_getty_symlinks ttyAMA0 ttyS0 hvc1

setup_grub "net.ifnames=0 console=ttyAMA0 8250.nr_uarts=1 console=ttyS0 loglevel=4"

apt-get purge -y vim-tiny
bullseye_cleanup
