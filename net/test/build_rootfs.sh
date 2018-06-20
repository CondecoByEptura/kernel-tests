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

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
  echo "usage: $0 net_test.rootfs.`date +%Y%m%d` [wheezy|stretch]"
  exit 1
}

# Sanity check the command line parameters
[ -z "$1" ] && usage
[ -z "$2" ] && suite=stretch || suite=$2
[ "$suite" != "wheezy" -a "$suite" != "stretch" ] && usage

# Import the package list for this release
packages=`cat $SCRIPT_DIR/rootfs/$suite.list | xargs | tr -s ' ' ','`

# For the debootstrap intermediates
mkdir -p workdir

# Run the debootstrap first
cd workdir
sudo debootstrap --arch=amd64 --variant=minbase --include=$packages \
                 $suite . http://ftp.debian.org/debian
# Workarounds for bugs in the debootstrap suite scripts
for path in dev dev/shm proc/sys/fs/binfmt_misc proc run/shm; do
  sudo umount $path 2>/dev/null || true
done
# Copy the chroot preparation scripts, and enter the chroot
for file in $suite.sh common.sh \
            iptables-enable-bpf-compiler.diff net_test.sh; do
  sudo cp -a $SCRIPT_DIR/rootfs/$file root/$file
  sudo chown root:root root/$file
done
sudo chroot . /root/$suite.sh

# Leave the workdir, to build the filesystem
cd -

# For the final image mount
mkdir -p mount

# Create a 1G empty ext3 filesystem
truncate -s 1G $1
mke2fs -F -t ext3 -L ROOT $1

# Mount the new filesystem locally
sudo mount -o loop -t ext3 $1 mount

# Copy the patched debootstrap results into the new filesystem
sudo cp -a workdir/* mount

# Fill the rest of the space with zeroes, to optimize compression
sudo dd if=/dev/zero of=mount/sparse bs=1M || true
sudo rm -f mount/sparse

# Unmount the new filesystem
sudo umount mount

# Clean up after ourselves
sudo rm -rf workdir mount
