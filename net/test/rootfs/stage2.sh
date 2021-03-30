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

exitcode="$1"
trap "echo $? >${exitcode}" ERR

# Remove the old ramdisk root; we don't need it any more
umount -l /host

# Complete the debootstrap process
/debootstrap/debootstrap --second-stage
apt-get clean
rm -rf /debootstrap /var/lib/apt/lists/*

# Read-only root breaks booting via init
cat >/etc/fstab << EOF
tmpfs /tmp     tmpfs defaults 0 0
tmpfs /var/log tmpfs defaults 0 0
tmpfs /var/tmp tmpfs defaults 0 0
EOF

# systemd will attempt to re-create this symlink if it does not exist,
# which fails if it is booting from a read-only root filesystem (which
# is normally the case). The syslink must be relative, not absolute,
# and it must point to /proc/self/mounts, not /proc/mounts.
ln -sf ../proc/self/mounts /etc/mtab

# Remove contaminants coming from the debootstrap process
echo vm >/etc/hostname
echo "nameserver 127.0.0.1" >/etc/resolv.conf

# Disable the root password
passwd -d root

# Support chroot jailing with minijail
mkdir -p /var/empty

# Clean up any other junk created by the imaging process
rm -rf /root/stage1.sh /root/stage2.sh /root/lib /tmp/*
find /var/log -type f -exec rm -f '{}' ';'
find /var/tmp -type f -exec rm -f '{}' ';'

# Create an empty initramfs to be combined with modules later
mkdir -p /lib/modules/`uname -r`/kernel
touch /lib/modules/`uname -r`/modules.{builtin,order}
depmod -a `uname -r`
update-initramfs -c -k `uname -r` -b /root
cat /root/initrd.img-`uname -r` >/dev/vdb
rm -rf /lib/modules/`uname -r` /root/initrd.img-`uname -r`

echo 0 >"${exitcode}"
poweroff -f
