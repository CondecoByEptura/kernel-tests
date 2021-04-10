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

trap "echo 3 >${exitcode}" ERR

# $1 - Suite name for apt sources
update_apt_sources() {
  # Add the needed debian sources
  cat >/etc/apt/sources.list <<EOF
deb http://ftp.debian.org/debian bullseye main
deb-src http://ftp.debian.org/debian bullseye main
EOF

  # Disable the automatic installation of recommended packages
  cat >/etc/apt/apt.conf.d/90recommends <<EOF
APT::Install-Recommends "0";
EOF

  # On the ARM64, allow packages from AMD64 to be installed
  dpkg --add-architecture amd64

  # Update for the above changes
  apt-get update
}

# $1 - Output file for currently installed packages
get_installed_packages() {
  LANG=C dpkg --get-selections | sort
}

# $1 - File containing package selections to restore to
# $2 - File containing currently installed packages list
remove_installed_packages() {
  apt-get purge --allow-remove-essential -y \
    $(comm -3 "$1" "$2" | sed -e 's,install,,' -e 's,\t,,' | xargs)
  rm -f "$1" "$2"
}

setup_static_networking() {
  # Temporarily bring up static QEMU SLIRP networking (no DHCP)
  ip link set dev eth0 up
  ip addr add 10.0.2.15/24 broadcast 10.0.2.255 dev eth0
  ip route add default via 10.0.2.2 dev eth0

  # Permanently update the resolv.conf with the Google DNS servers
  echo "nameserver 8.8.8.8"  >/etc/resolv.conf
  echo "nameserver 8.8.4.4" >>/etc/resolv.conf
}

setup_dynamic_networking() {
  # So isc-dhcp-client can work with a read-only rootfs..
  cat >>/etc/fstab <<EOF
tmpfs /var/lib/dhcp tmpfs defaults 0 0
EOF

  # Bring up networking one time with dhclient
  mount /var/lib/dhcp
  dhclient eth0
  echo "nameserver 8.8.8.8"  >/run/resolvconf/resolv.conf
  echo "nameserver 8.8.4.4" >>/run/resolvconf/resolv.conf

  # Set up automatic DHCP for future boots
  cat >/etc/systemd/network/dhcp.network <<EOF
[Match]
Name=en*

[Network]
DHCP=yes
EOF

  # Mask the NetworkManager-wait-online service to prevent hangs
  systemctl mask NetworkManager-wait-online.service
}

setup_cuttlefish_user() {
  # Add a default user and put them in the right group
  addgroup --system cvdnetwork
  useradd -m -G cvdnetwork,kvm,sudo -d /home/vsoc-01 --shell /bin/bash vsoc-01
  echo -e "cuttlefish\ncuttlefish" | passwd vsoc-01
}

# $* - One or more device names for getty spawns
create_systemd_getty_symlinks() {
  for device in $*; do
    ln -s /lib/systemd/system/serial-getty\@.service \
      /etc/systemd/system/getty.target.wants/serial-getty\@"${device}".service
  done
}

cleanup() {
  # Prevents systemd boot issues with read-only rootfs
  mkdir -p /var/lib/systemd/{coredump,linger,rfkill,timesync}
  chown systemd-timesync:systemd-timesync /var/lib/systemd/timesync

  # If embedding isn't enabled, remove the embedded modules and initrd and
  # uninstall the tools to regenerate the initrd, as they're unlikely to
  # ever be used
  if [ -z "${embed_kernel_initrd_dtb}" ]; then
    apt-get purge -y initramfs-tools initramfs-tools-core klibc-utils kmod
    rm -f "/boot/initrd.img-$(uname -r)"
    rm -rf "/lib/modules/$(uname -r)"
  else
    # For testing the image with a virtual device
    apt-get install -y grub2-common
    cat >/etc/default/grub <<"EOF"
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR=Debian
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="\$cmdline"
EOF
    mkdir /boot/grub
    update-grub
  fi

  # Miscellaneous cleanup
  rm -rf /var/lib/apt/lists/* || true
  rm -f /root/* || true
  apt-get clean

  echo 0 >"${exitcode}"
  sync && poweroff -f
}
