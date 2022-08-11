#!/bin/bash
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
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
  echo -n "usage: $0 [-h] [-s bullseye|bullseye-cuttlefish|bullseye-rockpi|bullseye-server] "
  echo -n "[-a i386|amd64|armhf|arm64] -k /path/to/kernel "
  echo -n "-i /path/to/initramfs.gz [-d /path/to/dtb:subdir] "
  echo "[-m http://mirror/debian] [-n rootfs|disk] [-r initrd] [-e] [-g]"
  exit 1
}

mirror=http://ftp.debian.org/debian
suite=bullseye
arch=amd64

embed_kernel_initrd_dtb=
dtb_subdir=
ramdisk=
disk=
dtb=

while getopts ":hs:a:m:n:r:k:i:d:e" opt; do
  case "${opt}" in
    h)
      usage
      ;;
    s)
      if [[ "${OPTARG%-*}" != "bullseye" ]]; then
        echo "Invalid suite: ${OPTARG}" >&2
        usage
      fi
      suite="${OPTARG}"
      ;;
    a)
      arch="${OPTARG}"
      ;;
    m)
      mirror="${OPTARG}"
      ;;
    n)
      disk="${OPTARG}"
      ;;
    r)
      ramdisk="${OPTARG}"
      ;;
    k)
      kernel="${OPTARG}"
      ;;
    i)
      initramfs="${OPTARG}"
      ;;
    d)
      dtb="${OPTARG%:*}"
      if [ "${OPTARG#*:}" != "${dtb}" ]; then
        dtb_subdir="${OPTARG#*:}/"
      fi
      ;;
    e)
      embed_kernel_initrd_dtb=1
      ;;
    g)
      install_grub=1
      ;;
    \?)
      echo "Invalid option: ${OPTARG}" >&2
      usage
      ;;
    :)
      echo "Invalid option: ${OPTARG} requires an argument" >&2
      usage
      ;;
  esac
done

# Disable Debian's "persistent" network device renaming
cmdline="net.ifnames=0 rw 8250.nr_uarts=2 PATH=/usr/sbin:/bin:/usr/bin"

# Pass down embedding option, if specified
if [ -n "${embed_kernel_initrd_dtb}" ]; then
  cmdline="${cmdline} embed_kernel_initrd_dtb=${embed_kernel_initrd_dtb}"
fi

# Pass down grub installation option, if specified
if [ -n "${install_grub}" ]; then
  cmdline="${cmdline} install_grub=${install_grub}"
fi

case "${arch}" in
  i386)
    cmdline="${cmdline} console=ttyS0 exitcode=/dev/ttyS1"
    machine="pc-i440fx-2.8,accel=kvm"
    qemu="qemu-system-i386"
    partguid="8303"
    cpu="max"
    ;;
  amd64)
    cmdline="${cmdline} console=ttyS0 exitcode=/dev/ttyS1"
    machine="pc-i440fx-2.8,accel=kvm"
    qemu="qemu-system-x86_64"
    partguid="8304"
    cpu="max"
    ;;
  armhf)
    cmdline="${cmdline} console=ttyAMA0 exitcode=/dev/ttyS0"
    machine="virt,gic-version=2"
    qemu="qemu-system-arm"
    partguid="8307"
    cpu="cortex-a15"
    ;;
  arm64)
    cmdline="${cmdline} console=ttyAMA0 exitcode=/dev/ttyS0"
    machine="virt,gic-version=2"
    qemu="qemu-system-aarch64"
    partguid="8305"
    cpu="cortex-a53" # "max" is too slow
    ;;
  *)
    echo "Invalid arch: ${OPTARG}" >&2
    usage
    ;;
esac

if [[ -z "${disk}" ]]; then
  if [[ -n "${install_grub}" ]]; then
    base_image_name=disk
  else
    base_image_name=rootfs
  fi
  disk="${base_image_name}.${arch}.${suite}.$(date +%Y%m%d)"
fi
disk=$(realpath "${disk}")

if [[ -z "${ramdisk}" ]]; then
  ramdisk="initrd.${arch}.${suite}.$(date +%Y%m%d)"
fi
ramdisk=$(realpath "${ramdisk}")

if [[ -z "${kernel}" ]]; then
  echo "$0: Path to kernel image must be specified (with '-k')"
  usage
elif [[ ! -e "${kernel}" ]]; then
  echo "$0: Kernel image not found at '${kernel}'"
  exit 2
fi

if [[ -z "${initramfs}" ]]; then
  echo "Path to initial ramdisk image must be specified (with '-i')"
  usage
elif [[ ! -e "${initramfs}" ]]; then
  echo "Initial ramdisk image not found at '${initramfs}'"
  exit 3
fi

# Sometimes it isn't obvious when the script fails
failure() {
  echo "Filesystem generation process failed." >&2
  rm -f "${disk}" "${ramdisk}"
}
trap failure ERR

# Import the package list for this release
packages=$(cpp "${SCRIPT_DIR}/rootfs/${suite}.list" | grep -v "^#" | xargs | tr -s ' ' ',')

# For the debootstrap intermediates
tmpdir=$(mktemp -d)
tmpdir_remove() {
  echo "Removing temporary files.." >&2
  sudo rm -rf "${tmpdir}"
}
trap tmpdir_remove EXIT

workdir="${tmpdir}/_"
mkdir "${workdir}"
chmod 0755 "${workdir}"
sudo chown root:root "${workdir}"

# Run the debootstrap first
cd "${workdir}"

retries=5
while ! sudo debootstrap --arch="${arch}" --variant=minbase --include="${packages}" \
        --foreign "${suite%-*}" . "${mirror}"; do
    retries=$((${retries} - 1))
    if [ ${retries} -le 0 ]; then
	failure
	exit 1
    fi
    echo "debootstrap failed - trying again - ${retries} retries left"
done

# Copy some bootstrapping scripts into the rootfs
sudo cp -a "${SCRIPT_DIR}"/rootfs/*.sh root/
sudo cp -a "${SCRIPT_DIR}"/rootfs/net_test.sh sbin/net_test.sh
sudo chown root:root sbin/net_test.sh

# Extract the ramdisk to bootstrap with to /
lz4 -lcd "${initramfs}" | sudo cpio -idum lib/modules/*

# Create /host, for the pivot_root and 9p mount use cases
sudo mkdir host

# Leave the workdir, to build the filesystem
cd -

# For the initial ramdisk, and later for the final rootfs
mount=$(mktemp -d)
mount_remove() {
  rmdir "${mount}"
  tmpdir_remove
}
trap mount_remove EXIT

# The initial ramdisk filesystem must be <=512M, or QEMU's -initrd
# option won't touch it
initrd=$(mktemp)
initrd_remove() {
  rm -f "${initrd}"
  mount_remove
}
trap initrd_remove EXIT
truncate -s 512M "${initrd}"
mke2fs -F -t ext3 -L ROOT "${initrd}"

# Mount the new filesystem locally
sudo mount -o loop -t ext3 "${initrd}" "${mount}"
image_unmount() {
  sudo umount "${mount}"
  initrd_remove
}
trap image_unmount EXIT

# Copy the patched debootstrap results into the new filesystem
sudo cp -a "${workdir}"/* "${mount}"
sudo rm -rf "${workdir}"

# Unmount the initial ramdisk
sudo umount "${mount}"
trap initrd_remove EXIT

loopdev="$(sudo losetup -f)"
loopdev_delete() {
  sudo losetup -d "${loopdev}"
  initrd_remove
}
if [[ -z "${install_grub}" ]]; then
  # If there's no bootloader, the initrd is the disk image
  cp -a "${initrd}" "${disk}"
  truncate -s 3G "${disk}"
  e2fsck -p -f "${disk}" || true
  resize2fs "${disk}"
  sudo losetup -f "${loopdev}" "${disk}"
  rootfs_loopdev="${loopdev}"
  trap loopdev_delete EXIT
else
  # If there's a bootloader, we need to make space for the GPT header, GPT
  # footer and EFI system partition (legacy boot is not supported)
  # Keep this simple - modern gdisk reserves 1MB for the GPT header and
  # assumes all partitions are 1MB aligned
  truncate -s "$((1 + 128 + 3 * 1024 + 1))M" "${disk}"
  /sbin/sgdisk --new="1:0:+128M" --typecode="1:ef00" "${disk}" >/dev/null 2>/dev/null
  /sbin/sgdisk --new="2:0:0" --typecode="1:${partguid}" "${disk}" >/dev/null
  # Temporarily set up a partitioned loop device so we can resize the rootfs
  # This also simplifes the mkfs and rootfs copy
  sudo losetup -P -f "${loopdev}" "${disk}"
  rootfs_loopdev="${loopdev}p2"
  trap loopdev_delete EXIT
  # Create an empty EFI system partition; it will be initialized later
  sudo /sbin/mkfs.vfat -n System -F32 "${loopdev}p1" >/dev/null
  # Copy the rootfs to just after the EFI system partition
  sudo dd if="${initrd}" of="${rootfs_loopdev}" bs=1M 2>/dev/null
  sudo e2fsck -p -f "${rootfs_loopdev}" || true
  sudo resize2fs "${rootfs_loopdev}"
  sudo losetup -d "${rootfs_loopdev}"
fi

# Create another fake block device for initrd.img writeout
raw_initrd=$(mktemp)
raw_initrd_remove() {
  rm -f "${raw_initrd}"
  loopdev_delete
}
trap raw_initrd_remove EXIT
truncate -s 64M "${raw_initrd}"

# Get number of cores for qemu. Restrict the maximum value to 8.
qemucpucores=$(nproc)
if [[ ${qemucpucores} -gt 8 ]]; then
  qemucpucores=8
fi

# Complete the bootstrap process using QEMU and the specified kernel
${qemu} -machine "${machine}" -cpu "${cpu}" -m 2048 >&2 \
  -kernel "${kernel}" -initrd "${initrd}" -no-user-config -nodefaults \
  -no-reboot -display none -nographic -serial stdio -parallel none \
  -smp "${qemucpucores}",sockets="${qemucpucores}",cores=1,threads=1 \
  -object rng-random,id=objrng0,filename=/dev/urandom \
  -device virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,max-bytes=1024,period=2000 \
  -drive file="${disk}",format=raw,if=none,aio=threads,id=drive-virtio-disk0 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk0 \
  -drive file="${raw_initrd}",format=raw,if=none,aio=threads,id=drive-virtio-disk1 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk1 \
  -chardev file,id=exitcode,path=exitcode \
  -device pci-serial,chardev=exitcode \
  -append "root=/dev/ram0 ramdisk_size=524288 init=/root/stage1.sh ${cmdline}"
[[ -s exitcode ]] && exitcode=$(cat exitcode | tr -d '\r') || exitcode=2
rm -f exitcode
if [ "${exitcode}" != "0" ]; then
  echo "Second stage debootstrap failed (err=${exitcode})"
  exit "${exitcode}"
fi

# Fix up any issues from the unclean shutdown
sudo e2fsck -p -f "${rootfs_loopdev}" || true

# New workdir for the initrd extraction
workdir="${tmpdir}/initrd"
mkdir "${workdir}"
chmod 0755 "${workdir}"
sudo chown root:root "${workdir}"

# Change into workdir to repack initramfs
cd "${workdir}"

# Process the initrd to remove kernel-specific metadata
kernel_version=$(basename $(lz4 -lcd "${raw_initrd}" | sudo cpio -idumv 2>&1 | grep usr/lib/modules/ - | head -n1))
sudo rm -rf usr/lib/modules
sudo mkdir -p usr/lib/modules

# Debian symlinks /usr/lib to /lib, but we'd prefer the other way around
# so that it more closely matches what happens in Android initramfs images.
# This enables 'cat ramdiskA.img ramdiskB.img >ramdiskC.img' to "just work".
sudo rm -f lib
sudo mv usr/lib lib
sudo ln -s /lib usr/lib

# Repack the ramdisk to the final output
find * | sudo cpio -H newc -o --quiet | lz4 -lc9 >"${ramdisk}"

# Pack another ramdisk with the combined artifacts, for boot testing
cat "${ramdisk}" "${initramfs}" >"${initrd}"

# Leave workdir to boot-test combined initrd
cd -

# Mount the new filesystem locally
sudo mount -t ext3 "${rootfs_loopdev}" "${mount}"
image_unmount2() {
  sudo umount "${mount}"
  raw_initrd_remove
}
trap image_unmount2 EXIT

# Embed the kernel and dtb images now, if requested
if [ -n "${embed_kernel_initrd_dtb}" ]; then
  if [ -n "${dtb}" ]; then
    sudo mkdir -p "${mount}/boot/dtb/${dtb_subdir}"
    sudo cp -a "${dtb}" "${mount}/boot/dtb/${dtb_subdir}"
    sudo chown -R root:root "${mount}/boot/dtb/${dtb_subdir}"
  fi
  sudo cp -a "${kernel}" "${mount}/boot/vmlinuz-${kernel_version}"
  sudo chown root:root "${mount}/boot/vmlinuz-${kernel_version}"
fi

# Unmount the initial ramdisk
sudo umount "${mount}"
trap raw_initrd_remove EXIT

# Boot test the new system and run stage 3
${qemu} -machine "${machine}" -cpu "${cpu}" -m 2048 >&2 \
  -kernel "${kernel}" -initrd "${initrd}" -no-user-config -nodefaults \
  -no-reboot -display none -nographic -serial stdio -parallel none \
  -smp "${qemucpucores}",sockets="${qemucpucores}",cores=1,threads=1 \
  -object rng-random,id=objrng0,filename=/dev/urandom \
  -device virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,max-bytes=1024,period=2000 \
  -drive file="${disk}",format=raw,if=none,aio=threads,id=drive-virtio-disk0 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk0 \
  -chardev file,id=exitcode,path=exitcode \
  -device pci-serial,chardev=exitcode \
  -netdev user,id=usernet0,ipv6=off \
  -device virtio-net-pci-non-transitional,netdev=usernet0,id=net0 \
  -append "root=LABEL=ROOT init=/root/${suite}.sh ${cmdline}"
[[ -s exitcode ]] && exitcode=$(cat exitcode | tr -d '\r') || exitcode=2
rm -f exitcode
if [ "${exitcode}" != "0" ]; then
  echo "Root filesystem finalization failed (err=${exitcode})"
  exit "${exitcode}"
fi

# Fix up any issues from the unclean shutdown
sudo e2fsck -p -f "${rootfs_loopdev}" || true

# Mount the final disk image locally
sudo mount -t ext3 "${rootfs_loopdev}" "${mount}"
image_unmount3() {
  sudo umount "${mount}"
  raw_initrd_remove
}
trap image_unmount3 EXIT

# Fill the rest of the space with zeroes, to optimize compression
sudo dd if=/dev/zero of="${mount}/sparse" bs=1M 2>/dev/null || true
sudo rm -f "${mount}/sparse"

echo "Debian ${suite} for ${arch} filesystem generated at '${disk}'."
echo "Initial ramdisk generated at '${ramdisk}'."
