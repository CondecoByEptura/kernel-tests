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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
  echo -n "usage: $0 [-h] [-s bullseye|bullseye-minimal|bullseye-rockpi] "
  echo -n "[-a i386|amd64|armhf|arm64] -k /path/to/kernel "
  echo -n "-i /path/to/initramfs.gz [-m http://mirror/debian] "
  echo "[-n rootfs] [-r initrd]"
  exit 1
}

mirror=http://ftp.debian.org/debian
suite=bullseye-minimal
arch=amd64

while getopts ":hs:a:m:n:r:k:i:" opt; do
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
      rootfs="${OPTARG}"
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
cmdline="net.ifnames=0 rw"

case "${arch}" in
  i386)
    cmdline="${cmdline} exitcode=/dev/ttyS1"
    machine="pc-i440fx-2.8,accel=kvm"
    qemu="qemu-system-i386"
    cpu="max"
    ;;
  amd64)
    cmdline="${cmdline} exitcode=/dev/ttyS1"
    machine="pc-i440fx-2.8,accel=kvm"
    qemu="qemu-system-x86_64"
    cpu="max"
    ;;
  armhf)
    cmdline="${cmdline} exitcode=/dev/ttyS0"
    machine="virt,gic-version=2"
    qemu="qemu-system-arm"
    cpu="cortex-a15"
    ;;
  arm64)
    cmdline="${cmdline} exitcode=/dev/ttyS0"
    machine="virt,gic-version=2"
    qemu="qemu-system-aarch64"
    cpu="cortex-a53" # "max" is too slow
    ;;
  *)
    echo "Invalid arch: ${OPTARG}" >&2
    usage
    ;;
esac

if [[ -z "${name}" ]]; then
  rootfs="rootfs.${arch}.${suite}.`date +%Y%m%d`"
fi

if [[ -z "${ramdisk}" ]]; then
  ramdisk="initrd.${arch}.${suite}.`date +%Y%m%d`"
fi

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
  rm -f "${rootfs}" "${ramdisk}"
}
trap failure ERR

# Import the package list for this release
packages=`cpp "${SCRIPT_DIR}/rootfs/${suite}.list" | grep -v "^#" | xargs | tr -s ' ' ','`

# For the debootstrap intermediates
tmpdir=`mktemp -d`
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
sudo debootstrap --arch="${arch}" --variant=minbase --include="${packages}" \
                 --foreign "${suite%-*}" . "${mirror}"
# Workarounds for bugs in the debootstrap suite scripts
for mount in `cat /proc/mounts | cut -d' ' -f2 | grep -e "^${workdir}"`; do
  echo "Unmounting mountpoint ${mount}.." >&2
  sudo umount "${mount}"
done

# Copy some bootstrapping scripts into the rootfs
sudo cp -a "${SCRIPT_DIR}"/rootfs/*.sh root/
sudo cp -a "${SCRIPT_DIR}"/rootfs/net_test.sh sbin/net_test.sh
sudo chown root:root sbin/net_test.sh

# Extract the ramdisk to bootstrap with to /root
lz4 -l -cd "${initramfs}" | sudo cpio -D root -idum
sudo chown -R root:root root

# Create /host, for the pivot_root and 9p mount use cases
sudo mkdir host

# Leave the workdir, to build the filesystem
cd -

# For the initial ramdisk, and later for the final rootfs
mount=`mktemp -d`
mount_remove() {
  rmdir "${mount}"
  tmpdir_remove
}
trap mount_remove EXIT

# The initial ramdisk filesystem must be <=512M, or QEMU's -initrd
# option won't touch it
initrd=`mktemp`
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

# Copy the initial ramdisk to the final rootfs name and extend it
sudo cp -a "${initrd}" "${rootfs}"
truncate -s 2G "${rootfs}"
e2fsck -p -f "${rootfs}" || true
resize2fs "${rootfs}"

# Create another fake block device for initrd.img writeout
raw_initrd=`mktemp`
raw_initrd_remove() {
  rm -f "${raw_initrd}"
  initrd_remove
}
trap raw_initrd_remove EXIT
truncate -s 16M "${raw_initrd}"

# Complete the bootstrap process using QEMU and the specified kernel
${qemu} -machine "${machine}" -cpu "${cpu}" -m 2048 >&2 \
  -kernel "${kernel}" -initrd "${initrd}" -no-user-config -nodefaults \
  -no-reboot -display none -nographic -serial stdio -parallel none \
  -smp 8,sockets=8,cores=1,threads=1 \
  -object rng-random,id=objrng0,filename=/dev/urandom \
  -device virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,max-bytes=1024,period=2000 \
  -drive file="${rootfs}",format=raw,if=none,aio=threads,id=drive-virtio-disk0 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk0 \
  -drive file="${raw_initrd}",format=raw,if=none,aio=threads,id=drive-virtio-disk1 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk1 \
  -chardev file,id=exitcode,path=exitcode \
  -device pci-serial,chardev=exitcode \
  -append "root=/dev/ram0 ramdisk_size=524288 init=/root/stage1.sh ${cmdline}"
[[ -s exitcode ]] && exitcode=`cat exitcode | tr -d '\r'` || exitcode=2
rm -f exitcode
if [ "${exitcode}" != "0" ]; then
  echo "Second stage debootstrap failed (err=${exitcode})"
  exit "${exitcode}"
fi

# Fix up any issues from the unclean shutdown
e2fsck -p -f "${rootfs}" || true

# New workdir for the initrd extraction
workdir="${tmpdir}/initrd"
mkdir "${workdir}"
chmod 0755 "${workdir}"
sudo chown root:root "${workdir}"

# Temporary final ramdisk
final_ramdisk=`mktemp`
final_ramdisk_remove() {
  rm -f "${final_ramdisk}"
  raw_initrd_remove
}
trap final_ramdisk_remove EXIT

# Change into workdir to repack initramfs
cd "${workdir}"

# Process the initrd to remove kernel-specific metadata
kernel_version=`basename $(lz4 -l -cd "${raw_initrd}" | sudo cpio -idumv 2>&1 | grep usr/lib/modules/ - | head -n1)`
sudo rm -rf usr/lib/modules
sudo mkdir -p usr/lib/modules

# Debian symlinks /usr/lib to /lib, but we'd prefer the other way around
# so that it more closely matches what happens in Android initramfs images.
# This enables 'cat ramdiskA.img ramdiskB.img >ramdiskC.img' to "just work".
sudo rm -f lib
sudo mv usr/lib lib
sudo ln -s /lib usr/lib

# Repack the ramdisk to the final output
find * | sudo cpio -H newc -o --quiet | lz4 -9 -l -c >"${final_ramdisk}"

# Pack another ramdisk with the combined artifacts, for boot testing
cat "${final_ramdisk}" "${initramfs}" >"${initrd}"

# Leave workdir to boot-test combined initrd
cd -

# Boot test the new system and run stage 3
${qemu} -machine "${machine}" -cpu "${cpu}" -m 2048 >&2 \
  -kernel "${kernel}" -initrd "${initrd}" -no-user-config -nodefaults \
  -no-reboot -display none -nographic -serial stdio -parallel none \
  -smp 8,sockets=8,cores=1,threads=1 \
  -object rng-random,id=objrng0,filename=/dev/urandom \
  -device virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,max-bytes=1024,period=2000 \
  -drive file="${rootfs}",format=raw,if=none,aio=threads,id=drive-virtio-disk0 \
  -device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk0 \
  -chardev file,id=exitcode,path=exitcode \
  -device pci-serial,chardev=exitcode \
  -netdev user,id=usernet0,ipv6=off \
  -device virtio-net-pci-non-transitional,netdev=usernet0,id=net0 \
  -append "root=/dev/vda init=/root/${suite}.sh ${cmdline}"
[[ -s exitcode ]] && exitcode=`cat exitcode | tr -d '\r'` || exitcode=2
rm -f exitcode
if [ "${exitcode}" != "0" ]; then
  echo "Root filesystem finalization failed (err=${exitcode})"
  exit "${exitcode}"
fi

# Fix up any issues from the unclean shutdown
e2fsck -p -f "${rootfs}" || true

# Resize the final rootfs to a smaller size
resize2fs "${rootfs}" 1G
truncate -s 1G "${rootfs}"

# Mount the final rootfs locally
sudo mount -o loop -t ext3 "${rootfs}" "${mount}"
image_unmount2() {
  sudo umount "${mount}"
  final_ramdisk_remove
}
trap image_unmount2 EXIT

# Fill the rest of the space with zeroes, to optimize compression
sudo dd if=/dev/zero of="${mount}/sparse" bs=1M 2>/dev/null || true
sudo rm -f "${mount}/sparse"

# Copy the final ramdisk image
cp -a "${final_ramdisk}" "${ramdisk}"

echo "Debian ${suite} for ${arch} filesystem generated at '${rootfs}'."
echo "Initial ramdisk generated at '${ramdisk}'."
