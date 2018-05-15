#!/bin/bash

# Common kernel options
OPTIONS=" DEBUG_SPINLOCK DEBUG_ATOMIC_SLEEP DEBUG_MUTEXES DEBUG_RT_MUTEXES"
OPTIONS="$OPTIONS IPV6 IPV6_ROUTER_PREF IPV6_MULTIPLE_TABLES IPV6_ROUTE_INFO"
OPTIONS="$OPTIONS TUN SYN_COOKIES IP_ADVANCED_ROUTER IP_MULTIPLE_TABLES"
OPTIONS="$OPTIONS NETFILTER NETFILTER_ADVANCED NETFILTER_XTABLES"
OPTIONS="$OPTIONS NETFILTER_XT_MARK NETFILTER_XT_TARGET_MARK"
OPTIONS="$OPTIONS IP_NF_IPTABLES IP_NF_MANGLE IP_NF_FILTER"
OPTIONS="$OPTIONS IP6_NF_IPTABLES IP6_NF_MANGLE IP6_NF_FILTER INET6_IPCOMP"
OPTIONS="$OPTIONS IPV6_OPTIMISTIC_DAD"
OPTIONS="$OPTIONS IPV6_ROUTE_INFO IPV6_ROUTER_PREF"
OPTIONS="$OPTIONS NETFILTER_XT_TARGET_NFLOG"
OPTIONS="$OPTIONS NETFILTER_XT_MATCH_QUOTA"
OPTIONS="$OPTIONS NETFILTER_XT_MATCH_QUOTA2"
OPTIONS="$OPTIONS NETFILTER_XT_MATCH_QUOTA2_LOG"
OPTIONS="$OPTIONS NETFILTER_XT_MATCH_SOCKET"
OPTIONS="$OPTIONS NETFILTER_XT_MATCH_QTAGUID"
OPTIONS="$OPTIONS INET_UDP_DIAG INET_DIAG_DESTROY"
OPTIONS="$OPTIONS IP_SCTP"
OPTIONS="$OPTIONS IP_NF_TARGET_REJECT IP_NF_TARGET_REJECT_SKERR"
OPTIONS="$OPTIONS IP6_NF_TARGET_REJECT IP6_NF_TARGET_REJECT_SKERR"
OPTIONS="$OPTIONS NET_KEY XFRM_USER XFRM_STATISTICS CRYPTO_CBC"
OPTIONS="$OPTIONS CRYPTO_CTR CRYPTO_HMAC CRYPTO_AES CRYPTO_SHA1 CRYPTO_SHA256"
OPTIONS="$OPTIONS CRYPTO_USER INET_ESP INET_XFRM_MODE_TRANSPORT"
OPTIONS="$OPTIONS INET_XFRM_MODE_TUNNEL INET6_ESP"
OPTIONS="$OPTIONS INET6_XFRM_MODE_TRANSPORT INET6_XFRM_MODE_TUNNEL"
OPTIONS="$OPTIONS CRYPTO_SHA256 CRYPTO_SHA512 CRYPTO_AES_X86_64 CRYPTO_NULL"
OPTIONS="$OPTIONS CRYPTO_GCM CRYPTO_ECHAINIV NET_IPVTI"

# Kernel version specific options
OPTIONS="$OPTIONS BLK_DEV_UBD HOSTFS"            # Unset by default in 4.14 (uml)
OPTIONS="$OPTIONS CGROUP_BPF"                    # Added in 4.10 (ebpf)
OPTIONS="$OPTIONS NF_SOCKET_IPV4 NF_SOCKET_IPV6" # Added in 4.9
OPTIONS="$OPTIONS INET_SCTP_DIAG"                # Added in 4.7
OPTIONS="$OPTIONS SOCK_CGROUP_DATA"              # Added in 4.5
OPTIONS="$OPTIONS CRYPTO_ECHAINIV"               # Added in 4.1 (ipsec)
OPTIONS="$OPTIONS BPF_SYSCALL"                   # Added in 3.18 (ebpf)
OPTIONS="$OPTIONS IPV6_VTI"                      # Added in 3.13 (ipsec)
OPTIONS="$OPTIONS IPV6_PRIVACY"                  # Removed in 3.12
OPTIONS="$OPTIONS NETFILTER_TPROXY"              # Removed in 3.11
OPTIONS="$OPTIONS DEVTMPFS DEVTMPFS_MOUNT"       # Unset in 3.1 (uml)

# Obsolete options present at some time in Android kernels
OPTIONS="$OPTIONS IP_NF_TARGET_REJECT_SKERR IP6_NF_TARGET_REJECT_SKERR"
OPTIONS="$OPTIONS XFRM_INTERFACE"

# These two break the flo kernel due to differences in -Werror on recent GCC.
DISABLE_OPTIONS=" REISERFS_FS ANDROID_PMEM"

# This one breaks the fugu kernel due to a nonexistent sem_wait_array.
DISABLE_OPTIONS="$DISABLE_OPTIONS SYSVIPC"

# How many TAP interfaces to create to provide the VM with real network access
# via the host. This requires privileges (e.g., root access) on the host.
#
# This is not needed to run the tests, but can be used, for example, to allow
# the VM to update system packages, or to write tests that need access to a
# real network. The VM does not set up networking by default, but it contains a
# DHCP client and has the ability to use IPv6 autoconfiguration. This script
# does not perform any host-level setup beyond configuring tap interfaces;
# configuring IPv4 NAT and/or IPv6 router advertisements or ND proxying must
# be done separately.
NUMTAPINTERFACES=0

# The root filesystem disk image we'll use.
ROOTFS=net_test.rootfs.20150203
COMPRESSED_ROOTFS=$ROOTFS.xz
URL=https://dl.google.com/dl/android/$COMPRESSED_ROOTFS

# Parse arguments and figure out which test to run.
J=${J:-64}
MAKE="make"
OUT_DIR=$(readlink -f ${OUT_DIR:-.})
KERNEL_DIR=$(readlink -f ${KERNEL_DIR:-.})
if [ "$OUT_DIR" != "$KERNEL_DIR" ]; then
    MAKE="$MAKE O=$OUT_DIR"
fi
SCRIPT_DIR=$(dirname $(readlink -f $0))
CONFIG_SCRIPT=${KERNEL_DIR}/scripts/config
CONFIG_FILE=${OUT_DIR}/.config
consolemode=
netconfig=
testmode=
cmdline=
nowrite=0
nobuild=0
norun=0

while [ -n "$1" ]; do
  if [ "$1" = "--builder" ]; then
    if [ "$ARCH" == "um" ]; then
      consolemode="con=null,fd:1"
    else
      consolemode="-serial stdio"
    fi
    testmode=builder
    shift
  elif [ "$1" == "--readonly" ]; then
    cmdline="ro"
    nowrite=1
    shift
  elif [ "$1" == "--nobuild" ]; then
    nobuild=1
    shift
  elif [ "$1" == "--norun" ]; then
    norun=1
    shift
  else
    test=$1
    break  # Arguments after the test file are passed to the test itself.
  fi
done

if [ "$ARCH" != "um" -a -z "$consolemode" ]; then
  # QEMU doesn't create a console by default, so if we haven't set up the
  # --builder console, enable the VGA console explicitly instead
  # Assume VGA on x86 for now
  OPTIONS="$OPTIONS VT VGA_CONSOLE"
  cmdline="$cmdline console=tty0"
  consolemode="-vga std"
fi

# Check that test file exists and is readable
test_file=$SCRIPT_DIR/$test
if [[ ! -e $test_file ]]; then
  echo "test file '${test_file}' does not exist"
  exit 1
fi

if [[ ! -x $test_file ]]; then
  echo "test file '${test_file}' is not executable"
  exit 1
fi

# Collect trailing arguments to pass to $test
test_args=${@:2}

function isRunningTest() {
  [[ -n "$test" ]] && ! (( norun ))
}

function isBuildOnly() {
  [[ -z "$test" ]] && (( norun )) && ! (( nobuild ))
}

if ! isRunningTest && ! isBuildOnly; then
  echo "Usage:" >&2
  echo "  $0 [--builder] [--readonly] [--nobuild] <test>" >&2
  echo "  $0 --norun" >&2
  exit 1
fi

cd $OUT_DIR
echo Running tests from: `pwd`

set -e

cd $SCRIPT_DIR
# Check if we need to uncompress the disk image.
# We use xz because it compresses better: to 42M vs 72M (gzip) / 62M (bzip2).
if [ ! -f $ROOTFS ]; then
  echo "Deleting $COMPRESSED_ROOTFS" >&2
  rm -f $COMPRESSED_ROOTFS
  echo "Downloading $URL" >&2
  wget -nv $URL
  echo "Uncompressing $COMPRESSED_ROOTFS" >&2
  unxz $COMPRESSED_ROOTFS
fi
echo "Using $ROOTFS"

# If we're not UML, we need to build the initramfs workaround
if [ "$ARCH" != "um" ]; then
  echo "Building init for initramfs" >&2
  ${CC:-gcc} -W -Wall -Werror -std=c++14 -Os -s -static \
    -o init init-qemu.cpp -lstdc++
  echo "Building initramfs.cpio" >&2
  find -type f \( -not -name $ROOTFS -and -not -name initramfs.cpio \) | \
    cpio -o -H newc >initramfs.cpio
fi
cd -

# If network access was requested, create NUMTAPINTERFACES tap interfaces on
# the host, and prepare UML command line params to use them. The interfaces are
# called <user>TAP0, <user>TAP1, on the host, and eth0, eth1, ..., in the VM.
if (( $NUMTAPINTERFACES > 0 )); then
  user=${USER:0:10}
  tapinterfaces=
  for id in $(seq 0 $(( NUMTAPINTERFACES - 1 )) ); do
    tap=${user}TAP$id
    tapinterfaces="$tapinterfaces $tap"
    mac=$(printf fe:fd:00:00:00:%02x $id)
    if [ "$ARCH" == "um" ]; then
      netconfig="$netconfig eth$id=tuntap,$tap,$mac"
    else
      netconfig="$netconfig -netdev tap,id=hostnet$id,ifname=$tap,script=no,downscript=no"
      netconfig="$netconfig -device virtio-net-pci,netdev=hostnet$id,id=net$id,mac=$mac"
    fi
  done

  for tap in $tapinterfaces; do
    if ! ip link list $tap > /dev/null; then
      echo "Creating tap interface $tap" >&2
      sudo tunctl -u $USER -t $tap
      sudo ip link set $tap up
    fi
  done
fi

if [ -n "$KERNEL_BINARY" ]; then
  nobuild=1
fi

if ((nobuild == 0)); then
  make_flags=
  if [ "$ARCH" == "um" ]; then
    # Exporting ARCH=um SUBARCH=x86_64 doesn't seem to work, as it
    # "sometimes" (?) results in a 32-bit kernel.
    make_flags="$make_flags ARCH=$ARCH SUBARCH=x86_64 CROSS_COMPILE= "
  fi
  if [ -n "$CC" ]; then
    # The CC flag is *not* inherited from the environment.
    make_flags="$make_flags CC=$CC"
    # Workaround for a kernel bug that interacts with clang
    # See https://lkml.org/lkml/2018/5/7/534
    if [ "$CC" == "clang" ]; then
      DISABLE_OPTIONS="$DISABLE_OPTIONS PARAVIRT"
    fi
  fi

  # If there's no kernel config at all, create one or UML won't work.
  [ -n "$DEFCONFIG" ] || DEFCONFIG=defconfig
  [ -f $CONFIG_FILE ] || (cd $KERNEL_DIR && $MAKE $make_flags $DEFCONFIG)

  # Enable the kernel config options listed in $OPTIONS.
  $CONFIG_SCRIPT --file $CONFIG_FILE ${OPTIONS// / -e }

  # Disable the kernel config options listed in $DISABLE_OPTIONS.
  $CONFIG_SCRIPT --file $CONFIG_FILE ${DISABLE_OPTIONS// / -d }

  # olddefconfig doesn't work on old kernels.
  if ! $MAKE $make_flags olddefconfig; then
    cat >&2 << EOF

Warning: "make olddefconfig" failed.
Perhaps this kernel is too old to support it.
You may get asked lots of questions.
Keep enter pressed to accept the defaults.

EOF
  fi

  # Compile the kernel.
  if [ "$ARCH" == "um" ]; then
    $MAKE -j$J $make_flags linux
    KERNEL_BINARY=./linux
  else
    $MAKE -j$J $make_flags
    # Assume x86_64 bzImage for now
    KERNEL_BINARY=./arch/x86/boot/bzImage
  fi
fi

if (( norun == 1 )); then
  exit 0
fi

# The cmdline is flags the *kernel* interprets, not UML or QEMU
cmdline="$cmdline init=/sbin/net_test.sh"
cmdline="$cmdline net_test_args=\"$test_args\" net_test_mode=$testmode"

if [ "$ARCH" == "um" ]; then
  # Get the absolute path to the test file that's being run.
  cmdline="$cmdline net_test=/host$SCRIPT_DIR/$test"

  # Use UML's /proc/exitcode feature to communicate errors on test failure
  cmdline="$cmdline net_test_exitcode=/proc/exitcode"

  # Map the --readonly flag to UML block device names
  if ((nowrite == 0)); then
    blockdevice=ubda
  else
    blockdevice="${blockdevice}r"
  fi

  exec $KERNEL_BINARY >&2 umid=net_test mem=512M \
    $blockdevice=$SCRIPT_DIR/$ROOTFS $netconfig $consolemode $cmdline
else
  # The test is embedded in the initramfs; we don't need SCRIPT_DIR
  cmdline="$cmdline net_test=/host/$test"

  # QEMU has no way to modify its exitcode; simulate it with a serial port
  cmdline="$cmdline net_test_exitcode=/dev/ttyS1"

  # Map the --readonly flag to a QEMU block device flag
  blockdevice=
  if ((nowrite > 0)); then
    blockdevice=",readonly"
  fi
  blockdevice="-drive file=$SCRIPT_DIR/$ROOTFS,format=raw,if=none,id=drive-virtio-disk0$blockdevice"
  blockdevice="$blockdevice -device virtio-blk-pci,drive=drive-virtio-disk0"

  # Assume x86_64 PC emulation for now
  qemu-system-x86_64 >&2 -name net_test -m 512 \
    -kernel $KERNEL_BINARY -initrd $SCRIPT_DIR/initramfs.cpio \
    -no-user-config -nodefaults -no-reboot \
    -machine pc,accel=kvm -cpu host -smp 2,sockets=2,cores=1,threads=1 \
    -chardev file,id=exitcode,path=exitcode \
    -device isa-serial,chardev=exitcode \
     $blockdevice $netconfig $consolemode -append "$cmdline"
  [ -s exitcode ] && exitcode=`cat exitcode | tr -d '\r'` || exitcode=1
  rm -f exitcode
  exit $exitcode
fi
