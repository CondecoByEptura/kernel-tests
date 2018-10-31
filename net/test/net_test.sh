#!/bin/bash
if [[ -n "${entropy}" ]]; then
  echo "adding entropy from hex string [${entropy}]" 1>&2

  # In kernel/include/uapi/linux/random.h RNDADDENTROPY is defined as
  # _IOW('R', 0x03, int[2]) =(R is 0x52)= 0x40085203 = 1074287107
  python 3>/dev/random <<EOF
import fcntl, struct
rnd = '${entropy}'.decode('hex')
fcntl.ioctl(3, 0x40085203, struct.pack('ii', len(rnd) * 8, len(rnd)) + rnd)
EOF

  # This is probably not truly required, but let us give the system
  # just a moment to catch up.  Mostly this just makes sure that
  # the 'random: crng init done' kernel message has a chance to print
  # out before we continue...
  sleep 0.2
fi

# In case IPv6 is compiled as a module.
[ -f /proc/net/if_inet6 ] || insmod $DIR/kernel/net-next/net/ipv6/ipv6.ko

# Minimal network setup.
ip link set lo up
ip link set lo mtu 16436
ip link set eth0 up

# Allow people to run ping.
echo "0 65536" > /proc/sys/net/ipv4/ping_group_range

# Read environment variables passed to the kernel to determine if script is
# running on builder and to find which test to run.

if [ "$net_test_mode" != "builder" ]; then
  # Fall out to a shell once the test completes or if there's an error.
  trap "exec /usr/bin/setsid /bin/bash </dev/tty0 >/dev/tty0 2>/dev/tty0" ERR EXIT
fi

echo -e "Running $net_test $net_test_args\n"
$net_test $net_test_args

# Write exit code of net_test to a file so that the builder can use it
# to signal failure if any tests fail.
echo $? >$net_test_exitcode
