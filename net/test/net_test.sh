#!/bin/bash
add_entropy() {
  local -r bits_of_entropy_per_character="$1"
  local -r random_characters="$2"

  # kernel/include/uapi/linux/random.h: RNDADDENTROPY = _IOW('R', 0x03, int [2]) =(R is 0x52)= 0x40085203 = 1074287107
  python <<-EOF
	import fcntl, os, struct
	RNDADDENTROPY = 1074287107
	fd = os.open('/dev/random', os.O_WRONLY)
	rnd = '${random_characters}'
	entropy = len(rnd) * ${bits_of_entropy_per_character}
	fcntl.ioctl(fd, RNDADDENTROPY, struct.pack('ii%is' % len(rnd), entropy, len(rnd), rnd))
	os.close(fd)
EOF
}

if [[ -n "${random_initializer}" ]]; then
  echo "entropy available: $(< /proc/sys/kernel/random/entropy_avail)" 1>&2
  echo "adding entropy from hex string [${random_initializer}]" 1>&2
  # We assume the string is a hex encoded string, hence only 4 bits of entropy
  # per character. Experience shows we need at least 128 bits of entropy for
  # crng init to complete, hence we need at least 32 hex chars from kcmdline,
  # we'll get 64 just to be safe.
  add_entropy 4 "${random_initializer}"
  # Give the system a moment to catch up.
  sleep 0.2
  echo "entropy available: $(< /proc/sys/kernel/random/entropy_avail)" 1>&2
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
  trap "exec /bin/bash" ERR EXIT
fi

echo -e "Running $net_test $net_test_args\n"
$net_test $net_test_args

# Write exit code of net_test to a file so that the builder can use it
# to signal failure if any tests fail.
echo $? >$net_test_exitcode
