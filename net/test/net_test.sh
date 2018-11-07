#!/bin/bash
echo "uname -a == [$(uname -a)]"
echo

echo "kernel command line [$(< /proc/cmdline)]"
echo

echo 'shell environment:'
env
echo

echo -n "net_test.sh (pid $$, parent ${PPID}, tty $(tty)) running [$0] with args"
for arg in "$@"; do
  echo -n " [${arg}]"
done
echo
echo

if [[ "$(tty)" == '/dev/console' ]]; then
  # setsid + /dev/tty{,AMA,S}0 allows bash's job control to work, ie. Ctrl+C/Z
  if [[ -c '/dev/tty0' ]]; then
    # exists in UML, does not exist on graphics/vga/curses-less QEMU
    con='/dev/tty0'
  elif [[ -c '/dev/ttyAMA0' ]]; then
    # Qemu for arm (note: /dev/ttyS0 also exists for exitcode)
    con='/dev/ttyAMA0'
  elif [[ -c '/dev/ttyS0' ]]; then
    # Qemu for x86 (note: /dev/ttyS1 also exists for exitcode)
    con='/dev/ttyS0'
  else
    # Can't figure it out, job control won't work, tough luck
    :
  fi

  echo "Currently tty[/dev/console], but it should be [${con}]..."

  if [[ -n "${con}" ]]; then
    # Redirect std{in,out,err} to the console equivalent tty
    # which actually supports all standard tty ioctls
    exec <"${con}" >&"${con}"

    # Re-executing if we were called with -c is too hard, hence this extra
    # check, but this should not happen due to how image is formed...
    if [[ -z "${BASH_EXECUTION_STRING}" ]]; then
      # Bash wants to be session leader, hence need for setsid
      echo "Re-executing..."
      exec /usr/bin/setsid /bin/bash "$@"
      # If the above exec fails, we just fall through...
      # (this implies failure to *find* setsid, not error return from bash,
      #  in practice due to image construction this cannot happen)
    fi
  fi
fi

# By the time we get here job control (ctrl+c in particular) should function.

if [[ -n "${entropy}" ]]; then
  echo "adding entropy from hex string [${entropy}]" 1>&2

  # In kernel/include/uapi/linux/random.h RNDADDENTROPY is defined as
  # _IOW('R', 0x03, int[2]) =(R is 0x52)= 0x40085203 = 1074287107
  /usr/bin/python 3>/dev/random <<EOF
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
  trap "exec /bin/bash" ERR EXIT
fi

echo -e "Running $net_test $net_test_args\n"
$net_test $net_test_args

# Write exit code of net_test to a file so that the builder can use it
# to signal failure if any tests fail.
echo $? >$net_test_exitcode
