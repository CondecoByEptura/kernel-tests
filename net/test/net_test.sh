#!/bin/bash
uname -a
set

python -c 'print 1001'
python -v -c 'print 1002'
python -v -c 'print 1003'
python -vv -c 'print 1004'
python -S -c 'print 1005'
python -Sv -c 'print 1006'
python -Sv -c 'print 1007'
python -Svv -c 'print 1008'
python -s -c 'print 1009'
python -sv -c 'print 1010'
python -sv -c 'print 1011'
python -svv -c 'print 1012'
python -sS -c 'print 1013'
python -sSv -c 'print 1014'
python -sSv -c 'print 1015'
python -sSvv -c 'print 1016'

python -E -c 'print 1001a'
python -Ev -c 'print 1002a'
python -Ev -c 'print 1003a'
python -Evv -c 'print 1004a'
python -ES -c 'print 1005a'
python -ESv -c 'print 1006a'
python -ESv -c 'print 1007a'
python -ESvv -c 'print 1008a'
python -Es -c 'print 1009a'
python -Esv -c 'print 1010a'
python -Esv -c 'print 1011a'
python -Esvv -c 'print 1012a'
python -EsS -c 'print 1013a'
python -EsSv -c 'print 1014a'
python -EsSv -c 'print 1015a'
python -EsSvv -c 'print 1016a'

python -B -c 'print 1001b'
python -Bv -c 'print 1002b'
python -Bv -c 'print 1003b'
python -Bvv -c 'print 1004b'
python -BS -c 'print 1005b'
python -BSv -c 'print 1006b'
python -BSv -c 'print 1007b'
python -BSvv -c 'print 1008b'
python -Bs -c 'print 1009b'
python -Bsv -c 'print 1010b'
python -Bsv -c 'print 1011b'
python -Bsvv -c 'print 1012b'
python -BsS -c 'print 1013b'
python -BsSv -c 'print 1014b'
python -BsSv -c 'print 1015b'
python -BsSvv -c 'print 1016b'

python -BE -c 'print 1001c'
python -BEv -c 'print 1002c'
python -BEv -c 'print 1003c'
python -BEvv -c 'print 1004c'
python -BES -c 'print 1005c'
python -BESv -c 'print 1006c'
python -BESv -c 'print 1007c'
python -BESvv -c 'print 1008c'
python -BEs -c 'print 1009c'
python -BEsv -c 'print 1010c'
python -BEsv -c 'print 1011c'
python -BEsvv -c 'print 1012c'
python -BEsS -c 'print 1013c'
python -BEsSv -c 'print 1014c'
python -BEsSv -c 'print 1015c'
python -BEsSvv -c 'print 1016c'

echo Z
python -c 'print 99'

ip link set lo up

echo Y
python -c 'print 98'

ip link set lo mtu 16436

echo X
python -c 'print 97'

ip link set eth0 up


echo A
python -c 'print 0'
echo B
python -c 'import fcntl; print 1'
echo C
python -c 'import struct; print 2'
echo D
python -c 'import fcntl, struct; print 3'
echo E
python -c 'import fcntl, struct; print 4' 3>/dev/random
echo F
python <<EOF
print 5
EOF
echo G
python <<EOF
import fcntl
print 6
EOF
echo H
python <<EOF
import struct
print 7
EOF
echo I
python <<EOF
import fcntl, struct
print 8
EOF
echo J

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
  trap "exec /bin/bash" ERR EXIT
fi

echo -e "Running $net_test $net_test_args\n"
$net_test $net_test_args

# Write exit code of net_test to a file so that the builder can use it
# to signal failure if any tests fail.
echo $? >$net_test_exitcode
