#!/bin/bash

mount -t proc none /proc
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

if [ -e /proc/exitcode ]; then
	mount -t hostfs hostfs /host
else
	mount -t 9p -o trans=virtio,version=9p2000.L host /host
fi

test=$(cat /proc/cmdline | sed -re 's/.*net_test=([^ ]*).*/\1/g')
cd $(dirname $test)
./net_test.sh
poweroff -f
