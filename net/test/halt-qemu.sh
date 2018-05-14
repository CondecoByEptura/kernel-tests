#!/bin/sh
# The net_test.sh script in the root filesystem always calls 'halt', which
# causes UML to exit, but a normal machine (and virtual machine) will not
# exit when halted, which is what we actually want. Remap to 'poweroff'.
/sbin/halt -p "$@"
