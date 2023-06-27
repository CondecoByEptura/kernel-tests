#!/bin/bash

# Ugly sleep. We want to wait until the login prompt appeared. And then
# we run the script. Otherwise the output are mixed together.
sleep 60

# Parsing /proc/cmdline and export all the variables
PARAMS=""
if [ -e /proc/cmdline ]; then
    PARAMS=$(cat /proc/cmdline)
fi

for i in ${PARAMS}
do
    export ${i}
done

# Log output for qemu serial.
LOG_FILE=$(mktemp)
if [ x"${console}" != x"" ]; then
    if [ -e /dev/${console} ]; then
	LOG_FILE=/dev/${console}
    fi
fi

# Run the script
cd /
if [ x"${installer_script}" = x"" ]; then
    exit
fi
if [ ! -x "${installer_script}" ]; then
    exit
fi

${installer_script} > "${LOG_FILE}" 2>&1

# shutdown the machine.
shutdown -h 1
