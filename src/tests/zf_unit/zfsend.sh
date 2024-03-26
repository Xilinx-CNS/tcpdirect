#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc.

if [ "$(id -u)" == "0" ]; then
function sudo() {
    "$@"
}
fi

dir=$(dirname "$0")
zfsend="${dir}/../zf_apps/static/zfsend"
zfsink="${dir}/../zf_apps/static/zfsink"

function print_result {
    rtn=$?
    if [ $rtn -eq 0 ]; then
        echo "ok - zfsend with shim: $1"
    else
        echo "not ok - zfsend with shim: $1 $2"
        echo "#   Failed test 'zfsend with shim: $1'"
        if [ $rtn -eq 124 ]; then
            echo "#   Test timed out after $t seconds"
        fi
    fi
}

# Delay between running "receive" and "send" processes.
delay=0.1
t=1

echo "Running zfsend test on b2b interface..."
# Start the receiver
echo "Starting UDP receive zocket..."
ZF_ATTR="emu=1;interface=b2b0;emu_shmname=udpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout $t "${zfsink}" 127.0.0.1:20101 127.0.0.1:20102 &
# Give the 'receive' side a chance to start up.
sleep ${delay}
# Start the sender
echo "Starting UDP transmit zocket..."
ZF_ATTR="emu=1;interface=b2b1;emu_shmname=udpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout $t "${zfsend}" -u -i 10 127.0.0.1:20102 127.0.0.1:20101

echo 1..1
print_result "b2b"

if [ -a /dev/shm/zf_emu_udpsanity ]; then
	unlink /dev/shm/zf_emu_udpsanity
fi

exit 0 # the cleanup might fail, not a problem in namespace
