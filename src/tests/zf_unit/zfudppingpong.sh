#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016-2024 Advanced Micro Devices, Inc.

if [ "$(id -u)" == "0" ]; then
function sudo() {
    "$@"
}
fi

rc=0
dir=$(dirname "$0")
zfudppingpong="${dir}/../zf_apps/static/zfudppingpong"

function print_result {
    rtn=$?
    if [ $rtn -eq 0 ]; then
        echo "ok - zfudppingpong with shim: $1"
    else
        rc=$rtn
        echo "not ok - zfudppingpong with shim: $1 $2"
        echo "#   Failed test 'zfudppingpong with shim: $1'"
        if [ $rtn -eq 124 ]; then
            echo "#   Test timed out after $t seconds"
        fi
    fi
}

echo "1..4"

rm -f /dev/shm/zf_emu_*

t=5
ZF_ATTR="emu=2;interface=lo;${EXTRA_ZF_ATTR}" /usr/bin/timeout $t "${zfudppingpong}" -i 100000 ping 127.0.0.1:20101 127.0.0.1:20101

print_result "loopback"

rm -f /dev/shm/zf_emu_*

# Delay between running "pong" and "ping" processes.
delay=1.0
pong_timeout=$(echo "${t} + ${delay}" | bc -l)
ping_timeout=${t}

ZF_ATTR="emu=1;interface=b2b0;emu_shmname=udpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${pong_timeout} "${zfudppingpong}" -i 100000 pong 127.0.0.1:20101 127.0.0.2:20102 &

# Give the 'pong' side a chance to start up.
sleep ${delay}

ZF_ATTR="emu=1;interface=b2b1;emu_shmname=udpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${ping_timeout} "${zfudppingpong}" -i 100000 ping 127.0.0.2:20102 127.0.0.1:20101

print_result "back to back ping"
wait
print_result "back to back pong"

rm -f /dev/shm/zf_emu_*

sudo ip tuntap add mode tun user $(id -nu) tunzf
sudo ifconfig tunzf 192.168.0.1/24 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind"
socat udp-recvfrom:22222,reuseaddr,fork udp-sendto:192.168.0.2:22222,reuseaddr,bind=192.168.0.1:22222 &
pid=$!

# Give the 'pong' side a chance to start up.
sleep ${delay}

sudo env ZF_ATTR="emu=3;interface=tunzf;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${ping_timeout} "${zfudppingpong}" -i 10000 ping 192.168.0.2:22222 192.168.0.1:22222

print_result "using tun interface "

kill $pid
wait

rm -f /dev/shm/zf_emu_*

sudo ifconfig tunzf down
sudo ip tuntap delete mode tun tunzf
sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_nonlocal_bind"
exit $rc # the cleanup might fail, not a problem in namespace
