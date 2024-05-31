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
zfsend="${dir}/../zf_apps/static/zfsend"

echo "1..5"
timeout_sec=5

function print_result {
    local rtn=$?
    local ttl=$1
    if [ $rtn -eq 0 ]; then
        echo "ok - zfudpttl with shim: $ttl"
    else
        rc=$rtn
        echo "not ok - zfudpttl with shim: $ttl $rtn"
        echo "#   Failed test 'zfudpttl with shim: $ttl'"
    fi
}

if [ -a /dev/shm/zf_emu_any ]; then
	unlink /dev/shm/zf_emu_any
fi

# Delay between running tcpdump and zfsend processes
delay=0.5
timeout=$(echo "${timeout_sec} + ${delay}" | bc -l)

# setup
sudo ip tuntap add mode tun user $(id -nu) tunzf
sudo ifconfig tunzf 192.168.0.1/24 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind"

# default ttl (64)
ttl=64
sudo /usr/bin/timeout $timeout tcpdump -i tunzf -v -c 1 udp 2>&1 | grep -q "ttl $ttl" &
sleep ${delay}
sudo env ZF_ATTR="emu=3;interface=tunzf;${EXTRA_ZF_ATTR}" "${zfsend}" -i 1 192.168.0.2:22222 192.168.0.1:22222 > /dev/null
wait $!
print_result $ttl

# smaller ttl
ttl=5
sudo /usr/bin/timeout $timeout tcpdump -i tunzf -v -c 1 udp 2>&1 | grep -q "ttl $ttl" &
sleep ${delay}
sudo env ZF_ATTR="emu=3;interface=tunzf;udp_ttl=$ttl;${EXTRA_ZF_ATTR}" "${zfsend}" -i 1 192.168.0.2:22222 192.168.0.1:22222 > /dev/null
wait $!
print_result $ttl

# larger ttl
ttl=100
sudo /usr/bin/timeout $timeout tcpdump -i tunzf -v -c 1 udp 2>&1 | grep -q "ttl $ttl" &
sleep ${delay}
sudo env ZF_ATTR="emu=3;interface=tunzf;udp_ttl=$ttl;${EXTRA_ZF_ATTR}" "${zfsend}" -i 1 192.168.0.2:22222 192.168.0.1:22222 > /dev/null
wait $!
print_result $ttl

# invalid ttl=0
ttl=0
sudo env ZF_ATTR="emu=3;interface=tunzf;udp_ttl=$ttl;${EXTRA_ZF_ATTR}" "${zfsend}" -i 1 192.168.0.2:22222 192.168.0.1:22222 2>&1 | grep -q "rc=-22" # invalid arg
print_result $ttl

# invalid ttl>255
ttl=300
sudo env ZF_ATTR="emu=3;interface=tunzf;udp_ttl=$ttl;${EXTRA_ZF_ATTR}" "${zfsend}" -i 1 192.168.0.2:22222 192.168.0.1:22222 2>&1 | grep -q "rc=-22" # invalid arg
print_result $ttl

# teardown
sudo ifconfig tunzf down
sudo ip tuntap delete mode tun tunzf
sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_nonlocal_bind"
exit $rc # the cleanup might fail, not a problem in namespace
