#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016-2024 Advanced Micro Devices, Inc.

if [ "$(id -u)" == "0" ]; then
function sudo() {
    "$@"
}
fi

dir=$(dirname "$0")
zftcppingpong2="${dir}/zftcppingpong2"

if [ -n "$2" ]; then
    TEST_RUN_PREFIX="$2"
fi

# Create a file with some random data to echo
datafile_in=$(mktemp /tmp/XXXXXX.data)
datafile_out=$(mktemp /tmp/XXXXXX.data)
dd if=/dev/urandom of=$datafile_in bs=1M count=1 &> /dev/null


function get_port() {
  # Cycle through ports every five minutes to steer clear of 2MSL.
  port=$((2000 + $(date +%s%N) / 10**8 % 3000))
  echo $port;
}


function print_result {
    rtn=$1
    test_name="$(basename $0) with shim: $2"
    if [ $rtn -eq 0 ]; then
        echo "ok - ${test_name}"
    else
        echo "not ok - ${test_name}"
        echo "#   Failed test '${test_name}'"
        if [ $rtn -eq 124 ]; then
            echo "#   Test timed out after $t seconds"
        else
            echo "#   Test failed with err $rtn"
        fi
    fi
}

function data_pong {
    sport=$(get_port)
    cport=$(( $sport + 1))
    test_extra=$1

    timeout $t nc -l ${sport} < $datafile_in > $datafile_out &

    while :; do
	# Wait for nc to open a listening socket before starting zftcppingpong2
	netstat --listen --numeric-ports --protocol=inet | \
	    grep "0\.0\.0\.0:${sport}\(\s\)*0\.0\.0\.0:\*" &> /dev/null
	# Check the return value from grep; 0 => matching entry found
	if [ $? -eq 0 ]; then
	    break
	fi
    done

    ZF_ATTR="emu=3;interface=tunzf;${EXTRA_ZF_ATTR};${ZF_ATTR_EXTRA}" \
      ${TEST_RUN_PREFIX-/usr/bin/timeout ${pong_timeout}} \
      "${zftcppingpong2}" -d pong 192.168.0.2:${cport} 192.168.0.1:${sport}

    # Store the return value from zftcppingpong2 and then wait for nc to finish
    rc=$?
    wait

    # We succeed iff zftcppingpong2 succeeded and the data was not corrupted.
    if [ $rc -eq 0 ]; then
        diff $datafile_in $datafile_out 1>&2
        rc=$?
        [ $rc -eq 0 ] || echo "#   Data not echoed back successfully"
    fi
    print_result $rc "data pong using tun interface $1"
}

echo "1..9"

t=60
# Delay between running "pong" and "ping" processes.
delay=1.0
pong_timeout=$(echo "${t} + ${delay}" | bc -l)
ping_timeout=${t}

sudo ip tuntap add mode tun user $(id -nu) tunzf
sudo ifconfig tunzf 192.168.0.1/24 up
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind"


# First a normal test
data_pong ""

# a normal test with small MTU
ZF_ATTR_EXTRA="emu_mtu=576" data_pong "small MTU"

# Then with some loss
sudo tc qdisc add dev tunzf root netem loss random "2%"
data_pong "with loss"
sudo tc qdisc del dev tunzf root netem loss random "2%"

# Then with some reordering
sudo tc qdisc add dev tunzf root netem delay 1ms reorder "90%" "50%"
data_pong "with reordering"
sudo tc qdisc del dev tunzf root netem delay 1ms reorder "90%" "50%"

# Then with some duplication
sudo tc qdisc add dev tunzf root netem duplicate "2%"
data_pong "with duplication"
sudo tc qdisc del dev tunzf root netem duplicate "2%"

# Then with all the plagues
sudo tc qdisc add dev tunzf root netem loss random "2%" delay 1ms reorder "90%" "50%" duplicate "2%"
data_pong "with all the plagues"

# Then with all the plagues and small MTU
# Note: we want to execute all the code paths small MSS might affect
ZF_ATTR_EXTRA="emu_mtu=576" data_pong "with all the plagues and small MTU # TODO bug 66429"
sudo tc qdisc del dev tunzf root


rm $datafile_in
rm $datafile_out

sudo ifconfig tunzf down
sudo ip tuntap delete mode tun tunzf
sudo sh -c "echo 0 > /proc/sys/net/ipv4/ip_nonlocal_bind"

rm -f /dev/shm/zf_emu_*
port=$(get_port)

ZF_ATTR="emu=1;interface=b2b0;emu_shmname=tcpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${pong_timeout} \
    "${zftcppingpong2}" ping 127.0.0.1:${port} &
pid=$!

# Give the 'pong' side a chance to start up.
sleep ${delay}

ZF_ATTR="emu=1;interface=b2b1;emu_shmname=tcpsanity;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${ping_timeout} \
    "${zftcppingpong2}" pong 127.0.0.2:${port} 127.0.0.1:${port}
print_result $? "latency ping-pong using back-to-back shim"

kill $pid &> /dev/null
wait


# Run zftcppingpong2 via a pair of tun interfaces so that netem can be used
sudo ip tuntap add mode tun user $(id -nu) tunzf1
sudo ifconfig tunzf1 192.168.0.2/24 up
sudo ip tuntap add mode tun user $(id -nu) tunzf2
sudo ifconfig tunzf2 192.168.1.2/24 up
old_ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
old_ip_nonlocal_bind=$(cat /proc/sys/net/ipv4/ip_nonlocal_bind)
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind"
for intf in tunzf{1,2}; do
  for param in route_localnet forwarding; do
    sudo sh -c "echo 1 > /proc/sys/net/ipv4/conf/${intf}/${param}"
  done
done

# Add some loss to one side
sudo tc qdisc add dev tunzf1 root netem loss random "1%"

port=$(get_port)

ZF_ATTR="emu=3;interface=tunzf1;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${pong_timeout} \
       "${zftcppingpong2}" -s 1 -i 1000 ping 192.168.0.1:$port &
pid=$!
sleep ${delay}
ZF_ATTR="emu=3;interface=tunzf2;${EXTRA_ZF_ATTR}" /usr/bin/timeout ${ping_timeout} \
       "${zftcppingpong2}" -s 1 -i 1000 pong \
       192.168.1.1:$port 192.168.0.1:$port
print_result $? "latency ping-pong with loss using tun"
kill $pid &> /dev/null
wait

sudo tc qdisc del dev tunzf1 root netem loss random "1%"
sudo ifconfig tunzf1 down
sudo ip tuntap delete mode tun tunzf1
sudo ifconfig tunzf2 down
sudo ip tuntap delete mode tun tunzf2
sudo sh -c "echo $old_ip_forward > /proc/sys/net/ipv4/ip_forward"
sudo sh -c "echo $old_ip_nonlocal_bind > /proc/sys/net/ipv4/ip_nonlocal_bind"
# $INTF/route_localnet settings are gone as tun interfaces have been deleted
exit 0 # the cleanup might fail, not a problem in namespace
