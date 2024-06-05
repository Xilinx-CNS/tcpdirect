#!/bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016-2024 Advanced Micro Devices, Inc.

# With no parameters runs all tests found in $PDTF folder defined below
# Otherwise,
#
# packetdrill.sh test_sel [test_prefix]
#    test_sel is a keyword to select subset of tests
#    test_prefix is a command to precede invocation of packet drill with
#        (e.g. strace or gdb)
RUN_WITH_LINUX_STACK=${RUN_WITH_LINUX_STACK-0}

rc=0

function print_result {
    rtn=$1
    test_name="$(basename $0) with shim: $2"
    echo
    if [ $rtn -eq 0 ]; then
        echo "ok - ${test_name}"
    else
        rc=$rtn
        echo "not ok - ${test_name}"
        echo "#   Failed test '${test_name}'"
        if [ $rtn -eq 124 ]; then
            echo "#   Test timed out after $t seconds"
        else
            echo "#   Test failed with err $rtn"
        fi
    fi
    echo
}


# Runs a command, prefixing stdout by '# ' so as not to confuse the TAP stream.
function do_diag {
  # Run the command, piped (in effect, but preserving exit code) through sed.
  # We buffer the output line by line so that we still see it if we have to
  # kill the task.
  exec stdbuf -oL "$@" > >(sed 's/^/# '/)
}


PD=build/gnu_x86_64-zf-devel/obj/tests/packetdrill/packetdrill
PDTF="../packetdrill-tcpdirect/gtests/net/packetdrill/tests/zf/"
if [[ ! -e "$PD" || ! -d "$PDTF" ]]; then
  echo "1..0 # SKIP packetdrill not found, clone Xilinx-CNS/packetdrill-tcpdirect into a neighbouring directory to run these tests."
  exit 0
fi

SHIMLIB=$(readlink -f build/gnu_x86_64-zf-devel/lib/libzf_sockets.so)
ZFLIB=$(readlink -f build/gnu_x86_64-zf-devel/lib/libonload_zf.so)


TEST_RUN_PREFIX="$2"
TEST_SEL=$1
TESTS=$(cd $PDTF && find . -type f -name "*${TEST_SEL}*.pkt" | sort)

echo "1..$(( $(echo ${TESTS} | wc -w) ))"

ip tuntap add mode tun user $(id -nu) tunzf

# insights into packetdrill
PD_CLIENT_IP=192.168.0.1
PD_SERVER_IP=192.168.0.2
IF_IP=192.168.0.3
PD_NETMASK=8 # PD uses /16 and route of 192.0./16 net we simply widen netmask
# so that zf can think this is local route, which prevents handover.

# Picture this:
# Our host is in fact running packetdrill server, which performs
# raw packet capture and raw packet injection on its tunzf device
# While client runs on a remote end of tunzf device, which is controlled and set up
# in proprietary manner by zf stack itself.
# Packetdrill have no means to configure this device, so we fool it by passing
# device foo.
# Control connections goes over loopback device, zf will handover this
# socket.

ifconfig lo up # up this if running in netns
# add this address so that os sockets in ZF can get bound without global
# setting of option /proc/sys/net/ipv4/ip_nonlocal_bind
ip addr add dev lo $PD_CLIENT_IP/32
ifconfig tunzf $IF_IP/$PD_NETMASK up

TIMEOUT=15
echo '# starting server'
if [ $RUN_WITH_LINUX_STACK -eq 0 ]; then
do_diag \
  $PD -vvv --wire_server --wire_server_dev=tunzf --tcp_ts_tick_usecs=90000 --tolerance_usecs=10000 &
else
do_diag \
  $PD -vvv --wire_server --wire_server_dev=lo --tcp_ts_tick_usecs=90000 --tolerance_usecs=10000 &
fi

S=$!
sleep 0.5

for T in ${TESTS}; do

if [ ! -d /proc/$S ] ; then
  break
fi

TEST_RUN_PREFIX="${TEST_RUN_PREFIX:-timeout $TIMEOUT}"
echo '# starting client'
if [ $RUN_WITH_LINUX_STACK -eq 0 ]; then
  do_diag \
  ${TEST_RUN_PREFIX} \
  env LD_LIBRARY_PATH=$(dirname ${ZFLIB}) LD_PRELOAD=${SHIMLIB} \
      ZF_ATTR="n_bufs=1024;interface=tunzf;emu=3;tcp_delayed_ack=0;emu_tun_ip=$PD_CLIENT_IP;zfss_implicit_host=$PD_CLIENT_IP;${EXTRA_ZF_ATTR}" \
  $PD -vvv --wire_client --wire_server_ip=127.0.0.1 \
     --local_ip $PD_CLIENT_IP --remote_ip $PD_SERVER_IP \
     --wire_client_dev=foo --tcp_ts_tick_usecs=90000 --tolerance_usecs=10000 $PDTF/$T &
else
  do_diag \
  ${TEST_RUN_PREFIX} \
  $PD -vvv --wire_client --wire_server_ip=127.0.0.1 --wire_client_dev=lo --tcp_ts_tick_usecs=90000 --tolerance_usecs=10000 $PDTF/$T --non_fatal=packet &
fi

C=$!
wait $C
CR=$?

TODO=$(grep -o -P "# TODO.*" $PDTF/$T)
print_result $CR "client: $T $TODO"

sleep 1
done

# kill packetdrill server
kill $S
sleep 1
kill -9 $S
wait $S

# assume cleanup is done by implicit destruction of netns

exit $rc
