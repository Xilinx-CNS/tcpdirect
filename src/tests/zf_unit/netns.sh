# ! /bin/bash
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2019-2024 Advanced Micro Devices, Inc.

# launches command given in arguments into brand new netns
# fixes up state of lo interface to be up

if [ "$1" != "--" ]; then
  # reexecute script with new netns
  exec unshare -n "$0" "--" "$@"
fi

# Jenkins VM do not have this in the path - required for ifconfig
export PATH=$PATH:/usr/sbin

echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_nonlocal_bind
echo 4096 > /proc/sys/vm/nr_hugepages
# we are in new namespace, get lo dev up and kick off the command
ifconfig lo up
shift

exec "$@"
