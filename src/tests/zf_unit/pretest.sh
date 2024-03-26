#!/bin/sh
#
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc.

# Script to prepare machine to run unit tests.

set -e

# Ensure that there's no state left over from previous back-to-back emu runs.
rm -f /dev/shm/zf_emu_*
