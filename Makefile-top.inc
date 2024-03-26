# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2022 Advanced Micro Devices, Inc.

# Shared by all the stand-alone/top-level makefiles

ZF_CFLAGS_COMMON = \
  -O2 \
  -mtune=native \
  -m64 \
  -Wall \
  -Werror \
  -Wundef \
  -Wpointer-arith \
  -Wno-unused-result \
  -Wno-stringop-truncation \
  -Wno-format-truncation \
  -Wno-ignored-attributes

ZF_CXXFLAGS_COMMON = \
  -x c++ \
  -std=c++17 \
  -Wimplicit-fallthrough=2 \
  -Wno-literal-suffix \
  -fno-exceptions \
  -fno-threadsafe-statics \
  -Wno-address-of-packed-member
