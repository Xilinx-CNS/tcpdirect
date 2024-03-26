# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.

# Standalone makefile for the ZF example applications.

.PHONY: all clean
.DEFAULT_GOAL := all

include Makefile-top.inc

ZF_CFLAGS_TOP = \
  -DNDEBUG

BIN_ROOT := $(CURDIR)/..
OBJ_CURRENT := $(CURDIR)

CLINK := $(CC)

# Link against the installed libraries.
ZF_SHARED_LIB := -lonload_zf
ZF_STATIC_LIB := -lonload_zf_static

%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(ZF_CFLAGS_COMPONENT) $(CFLAGS) $(ZF_CFLAGS_TOP) -c $< -o $@

include Makefile.inc

clean:
	rm -rf $(TEST_OBJS) $(BIN_SHARED) $(BIN_STATIC)
