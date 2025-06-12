# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.

# Standalone makefile for the trade_sim example applications.

.PHONY: all clean
.DEFAULT_GOAL := all

include Makefile-top.inc

ZF_CFLAGS = \
  $(ZF_CFLAGS_COMMON) \
  -DNDEBUG

BIN_ROOT := $(CURDIR)/..
OBJ_CURRENT := $(CURDIR)

CLINK := $(CC)
LDFLAGS += -lciul1

# Link against the installed libraries.
ZF_SHARED_LIB := -lonload_zf
ZF_STATIC_LIB := -lonload_zf_static

%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(ZF_CFLAGS_COMPONENT) $(CXXFLAGS) $(CFLAGS_TOP) -c $< -o $@

include Makefile.inc

clean:
	rm -rf $(TEST_OBJS) $(BIN_SHARED) $(BIN_STATIC)
