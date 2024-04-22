# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2015-2024 Advanced Micro Devices, Inc.

.SUFFIXES:
.PHONY: all clean
.DEFAULT_GOAL := all

TOP := $(patsubst %/,%,$(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

include Makefile.onload
include Makefile-top.inc

# Use Onload's build-tree structure, unless overridden.
ZF_BUILD_ROOT ?= build/$(ONLOAD_UL_BUILD_NAME)

SRC_ROOT := src
LIB_ROOT = $(ZF_BUILD_ROOT)/lib
BIN_ROOT = $(ZF_BUILD_ROOT)/bin
OBJ_ROOT = $(ZF_BUILD_ROOT)/obj

# These paths are evaulated each time they are referenced so are always
# relative to the current makefile
SRC_CURRENT = $(dir $(lastword $(MAKEFILE_LIST)))
OBJ_CURRENT = $(SRC_CURRENT:$(SRC_ROOT)/%=$(OBJ_ROOT)/%)

ifndef CC
  CC := gcc
endif

ifndef CLINK
  CLINK := $(CC)
endif

ifndef OBJCOPY
  export OBJCOPY := $(shell $(CC) -print-prog-name=objcopy)
endif

ZF_CFLAGS_TOP = \
  -Isrc/include \
  -MD

ifeq ($(NDEBUG),1)
  ZF_CFLAGS_TOP += -DNDEBUG=1
else
  ZF_CFLAGS_TOP += -g
endif

# Generic rule to build most object files
$(OBJ_ROOT)/%.o: $(SRC_ROOT)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(ZF_CFLAGS_COMPONENT) $(CFLAGS) $(ZF_CFLAGS_TOP) -c $< -o $@


ifeq ($(ZF_DEVEL),1)
  ZF_CFLAGS_TOP += -DZF_DEVEL
endif

include src/lib/zf/Makefile.inc

ifeq ($(ZF_DEVEL),1)
  include src/lib/zf/shim/Makefile.inc
  include src/tests/zf_unit/Makefile.inc
endif

include src/tests/trade_sim/Makefile.inc
include src/tools/zf/Makefile.inc
include src/tests/zf_apps/Makefile.inc
include src/tests/zf_internal/Makefile.inc

# We use packetdrill for some tests, but can cope without it if not present
ifneq ("$(wildcard ../packetdrill-tcpdirect/Makefile.inc)", "")
	include ../packetdrill-tcpdirect/Makefile.inc
endif

include $(shell find $(OBJ_ROOT) -name *.d 2>/dev/null)

tarball:
	scripts/zf_make_tarball 

clean:
	rm -rf $(ZF_BUILD_ROOT)
