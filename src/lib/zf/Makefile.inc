# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.

PUBLIC_LIB_SRCS := zf.c log.c attr.c stack.c pool.c udp_rx.c rx.c udp_tx.c \
	    muxer.c tcp.c tcp_in.c tcp_out.c tcp_core.c rx_table.c zf_alts.c \
	    lazy_alloc.c x86.c timers.c cplane.c zf_tcp.c zf_stackdump.c \
	    dshm.c zf_alt_buffer_model.c zf_ds.c bond.c tx_warm.c

# Source files that are not distributed, living in private/.
PRIVATE_LIB_SRCS := stack_fast.c stack_alloc.c tcp_fast.c reactor.c
ifeq ($(ZF_DEVEL),1)
  PRIVATE_LIB_SRCS += zf_emu_superbuf.c zf_emu.c
else
  PRIVATE_LIB_SRCS += zf_emu_stub.c
endif

PUBLIC_LIB_OBJS := $(PUBLIC_LIB_SRCS:%.c=$(OBJ_CURRENT)/%.o)
PRIVATE_LIB_OBJS := $(PRIVATE_LIB_SRCS:%.c=$(OBJ_CURRENT)/private/%.o)
LIB_OBJS := $(PUBLIC_LIB_OBJS) $(PRIVATE_LIB_OBJS)

ZF_MAJOR_VERSION := 1
ZF_MINOR_VERSION := 2
ZF_MICRO_VERSION := 1

ZF_STATIC_LIB := $(LIB_ROOT)/libonload_zf_static.a

ZF_SONAME_BARE := libonload_zf.so
ZF_SONAME   := $(ZF_SONAME_BARE).$(ZF_MAJOR_VERSION)
ZF_REALNAME   := $(ZF_SONAME).$(ZF_MINOR_VERSION).$(ZF_MICRO_VERSION)

ZF_SHARED_LIB := $(LIB_ROOT)/$(ZF_SONAME_BARE)
ZF_SHARED_LIB_LINK := $(LIB_ROOT)/$(ZF_SONAME)

ZF_SEMANTIC_VERSION := $(shell awk '/version/ {print $$2}' \
                        $(SRC_ROOT)/../versions.yaml)
ZF_GIT_VERSION_INFO := $(shell git show -s --format="format:%h %cd" \
                        --date=short HEAD)
ZF_GIT_BRANCH_INFO  := $(shell git symbolic-ref -q --short HEAD)

# For the full build, we just add the list of private sources to the list of
# public sources and build the whole lot together.  However, we also have an
# intermediate phony target that just compiles the public sources, the build
# logs from which can be shared with customers once we've checked that those
# logs contain no references to private headers.
public_objects: $(PUBLIC_OBJS)
.PHONY: public_objects

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS  := -I$(ONLOAD_TREE)/src/include \
                    -I$(ONLOAD_UL_BUILD_DIR)/include \
                    '-DONLOAD_VERSION_HDR="onload_version.h"'
else
  ONLOAD_CFLAGS  := '-DONLOAD_VERSION_HDR=<onload/onload_version.h>'
endif
# ZF sources are C files that are built as C++ using the cc command.  The
# reasons being:
#  * files can stay .c
#  * gcc does not enable exceptions nor link with stdcpp library (as opposed to
#    C++).
$(LIB_OBJS): ZF_CFLAGS_COMPONENT := \
  $(ZF_CFLAGS_COMMON) \
  $(ZF_CXXFLAGS_COMMON) \
  -fvisibility=hidden \
  $(ONLOAD_VERSION_CFLAGS) \
  $(ONLOAD_CFLAGS) \
  -fPIC \
  '-DZF_VERSION="$(ZF_SEMANTIC_VERSION) \
  $(ZF_GIT_VERSION_INFO) \
  $(ZF_GIT_BRANCH_INFO)"'

LDEP := $(CITOOLS_LIB) $(CIUL_LIB)

$(LIB_OBJS): $(ONLOAD_VERSION_HDR)

$(ZF_SHARED_LIB): $(LIB_OBJS) $(LDEP)
	@mkdir -p $(dir $@)
	$(CLINK) -shared -fPIC $^ -e zf_print_version -Wl,-soname,$(ZF_SONAME),--exclude-libs,libciul1.a -o $@

$(ZF_SHARED_LIB_LINK) $(ZF_SHARED_LIB_LINK_BARE): $(ZF_SHARED_LIB)
	ln -fs $(shell basename $^) $@

$(ZF_STATIC_LIB): $(LIB_OBJS) $(LDEP)
	@mkdir -p $(dir $@)
	$(CLINK) -fPIC -nostdlib -z combreloc -r $^ -o $@

.PHONY: lib
all: lib
lib: $(ZF_SHARED_LIB_LINK) $(ZF_STATIC_LIB)
