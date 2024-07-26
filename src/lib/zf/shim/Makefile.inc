# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2020-2022 Advanced Micro Devices, Inc.
#
# Used internally for tests

SOCKET_SHIM_SRCS := socket_shim.c socket_fd.c socket_common.c \
		    socket_udp.c socket_tcp.c socket_epoll.c
SOCKET_SHIM_OBJS := $(SOCKET_SHIM_SRCS:%.c=$(OBJ_CURRENT)/%.o)
SOCKET_SHIM_SO   := $(LIB_ROOT)/libzf_sockets.so

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS  := -I$(ONLOAD_TREE)/src/include \
                    -I$(ONLOAD_UL_BUILD_DIR)/include
endif

# ZF sources are C files that are built as C++ using the cc command.  The
# reasons being:
#  * files can stay .c
#  * gcc does not enable exceptions nor link with stdcpp library (as opposed to
#    C++).
$(SOCKET_SHIM_OBJS): ZF_CFLAGS_COMPONENT := \
  $(ZF_CFLAGS_COMMON) \
  $(ZF_CXXFLAGS_COMMON) \
  -fvisibility=hidden \
  $(ONLOAD_CFLAGS) \
  -fPIC

# Link the shim against the dynamic ZF library to make Runbench's life easier.
# If the shim is ever distributed, Runbench can use that instead, and we'd be
# better linking against the static library.
SHIM_LDEP := $(ZF_SHARED_LIB)
SHIM_LINKFLAGS := -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic -lm -ldl

$(SOCKET_SHIM_SO): $(SOCKET_SHIM_OBJS) $(SHIM_LDEP)
	@mkdir -p $(dir $@)
	$(CLINK) -shared -fPIC $^ $(SHIM_LINKFLAGS) -Wl,-soname,$(shell basename $(SOCKET_SHIM_SO)) -o $@

.PHONY: shim
all: shim
shim: $(SOCKET_SHIM_SO)
