# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2020-2022 Advanced Micro Devices, Inc.
TOOLS := zf_stackdump

TOOL_OBJS := $(TOOLS:%=$(OBJ_CURRENT)/%.o)
TOOL_BINS := $(TOOLS:%=$(BIN_ROOT)/%)

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS  := -I$(ONLOAD_TREE)/src/include
endif

$(TOOL_OBJS): ZF_CFLAGS_COMPONENT := \
  $(ZF_CFLAGS_COMMON) \
  $(ONLOAD_CFLAGS) \
  -g \
  $(ZF_CXXFLAGS_COMMON)

$(TOOL_BINS): $(BIN_ROOT)/% : $(OBJ_CURRENT)/%.o $(ZF_STATIC_LIB)
	@mkdir -p $(dir $@)
	+$(CLINK) -m64 -O2 -g -Wl,-E $^ $(STATIC_ZF_LIB) -lm -lpthread -lrt -ldl -o $@

.PHONY: tools
all: tools
tools: $(TOOL_BINS)
