# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) 2020-2022 Advanced Micro Devices, Inc.
TOOLS := zf_stackdump

TOOL_OBJS := $(TOOLS:%=$(OBJ_CURRENT)/%.o)
TOOL_BINS := $(TOOLS:%=$(BIN_ROOT)/%)
STRIPPED_BINS := $(TOOLS:%=$(BIN_ROOT)/stripped/%)

$(TOOL_OBJS): ZF_CFLAGS_COMPONENT := \
  $(ZF_CFLAGS_COMMON) \
  -I$(ONLOAD_TREE)/src/include \
  -g \
  $(ZF_CXXFLAGS_COMMON) \
  $(CP_INTF_VER_CFLAGS)

$(TOOL_OBJS): $(CP_INTF_VER_HDR)

$(TOOL_BINS): $(BIN_ROOT)/% : $(OBJ_CURRENT)/%.o $(ZF_STATIC_LIB)
	@mkdir -p $(dir $@)
	$(CLINK) -m64 -O2 -g -Wl,-E $^ $(STATIC_ZF_LIB) -lm -lpthread -lrt -ldl -o $@

$(STRIPPED_BINS): $(BIN_ROOT)/stripped/%: $(BIN_ROOT)/%
	@mkdir -p $(dir $@)
	strip $< -o $@

.PHONY: tools
all: tools
tools: $(STRIPPED_BINS)
