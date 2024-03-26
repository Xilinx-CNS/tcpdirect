# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.
INT_APPS := zfudppingpong_sleep zftcppingpong_sleep

INT_OBJS := $(INT_APPS:%=$(OBJ_CURRENT)/%.o)

BIN_SHARED := $(BIN_ROOT)/zf_internal/shared
BIN_STATIC := $(BIN_ROOT)/zf_internal/static

SHARED_INT_BINS := $(INT_APPS:%=$(BIN_SHARED)/%)
STATIC_INT_BINS := $(INT_APPS:%=$(BIN_STATIC)/%)
INT_BINS := $(SHARED_INT_BINS) $(STATIC_INT_BINS)

$(SHARED_INT_BINS): $(BIN_SHARED)/%: $(OBJ_CURRENT)/%.o $(ZF_SHARED_LIB)
$(STATIC_INT_BINS): $(BIN_STATIC)/%: $(OBJ_CURRENT)/%.o $(ZF_STATIC_LIB)

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS := -I$(ONLOAD_TREE)/src/include
endif

# For compatibility with old compilers, use gnu99 rather than, say, c11.
$(TEST_OBJS): ZF_CFLAGS_COMPONENT := -std=gnu99 $(ZF_CFLAGS_COMMON) $(ONLOAD_CFLAGS)

$(INT_BINS):
	@mkdir -p $(dir $@)
	$(CLINK) $^ -lm -lpthread -lrt -o $@

.PHONY: zf_internal
all: zf_internal
zf_internal: $(INT_BINS)
