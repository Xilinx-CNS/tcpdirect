# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.
TEST_APPS := trader_tcpdirect_ds_efvi trader_tcpdirect_ds_efvi_ct_rx

TEST_OBJS := $(TEST_APPS:%=$(OBJ_CURRENT)/%.o)

BIN_SHARED := $(BIN_ROOT)/trade_sim/shared
BIN_STATIC := $(BIN_ROOT)/trade_sim/static

SHARED_APP_BINS := $(TEST_APPS:%=$(BIN_SHARED)/%)
STATIC_APP_BINS := $(TEST_APPS:%=$(BIN_STATIC)/%)
APP_BINS := $(SHARED_APP_BINS) $(STATIC_APP_BINS)

$(SHARED_APP_BINS): $(BIN_SHARED)/%: $(OBJ_CURRENT)/%.o $(OBJ_CURRENT)/utils.o $(ZF_SHARED_LIB) $(CIUL_LIB)
$(STATIC_APP_BINS): $(BIN_STATIC)/%: $(OBJ_CURRENT)/%.o $(OBJ_CURRENT)/utils.o $(ZF_STATIC_LIB) $(CIUL_LIB)

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS := -I$(ONLOAD_TREE)/src/include
endif

# For compatibility with old compilers, use gnu99 rather than, say, c11.
$(TEST_OBJS): ZF_CFLAGS_COMPONENT := -std=gnu99 $(ZF_CFLAGS_COMMON) $(ONLOAD_CFLAGS)

$(APP_BINS):
	@mkdir -p $(dir $@)
	+$(CLINK) $^ -lm -lpthread -lrt -ldl $(LDFLAGS) -o $@

.PHONY: trade_sim
all: trade_sim
trade_sim: $(APP_BINS)
