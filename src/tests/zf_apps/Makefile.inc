# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.

STATS_LIB_SRCS := zf_stats.c zf_timer.c
STATS_LIB_OBJS := $(STATS_LIB_SRCS:%.c=$(OBJ_CURRENT)/%.o)

TEST_APPS := zfsink zfsend zfudppingpong zftcppingpong zfaltpingpong zftcpmtpong

TEST_OBJS := $(TEST_APPS:%=$(OBJ_CURRENT)/%.o)

BIN_SHARED := $(BIN_ROOT)/zf_apps/shared
BIN_STATIC := $(BIN_ROOT)/zf_apps/static

SHARED_APP_BINS := $(TEST_APPS:%=$(BIN_SHARED)/%)
STATIC_APP_BINS := $(TEST_APPS:%=$(BIN_STATIC)/%)
APP_BINS := $(SHARED_APP_BINS) $(STATIC_APP_BINS)

$(SHARED_APP_BINS): $(BIN_SHARED)/%: $(OBJ_CURRENT)/%.o $(ZF_SHARED_LIB)
$(STATIC_APP_BINS): $(BIN_STATIC)/%: $(OBJ_CURRENT)/%.o $(ZF_STATIC_LIB)

ifdef ONLOAD_TREE
  ONLOAD_CFLAGS := -I$(ONLOAD_TREE)/src/include
endif

# For compatibility with old compilers, use gnu99 rather than, say, c11.
$(TEST_OBJS): ZF_CFLAGS_COMPONENT := -std=gnu99 $(ZF_CFLAGS_COMMON) $(ONLOAD_CFLAGS)

$(APP_BINS): $(STATS_LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CLINK) $^ -lm -lpthread -lrt -o $@

.PHONY: zf_apps
all: zf_apps
zf_apps: $(APP_BINS)
