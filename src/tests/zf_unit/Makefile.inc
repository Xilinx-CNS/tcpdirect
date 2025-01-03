# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc.

# Test lists are divided based on configuration in two ways:
# * test configuration requirements
#    e.g. between those that use a TUN interface and those that not
# * variants of test configuration
#    allowing to run subsets of tests with various variants
UT_LOOP := zftest zfinit zfudprx zf_superbuf_reuse zftcprx zftcpcopyrx \
           zftcptx zfmulticast zftcp_muxer \
           zfds efrxtimestamping zftcprx_on14495
UT_LOOP2 := zftest zfinit zfudprx zf_superbuf_reuse zftcprx zftcpcopyrx \
            zftcptx zfmulticast zftcp_muxer \
            zfds efrxtimestamping zftcprx_on14495
UT_MISC := zfpool zfmuxer zfrxtable zfzockbuf \
          zfmultizock zftimers zflisten zfbackingsock zfzockfree \
          zfquiesce_waittw zfquiesce_nowaittw zfstackfree \
          zfshm zfattrs zfattr_getset \
          zfpending zftcp_full_sendq zfstackdump \
          zfbonding zfbonding_lacp zfmultizock_bond # these bonding tests should go to UT_LOOP but fail with vlan
UT_DELEGATED := zfdelegated
UT_B2B := zftcptimeouts zfovl zfreactorloop zfonlystack
UT_B2B_SB := zf_superbuf_buffer zf_superbuf_buffer_reuse zf_superbuf_multiapp_sanity \
            zf_superbuf_fallback zf_superbuf_stack_destroy zf_superbuf_locality \
						zf_superbuf_n_sleep zf_superbuf_sleepy_stacks
UT_ALTS := zfalternatives
UT_OTHER := zftcppingpong2
UT_SCRIPTS := zfudppingpong.sh zf_tcp_sanity.sh packetdrill.sh zfsend.sh zfudpttl.sh

# List of tests to skip unless ZF_RUN_SLOW_TESTS=1 (defaults to 1)
# NOTE: `zfovl` is not actually slow, but rather unstable on slow machines.
UT_SLOW := zf_superbuf_fallback zf_superbuf_stack_destroy zf_superbuf_locality \
           zf_superbuf_n_sleep zf_superbuf_sleepy_stacks zftcptimeouts \
	   zfreactorloop zfstackfree zfrxtable zftcprx zfovl

# List of tests to skip unless ZF_RUN_UNSTABLE_TESTS=1 (defaults to 0)
UT_UNSTABLE := zftimestamping $(UT_SCRIPTS)

# sort is required to remove duplicates
UT_ALL := $(sort \
  $(UT_LOOP) \
  $(UT_LOOP2) \
  $(UT_MISC) \
  $(UT_DELEGATED) \
  $(UT_B2B) \
  $(UT_B2B_SB) \
  $(UT_ALTS) \
  $(UT_OTHER))


ifdef ONLOAD_TREE
  ONLOAD_CFLAGS  := -I$(ONLOAD_TREE)/src/include
endif

UT_OBJS := $(UT_ALL:%=$(OBJ_CURRENT)/%.o)
$(UT_OBJS): $(ZF_SHARED_LIB_LINK)
$(UT_OBJS): ZF_CFLAGS_COMPONENT := \
  $(ZF_CFLAGS_COMMON) \
  $(filter-out -fno-exceptions -fno-threadsafe-statics,$(ZF_CXXFLAGS_COMMON)) \
  $(ONLOAD_CFLAGS) \
  -I$(SRC_CURRENT)


# zfquiesce_waittw and zfquiesce_nowaittw are built from the same source file
# with slightly different preprocessor definitions.
$(OBJ_CURRENT)/zfquiesce_waittw.o: \
	ZF_CFLAGS_COMPONENT += -DWAIT_FOR_TIME_WAIT=1
$(OBJ_CURRENT)/zfquiesce_nowaittw.o: \
	ZF_CFLAGS_COMPONENT += -DWAIT_FOR_TIME_WAIT=0

$(OBJ_CURRENT)/zfquiesce_nowaittw.o $(OBJ_CURRENT)/zfquiesce_waittw.o: \
  $(SRC_CURRENT)/zfquiesce.c
	@mkdir -p $(dir $@)
	$(CC) $(ZF_CFLAGS_COMPONENT) $(CFLAGS) $(ZF_CFLAGS_TOP) -c $< -o $@


UT_BINDIR := $(BIN_ROOT)/zf_unit

UT_BINS := $(UT_ALL:%=$(UT_BINDIR)/%)
$(UT_BINS): $(UT_BINDIR)/%: $(OBJ_CURRENT)/%.o
$(UT_BINS): $(OBJ_CURRENT)/../tap/tap.o
$(UT_BINS): $(ZF_STATIC_LIB)

$(UT_BINS):
	@mkdir -p $(dir $@)
	$(CLINK) $^ -lm -lpthread -lrt -ldl -lstdc++ -o $@

ENV := EF_VI_CTPIO_MODE=fast # default mode would slow down the tests considerably
# We would like the flexibility to use TODOs to indicate tests that *might*
# fail, rather than that they *must* fail.
UT_ENV := ALLOW_PASSING_TODOS=1

# Various test require various base configurations.
# With the loopback configuration we include some bonding tests.  In that case
# we will have more RX rings to fill, so need a higher number of buffers to
# run the tests.  Completely filling 4 rings of size 512 requires 2048 bufs,
# so bump up to 4096 to leave some spare.
TEST_LOOP_ZF_ATTR := n_bufs=4096 emu=2 interface=lo tcp_timewait_ms=1 tcp_wait_for_time_wait=1 log_file=/dev/null
TEST_B2B_SB_ZF_ATTR := emu=1 interface=lo2 emu_nic=3 tx_emu_nic=3
TEST_B2B_ZF_ATTR := n_bufs=1024 emu=1 interface=lo2
TEST_ALTS_ZF_ATTR := n_bufs=1024 tcp_timewait_ms=10 alt_count=8 alt_buf_size=16384 emu=2 interface=any1
TEST_SCRIPT_ZF_ATTR := max_sbufs=128
# tests running in parallel need distinct device names
# testloop needs for some reason real lo device (multicast tests)
containing = $(foreach v,$2,$(if $(findstring $1,$v),$v))
not-containing = $(foreach v,$2,$(if $(findstring $1,$v),,$v))
empty:=
space:= $(empty) $(empty)
join = $(subst $(space),;,$(1))
join_= $(subst $(space),_,$(1))

# Test usually can run in multiple configuration variants
# (though some combinations are faulty), which influence ATTR_LIST/ZF_ATTR
variants = txvi vlan smallmtu x3 rx-x3
target_variant = $(call join_,$(1) $(2))
target_run_variant = $(call join_,run $(1) $(2))
target_variants_ = $(1) $(foreach v, $(variants), $(1)_$v)
target_variants = $(foreach t,$(1),$(call target_variants_,$(t)))
target_explode = $(call target_variants,$(1)) $(call target_variants,$(2:%=run_%))

UT_NONSCRIPT_LISTS := testloop testloop2 testmisc testdelegated testb2b testb2bsb testalts testrxx3
UT_SCRIPT_LISTS := testscript testpacketdrill
UT_ALL_LISTS = $(UT_NONSCRIPT_LISTS) $(UT_SCRIPT_LISTS)

UT_ALL_LOOP_TARGETS := $(sort $(call target_explode,testloop,$(UT_LOOP)) \
                              $(call target_variants,testloop2))
UT_ALL_MISC_TARGETS := $(call target_explode,testmisc,$(UT_MISC))
UT_ALL_DELEGATED_TARGETS := $(call target_explode,testdelegated,$(UT_DELEGATED))
UT_ALL_B2B_SB_TARGETS := $(call target_explode,testb2bsb,$(UT_B2B_SB))
UT_ALL_B2B_TARGETS := $(call target_explode,testb2b,$(UT_B2B))
UT_ALL_ALTS_TARGETS := $(call target_explode,testalts,$(UT_ALTS))
UT_ALL_NONSCRIPT_TARGETS := $(UT_ALL_LOOP_TARGETS) $(UT_ALL_MISC_TARGETS) \
                  $(UT_ALL_DELEGATED_TARGETS) $(UT_ALL_B2B_TARGETS) $(UT_ALL_ALTS_TARGETS) \
		  $(UT_ALL_B2B_SB_TARGETS)
UT_ALL_SCRIPT_TARGETS := $(call target_explode,testscript,$(UT_SCRIPTS)) \
                         $(call target_variants,testpacketdrill,$(UT_SCRIPTS))
UT_ALL_TARGETS := $(UT_ALL_NONSCRIPT_TARGETS) \
                  $(UT_ALL_SCRIPT_TARGETS)


# Associate targets of each list with their base configuration
$(UT_ALL_LOOP_TARGETS) : ATTR_LIST += $(TEST_LOOP_ZF_ATTR)
$(UT_ALL_MISC_TARGETS) : ATTR_LIST += $(TEST_LOOP_ZF_ATTR)
# zfdelegated needs the send queue to be smaller than the TCP window, so that
# send space is the limiting factor. Because the send queue is a fixed number
# of segments, each of MSS size, we can arrange this by reducing the MTU, and
# hence the MSS. zfdelegated pass with _smallmtu variant
$(UT_ALL_DELEGATED_TARGETS) : ATTR_LIST += $(TEST_LOOP_ZF_ATTR)
$(UT_ALL_B2B_SB_TARGETS)  : ATTR_LIST += $(TEST_B2B_SB_ZF_ATTR)
$(UT_ALL_B2B_TARGETS)  : ATTR_LIST += $(TEST_B2B_ZF_ATTR)
$(UT_ALL_ALTS_TARGETS) : ATTR_LIST += $(TEST_ALTS_ZF_ATTR)
$(UT_ALL_SCRIPT_TARGETS): ATTR_LIST +=  $(TEST_SCRIPT_ZF_ATTR)

# Each test variant gets its ZF_ATTR tweaked
$(call containing,_txvi,$(UT_ALL_TARGETS)): ATTR_LIST += force_separate_tx_vi=1
$(call containing,_vlan,$(UT_ALL_TARGETS)): ATTR_LIST += emu_vlan=2
$(call containing,_smallmtu,$(UT_ALL_TARGETS)): ATTR_LIST += emu_mtu=576
$(call containing,_x3,$(UT_ALL_TARGETS)): ATTR_LIST += tx_emu_nic=3 emu_nic=3 force_separate_tx_vi=0
$(call containing,_rx-x3,$(UT_ALL_TARGETS)): ATTR_LIST += tx_emu_nic=2 emu_nic=3 force_separate_tx_vi=1


# assosicate each run_<test_exec> and run_<test_exec>_<variant> target with their <test_exec> dependency
$(patsubst %,run_%,$(UT_ALL) $(UT_SCRIPTS)): run_%: $(UT_BINDIR)/%
$(patsubst %,run_%_txvi,$(UT_ALL) $(UT_SCRIPTS)): run_%_txvi: $(UT_BINDIR)/%
$(patsubst %,run_%_vlan,$(UT_ALL) $(UT_SCRIPTS)): run_%_vlan: $(UT_BINDIR)/%
$(patsubst %,run_%_smallmtu,$(UT_ALL) $(UT_SCRIPTS)): run_%_smallmtu: $(UT_BINDIR)/%
$(patsubst %,run_%_x3,$(UT_ALL) $(UT_SCRIPTS)): run_%_x3: $(UT_BINDIR)/%
$(patsubst %,run_%_rx-x3,$(UT_ALL) $(UT_SCRIPTS)): run_%_rx-x3: $(UT_BINDIR)/%

PROVE_FLAGS += --merge --timer

# The scripts are in the SRC folder really
UT_SCRIPT_BINS := $(UT_SCRIPTS:%=$(UT_BINDIR)/%)
$(UT_SCRIPT_BINS): $(UT_BINDIR)/%: $(SRC_CURRENT)/%
	@mkdir -p $(dir $@)
	cp $< $@

# make this phony to enforce always looking into the following dependencies
# Notably it enforces copying the scripts everytime...
.PHONY: $(UT_SCRIPT_BINS)
$(UT_SCRIPT_BINS): zf_apps $(UT_BINDIR)/zftcppingpong2

HARNESS_TIME_OUT=480
TEST_TIME_OUT=120

$(call target_variants,testloop): $(UT_LOOP:%=$(UT_BINDIR)/%)
$(call target_variants,testloop2): $(UT_LOOP2:%=$(UT_BINDIR)/%)
$(call target_variants,testmisc): $(UT_MISC:%=$(UT_BINDIR)/%)
$(call target_variants,testdelegated): $(UT_DELEGATED:%=$(UT_BINDIR)/%)
$(call target_variants,testb2bsb): $(UT_B2B_SB:%=$(UT_BINDIR)/%)
$(call target_variants,testb2b): $(UT_B2B:%=$(UT_BINDIR)/%)
$(call target_variants,testalts): $(UT_ALTS:%=$(UT_BINDIR)/%)
$(call target_variants,testscript): $(filter-out %packetdrill.sh,$(UT_SCRIPT_BINS))
$(call target_variants,testpacketdrill): $(filter %packetdrill.sh,$(UT_SCRIPT_BINS))

# for phony targets it does not matter whether dependencies are order-only or not
# However order-only dependencies are out of $^ which makes recipes simpler.
ifeq ("$(wildcard ../packetdrill-tcpdirect/Makefile.inc)", "")
  packetdrill: ;
endif
$(call target_explode,testpacketdrill): | shim packetdrill

NETNS_SCRIPT := $(SRC_CURRENT)/netns.sh

buildattrs = ZF_ATTR="$(subst $(space),;,$(ATTR_LIST))"

$(call target_variants,$(UT_NONSCRIPT_LISTS)):
	@echo "Test target: $@"
	sudo env $(UT_ENV) $(ENV) $(call buildattrs) \
		UT_OUTPUT=$(UT_OUTPUT) TEST_TARGET="$@" \
		ZF_SLOW_TESTS="${UT_SLOW}" \
		ZF_UNSTABLE_TESTS="${UT_UNSTABLE}" \
		ZF_RUN_SLOW_TESTS=$${ZF_RUN_SLOW_TESTS:-1} \
		ZF_RUN_UNSTABLE_TESTS=$${ZF_RUN_UNSTABLE_TESTS:-0} \
		TEST_TIME_OUT=$$(($${TIMEOUT_MULTIPLIER:-1} * $(TEST_TIME_OUT))) \
		timeout $$(($${TIMEOUT_MULTIPLIER:-1} * $(HARNESS_TIME_OUT))) \
		prove --exec \
		"$(NETNS_SCRIPT)" \
		$(PROVE_FLAGS) \
		$^

$(call target_variants,$(UT_SCRIPT_LISTS)):
	@echo "Test target: $@"
	sudo env $(UT_ENV) $(ENV) EXTRA_$(call buildattrs) \
		UT_OUTPUT=$(UT_OUTPUT) TEST_TARGET="$@" \
		ZF_SLOW_TESTS="${UT_SLOW}" \
		ZF_UNSTABLE_TESTS="${UT_UNSTABLE}" \
		ZF_RUN_SLOW_TESTS=$${ZF_RUN_SLOW_TESTS:-1} \
		ZF_RUN_UNSTABLE_TESTS=$${ZF_RUN_UNSTABLE_TESTS:-0} \
		TEST_TIME_OUT=$$(($${TIMEOUT_MULTIPLIER:-1} * $(TEST_TIME_OUT))) \
		timeout $$(($${TIMEOUT_MULTIPLIER:-1} * $(HARNESS_TIME_OUT))) \
		prove --exec \
		"$(NETNS_SCRIPT)" \
		$(PROVE_FLAGS) \
		$^


# The targets need to run sequentieally as each uses huge pages and spins on CPUs
.NOTPARALLEL: $(UT_ALL_TARGETS)

# note that for test target only subset of the generated targets is execuded
# otherwise it would be too many combinations and notably
# some combinations could actually fail. All are left left for manual execution.
# see we only use testdelegated_smallmtu
test: testloop \
      testloop2_rx-x3 testloop2_x3 \
      testloop_vlan testloop_txvi \
      testb2bsb testmisc \
      testdelegated_smallmtu \
      testb2b testalts testalts_vlan \
      testalts_txvi testpacketdrill \
      testscript_x3 testscript

.PHONY: zf_unit test
zf_unit: $(UT_BINS)

ifeq ($(ZF_DEVEL),1)
  all: zf_unit
endif



# build enviorment for manually run tests,
# By default ZF_ATTR as defined for automated test run are used,
# by providing EXTRA_ZF_ATTR these can be extended

$(filter run_%,$(UT_ALL_TARGETS)): ATTR_LIST += $(EXTRA_ZF_ATTR)

# The following creates a target for each script to allow it to be run manually
# with little effort and allow tweaks.
# Targets are called run_packetdrill.sh run_zftcptimeouts etc, which run
# respective scripts
#
# The rule launches a test script in the following way:
#   ZF_ATTR="<test default attrs>;${EXTRA_ZF_ATTR}" sudo bash -x .../<test_name> "${TEST_OPTS}" "$(TEST_PREFIX)"
# Note the support of TEST_OPTS and TEST_PREFIX depends on the script.
#
# Example run the following as root:
#   make run_packet_drill.sh EXTRA_ZF_ATTR=log_level=-1 TEST_OPTS="listen" TEST_PREFIX=strace
#
# To kick off a packetdrill to run listen tests with full zf logging and strace.
$(filter run_%,$(UT_ALL_SCRIPT_TARGETS)):
	sudo env $(ENV) EXTRA_$(call buildattrs) $(TEST_PREFIX_SCRIPT) bash -x \
		$^ "$(TEST_OPTS)" "$(TEST_PREFIX)"




# The following creates a target for each test executables, targets are called
# run_zfinit run_zfpool, etc.
#
# The rule launches a test executable in the following way:
#   ZF_ATTR="<test default attrs>;${EXTRA_ZF_ATTR}" .../test_name ${TEST_OPTS}
# Defining TEST_PREFIX can add a modifier gdb or script or timeout.
#
# Example run the following as root:
#   make run_zfinit EXTRA_ZF_ATTR=logging=-1 TEST_PREFIX=strace
# And this will kick off the folowing:
#   ZF_ATTR='...;logging=-1' strace .../zfinit
$(filter run_%,$(UT_ALL_NONSCRIPT_TARGETS)):
	sudo env $(ENV) $(call buildattrs) $(TEST_PREFIX) $^ $(TEST_OPTS)

.PHONY: $(UT_ALL_TARGETS) $(UT_OUTPUT_DIR)
