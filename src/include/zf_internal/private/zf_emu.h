/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_ZF_EMU_H__
#define __ZF_INTERNAL_ZF_EMU_H__
#include <netinet/ether.h>
#include <vector>

#ifdef __cplusplus
/* Needed because in C++ an empty struct has a non-zero size. Additionally, a
 * zero-length array is used instead of a standard flexible array member so that
 * it can be used in the middle of a struct without gcc complaining. */
#undef CI_DECLARE_FLEX_ARRAY
#define CI_DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct { \
		TYPE NAME[0]; \
	}
#endif
#include <etherfabric/internal/efct_uk_api.h>

/* These interface names are used for the default configuration of the "back-
 * to-back" emulator. */
#define ZF_EMU_B2B0 "b2b0"
#define ZF_EMU_B2B1 "b2b1"

static const int ZF_EMU_MAX_VIS = 32;
static const int CI_TEST_EFCT_MAX_SUPERBUFS = 1024;

struct efct_tx_ctpio_header
{
  unsigned packet_length;
  unsigned ct_thresh;
  unsigned timestamp_flag;
  unsigned warm_flag;
  unsigned action;
};

struct ef_vi;
struct zf_stack;
using ci_mac_addr_t = uint8_t[ETH_ALEN];

extern void
zf_emu_intf_add(const char* ifname, int ifindex,
                const int* hw_ifindices, size_t n_hw_ifindices,
                uint16_t vlan_id, uint32_t encap, int peer_ifindex,
                const ci_mac_addr_t mac);

static inline void
zf_emu_intf_add(const char* ifname, int ifindex,
                std::initializer_list<int> hw_ifindices, uint16_t vlan_id,
                uint32_t encap, int peer_ifindex,
                const ci_mac_addr_t mac)
{
  return zf_emu_intf_add(ifname, ifindex, hw_ifindices.begin(),
                         hw_ifindices.size(), vlan_id, encap, peer_ifindex, mac);
}
extern void
zf_emu_remove_all_intfs(void);
extern void
zf_emu_set_dst_mac(const ci_mac_addr_t mac);

extern void
zf_emu_intf_set_intf_up(const char* ifname, bool up);

extern void
zf_emu_intf_set_mac(const char* ifname, ci_mac_addr_t mac);

extern void
zf_emu_sync(void);

extern void
zf_emu_pftf_pause(ef_vi* vi);

extern void
zf_emu_pftf_pause(zf_stack* st, int nic);

extern void
zf_emu_pftf_resume(ef_vi* vi);

void
zf_emu_pftf_resume(zf_stack* st, int nic);

extern void
zf_emu_set_fw_variant(int fw_variant);

extern void
zf_emu_set_vlan_override(bool enable, uint32_t dst_addr, uint16_t vlan_id);

struct efab_efct_rxq_uk_shm_q_stats {
    unsigned no_rxq_space;
    unsigned too_many_owned;
    unsigned no_bufs;
    unsigned skipped_bufs;
};

struct emu_stats {
  size_t no_desc_drops{0};
  struct {
    size_t n_starts;
    size_t n_ends;
    size_t n_rollovers;
  } sbufs[CI_TEST_EFCT_MAX_SUPERBUFS]{0};
  struct {
    efab_efct_rxq_uk_shm_q_stats *stats[ZF_EMU_MAX_VIS];
    int alloced;
  } efct_shm_stats;
  bool sbuf_leaked;
};

extern struct emu_stats& emu_stats_update(void);
void emu_stats_display(struct emu_stats& stats);

const uint32_t CICP_LLAP_TYPE_XMIT_HASH_LAYER2    = 0x00000008;
const uint32_t CICP_LLAP_TYPE_XMIT_HASH_LAYER34   = 0x00000010;
const uint32_t CICP_LLAP_TYPE_XMIT_HASH_LAYER23   = 0x00000020;

#endif /* __ZF_INTERNAL_ZF_EMU_H__ */

