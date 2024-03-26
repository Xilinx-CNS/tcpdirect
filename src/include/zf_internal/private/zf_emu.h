/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_ZF_EMU_H__
#define __ZF_INTERNAL_ZF_EMU_H__

#include <cplane/mib.h>
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

extern void
zf_emu_intf_add(const char* ifname, cicp_hwport_mask_t rx_hwports,
                cicp_hwport_mask_t tx_hwports, uint16_t vlan_id,
                cicp_llap_type_t hash_policy, int peer_vi,
                const ci_mac_addr_t mac);
extern void
zf_emu_remove_all_intfs(void);
extern void
zf_emu_set_dst_mac(const ci_mac_addr_t mac);

extern void
zf_emu_intf_set_tx_hwports(const char* if_name, cicp_hwport_mask_t hwports);

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

#endif /* __ZF_INTERNAL_ZF_EMU_H__ */

