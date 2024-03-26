/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <cplane/cplane.h>

#include <zf/zf.h>
#include <zf_internal/private/zf_stack_def.h>
#include <zf_internal/tx_types.h>
#include <zf_internal/tcp_types.h>
#include <zf_internal/udp_tx.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/utils.h>
#include <zf_internal/bond_types.h>
#include <zf_internal/bond.h>
#include <zf_internal/zf_stack_impl.h>


static void zf_bond_repin(struct zf_stack* stack)
{
    /* Iterate over all TX zockets, repin everything */
  for( int i = 0; i < ZF_ZOCKET_ID_MAX + 1; i++ ){
    if( zf_stack_tcp_is_allocated(stack, &stack->tcp[i]) )
      zf_path_pin_zock(stack, &stack->tcp[i].tst);

    if( zf_stack_udp_tx_is_allocated(stack, &stack->udp_tx[i]) )
      zf_path_pin_zock(stack, &stack->udp_tx[i].tx);

    /* Listening zockets are pinned on a per-packet basis, as when we're
     * using a hashing bond mode their TX vi can change and it seemed more
     * consistent to do it the same way all the time.
     */
  }
}

ZF_COLD int zf_bond_update(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, stack);
  struct zf_bond_state* bs = &stack->bond_state;
  cp_version_t ver;
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cicp_llap_row_t llap;

  CP_VERLOCK_START(ver, mib, &zf_state.cplane_handle)
    bs->llap_version = *mib->llap_version;

    id = cp_llap_by_ifname(mib, sti->sti_if_name);
    if(ZF_LIKELY( id != CICP_ROWID_BAD ))
      llap = mib->llap[id];

  CP_VERLOCK_STOP(ver, mib);

  if(ZF_UNLIKELY( id == CICP_ROWID_BAD ))
    return -1;

  /* We don't really care about changes to rx_hwports, we just listen on all
   * VIs instatiated during stack creation. Nonetheless, it should not grow
   * outside of its initial value. */
  zf_assert_flags(bs->rx_hwports, llap.rx_hwports);

  /* Similarly, tx_hwports should not grow outside of intitial rx_hwports */
  zf_assert_flags(bs->rx_hwports, llap.tx_hwports);

  /* In the unlikely case that we have no TX hwports, we will continue to
   * send as we did previously until we get another update that provides a
   * non-empty set. */
  if(ZF_UNLIKELY( ! llap.tx_hwports ))
    return 0;

  /* Try and optimise for the false-positive case */
  if(ZF_UNLIKELY( bs->tx_hwports != llap.tx_hwports ||
                  memcmp(sti->sti_src_mac, llap.mac, ETH_ALEN) )) {
    bs->tx_hwports = llap.tx_hwports;

    /* Update the stack's copy of the local MAC address.  This will be
     * proagated to zockets when repinning. */
    memcpy(sti->sti_src_mac, llap.mac, ETH_ALEN);

    zf_assert_equal(stack->encap_type, llap.encap.type);
    zf_bond_repin(stack);
  }

  return 0;
}

