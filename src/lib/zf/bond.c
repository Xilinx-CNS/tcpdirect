/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <cplane/cplane.h>
#include <iterator>

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

static int check_and_update_bond_state(struct zf_stack* st)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  struct zf_bond_state* bs = &st->bond_state;
  ef_cp_intf intf;
  int rc;
  int ifindices[CI_ARRAY_SIZE(bs->ifindices)];

  st->bond_state.intf_version = zf_state.cp.intf_version_get(zf_state.cp_handle);
  rc = zf_state.cp.get_intf_by_name(zf_state.cp_handle, sti->sti_if_name,
                                    &intf, 0);
  if(ZF_UNLIKELY( rc < 0 ))
    return rc;

  rc = zf_state.cp.get_lower_intfs(zf_state.cp_handle, intf.ifindex, ifindices,
                         std::size(ifindices),
                         EF_CP_GET_INTFS_F_NATIVE | EF_CP_GET_INTFS_F_UP_ONLY |
                                    EF_CP_GET_INTFS_F_MOST_DERIVED);
  if(ZF_UNLIKELY( rc < 0 ))
    return rc;

  rc = std::min<int>(rc, std::size(ifindices));
  if(ZF_UNLIKELY( bs->ifindices_n != rc ||
                  memcmp(bs->ifindices, ifindices, rc * sizeof(ifindices)) ||
                  memcmp(sti->sti_src_mac, intf.mac, ETH_ALEN) )) {
    memcpy(bs->ifindices, ifindices, sizeof(ifindices));
    bs->ifindices_n = rc;
    /* Update the stack's copy of the local MAC address.  This will be
     * proagated to zockets when repinning. */
    memcpy(sti->sti_src_mac, intf.mac, ETH_ALEN);
    return true;
  }
  return false;
}

ZF_COLD int zf_stack_init_bond_state(struct zf_stack* st,
                                     struct zf_if_info* ifinfo)
{
  int rc = check_and_update_bond_state(st);
  return rc < 0 ? rc : 0;
}

ZF_COLD int zf_bond_update(struct zf_stack* stack)
{
  struct zf_bond_state* bs = &stack->bond_state;
  int rc = check_and_update_bond_state(stack);

  if(ZF_UNLIKELY( rc < 0 ))
    return -1;

  (void)bs; /* quell compiler in NDEBUG */
#ifndef NDEBUG
  /* We only initialize our VIs at startup, so it'd be unfortunate if a new
   * interface was added to a bond which we weren't able to use.
   * ef_cp_resolve() will cope cleanly with this by not using the unregistered
   * interfaces, but it's still useful to assert if this has happened. */
  for( int i = 0; i < bs->ifindices_n; ++i ) {
    ef_cp_intf intf;
    int r = zf_state.cp.get_intf(zf_state.cp_handle, bs->ifindices[i], &intf, 0);
    zf_assert_equal(r, 0);
    zf_assert_nequal(intf.registered_cookie, NULL);
  }
#endif

  /* Try and optimise for the false-positive case */
  if(ZF_UNLIKELY( rc > 0 ))
    zf_bond_repin(stack);

  return 0;
}

