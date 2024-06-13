/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF transmit warming */

#include <zf_internal/zf_stack.h>
#include <zf_internal/tx_warm.h>
#include <etherfabric/efct_vi.h>


int enable_tx_warm(struct zf_tx* tx, zf_tx_warm_state* state)
{
  struct zf_stack* st = zf_stack_from_zocket(tx);
  struct zf_stack_nic* st_nic = &st->nic[tx->path.nicno];
  ef_vi* vi = zf_stack_nic_tx_vi(st_nic);
  zf_assert_nflags(st->flags, ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED);
  zf_log_stack_trace(st, "%s: TX warm enabled\n", __func__);
  char* ctpio_warm_buf = NULL;
  state->ctpio_warm_buf_id = PKT_INVALID;
  if( vi->vi_flags & EF_VI_TX_CTPIO && vi->nic_type.arch != EF_VI_ARCH_EFCT ) {
    int rc = zft_alloc_pkt(&st->pool, &state->ctpio_warm_buf_id);
    if( rc < 0 )
      return rc;
    ctpio_warm_buf = PKT_BUF_BY_ID(&st->pool, state->ctpio_warm_buf_id);
  }
  ef_vi_start_transmit_warm(vi, &state->ef_vi_state[tx->path.nicno],
                            ctpio_warm_buf);
  st->flags |= ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED;
  return 0;
}


void disable_tx_warm(struct zf_tx* tx, zf_tx_warm_state* state)
{
  struct zf_stack* st = zf_stack_from_zocket(tx);
  struct zf_stack_nic* st_nic = &st->nic[tx->path.nicno];
  ef_vi* vi = zf_stack_nic_tx_vi(st_nic);
  zf_assert_flags(st->flags, ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED);
  zf_log_stack_trace(st, "%s: TX warm disabled\n", __func__);
  ef_vi_stop_transmit_warm(vi, &state->ef_vi_state[tx->path.nicno]);
  if( state->ctpio_warm_buf_id != PKT_INVALID )
    zf_pool_free_pkt(&st->pool, state->ctpio_warm_buf_id);
  st->flags &= ~ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED;
}

