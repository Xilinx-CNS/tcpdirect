/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF tx warming */

#ifndef __ZF_TX_WARM_H__
#define __ZF_TX_WARM_H__

#include <zf_internal/tx_types.h>
#include <zf_internal/zf_pool.h>
extern "C" {
#include <etherfabric/ef_vi.h>
}

struct zf_tx_warm_state {
  ef_vi_tx_warm_state ef_vi_state[ZF_MAX_NICS];
  pkt_id ctpio_warm_buf_id;
};


extern ZF_COLD int
enable_tx_warm(struct zf_tx* tx, zf_tx_warm_state* state);
extern ZF_COLD void
disable_tx_warm(struct zf_tx* tx, zf_tx_warm_state* state);

#endif /* __ZF_TX_WARM_H__ */
