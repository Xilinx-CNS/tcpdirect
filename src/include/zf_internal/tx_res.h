/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** Slow-path UDP TX structures. */

#ifndef __ZF_TX_RES_H__
#define __ZF_TX_RES_H__

#include <zf_internal/utils.h>
#include <zf_internal/res.h>
#include <zf_internal/allocator.h>

struct zf_tx_res {
  struct zf_generic_res generic_res;
};


static inline struct zf_tx_res* zf_tx_res_alloc(zf_allocator* a, size_t count)
{
  auto len = count * sizeof(struct zf_tx_res);
  auto res = (struct zf_tx_res*) zf_allocator_alloc(a, len);
  if( res == NULL )
    return NULL;

  memset(res, 0, len);

  return res;
}


#endif /* __ZF_TX_RES_H__ */

