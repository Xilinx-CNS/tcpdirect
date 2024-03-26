/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_BOND_H__
#define __ZF_BOND_H__

#include <cplane/cplane.h>

#include <zf/zf.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/private/zf_stack_def.h>

/* Check if our llap_version is stale. This does not necessarily mean the bond
 * information is incorrect, just that the llap table has been updated. */
static inline int
zf_bond_stale(struct zf_stack* stack)
{
  cp_version_t cp_llap = OO_ACCESS_ONCE(*zf_state.cplane_handle.mib->llap_version);
  cp_version_t zf_llap = stack->bond_state.llap_version;

  return cp_llap != zf_llap;
}

ZF_COLD extern int zf_bond_update(struct zf_stack* stack);
ZF_COLD extern void zf_bond_pin_zock(struct zf_stack* st, struct zf_tx* tx);


#endif /* __ZF_BOND_H__ */
