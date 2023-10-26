/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_BOND_H__
#define __ZF_BOND_H__

#include <cplane/cplane.h>

#include <zf/zf.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/private/zf_stack_def.h>

/* Check if our llap version is stale. This does not necessarily mean the bond
 * information is incorrect, just that the llap table has been updated. */
static inline int
zf_bond_stale(struct zf_stack* stack)
{
  return !zf_state.cp.intf_version_verify(zf_state.cp_handle,
                                          &stack->bond_state.intf_version);
}

ZF_COLD extern int zf_stack_init_bond_state(struct zf_stack* st,
                                            struct zf_if_info* ifinfo);
ZF_COLD extern int zf_bond_update(struct zf_stack* stack);
ZF_COLD extern void zf_bond_pin_zock(struct zf_stack* st, struct zf_tx* tx);


#endif /* __ZF_BOND_H__ */
