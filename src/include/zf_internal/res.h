/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * Generic resource-management.
 */

#ifndef __ZF_INTERNAL_RES_H__
#define __ZF_INTERNAL_RES_H__

struct zf_generic_res {
  /* Link into list of free zockets. */
  ci_sllink free_link;

#define ZF_GENERIC_RES_ALLOCATED   0x00000001u
  uint32_t res_flags;
};

#endif /* __ZF_INTERNAL_RES_H__ */

