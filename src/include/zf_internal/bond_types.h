/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_BOND_TYPES_H__
#define __ZF_BOND_TYPES_H__

#include <cplane/api.h>

struct zf_bond_state {
  /* The version of the LLAP table we pulled our information from. This is how
   * we track bond changes. */
  ef_cp_intf_verinfo intf_version;

  /* Currently-up ifindex list, so we can detect when it's changed  */
  int ifindices[ZF_MAX_NICS];
  int ifindices_n;
};

#endif
