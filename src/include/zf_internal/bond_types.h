/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_BOND_TYPES_H__
#define __ZF_BOND_TYPES_H__

#include <cplane/cplane.h>

struct zf_bond_state {
  /* The version of the LLAP table we pulled our information from. This is how
   * we track bond changes. */
  cp_version_t llap_version;

  /* For LACP this will be a bitset of interfaces over which we should transmit
   * according to a hash policy. Otherwise, exactly one bit should be set. */
  cicp_hwport_mask_t tx_hwports;

  /* The bitset of ports on which we will need filters. We do not support this
   * growing outside of its initial value. It doesn't change once intialised */
  cicp_hwport_mask_t rx_hwports;
};

#endif
