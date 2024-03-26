/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_STATE_H__
#define __ZF_STATE_H__

#include <cplane/cplane.h>

struct zf_state {
  int cplane_fd;
  struct oo_cplane_handle cplane_handle;
};

extern struct zf_state zf_state;

#endif
