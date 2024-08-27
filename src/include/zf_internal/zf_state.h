/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_STATE_H__
#define __ZF_STATE_H__

#include <cplane/api.h>

#define FOR_EACH_EF_CP_FUNCTION(OP) \
    OP(init) \
    OP(fini) \
    OP(get_lower_intfs) \
    OP(get_intf) \
    OP(get_intf_by_name) \
    OP(intf_version_get) \
    OP(intf_version_verify) \
    OP(register_intf) \
    OP(resolve)

#define CP_FUNC_TYPE(x) \
  decltype(ef_cp_##x)

#define CP_FUNC_PTR_TYPE(x) \
  decltype(&ef_cp_##x)

struct zf_state {
  struct ef_cp_handle* cp_handle;
  struct {
#define CP_FUNC_DEFINE_FUNC_PTR(x)  CP_FUNC_PTR_TYPE(x) x;
    FOR_EACH_EF_CP_FUNCTION(CP_FUNC_DEFINE_FUNC_PTR)
  } cp;
  void* efcp_so_handle;
};

extern struct zf_state zf_state;

#endif
