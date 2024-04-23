/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF library lifetime management routines */

#include <zf/zf.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/private/zf_hal.h>
#include <dlfcn.h>
#include <functional>

template <typename T>
T _placeholder_cp_func() {
  return (T)-1;
}

template <>
bool _placeholder_cp_func<bool>() {
  return false;
}

template <>
ef_cp_intf_verinfo _placeholder_cp_func<ef_cp_intf_verinfo>() {
  return EF_CP_INTF_VERINFO_INIT;
}

#define ERR_EF_CP_FUNCTION(name) \
  (CP_FUNC_PTR_TYPE(name)) \
  &_placeholder_cp_func<std::function<CP_FUNC_TYPE(name)>::result_type>

#define ERR_EF_CP_FUNCTION_INIT(name) \
  .name = ERR_EF_CP_FUNCTION(name),

#define CP_FUNC_SET_TO_ERR(name) zf_state.cp.name = ERR_EF_CP_FUNCTION(name);

struct zf_state zf_state = (struct zf_state) {
  .cp_handle = NULL,
  .cp = {
    FOR_EACH_EF_CP_FUNCTION(ERR_EF_CP_FUNCTION_INIT)
  },
  .efcp_so_handle = NULL
};

int zf_init(void)
{
  int rc;
  struct zf_attr* attr;

  zf_log_stderr(); /* Initialise this before anything that might log */

  rc = zf_attr_alloc(&attr);
  if( rc ) {
    zf_log_stack_err(NO_STACK,
                     "ERROR: Failed to parse command line attributes.\n");
    return rc;
  }

  /* Set global attributes */
  if( attr->log_level != ZF_LCL_ALL_ERR )
    zf_log_level = attr->log_level;
  if( attr->log_format != ZF_LCL_ALL_ERR )
    zf_log_format = attr->log_format;

  if( attr->log_to_kmsg )
    rc = zf_log_replace_stderr("/dev/kmsg");
  else if( attr->log_file )
    rc = zf_log_redirect(attr->log_file);

  if( rc < 0 ) {
    zf_log_stack_err(NO_STACK, "%s: Failed to redirect logging: %s\n",
                     __func__, strerror(-rc));
    /* Failure here is non-fatal. */
  }

  rc = zf_hal_init(attr);
  zf_attr_free(attr);

  if( rc < 0 )
    goto fail;

  if( ! zf_state.efcp_so_handle ) {
    zf_state.efcp_so_handle = dlopen("libefcp.so", RTLD_NOW);
    if( ! zf_state.efcp_so_handle ) {
      zf_log_stack_err(NO_STACK, "%s: Failed to open ef_vi Control Plane: %s\n",
                      __func__, dlerror());
      rc = -ENOENT;
      goto fail;
    }

#define CP_FUNC_INIT_FUNC_PTR(x) \
    zf_state.cp.x = reinterpret_cast<decltype(zf_state.cp.x)>( \
                                    dlsym(zf_state.efcp_so_handle, "ef_cp_" #x)); \
    if( ! zf_state.cp.x ) { \
      zf_log_stack_err(NO_STACK, "%s: Failed to link to ef_vi Control Plane: %s\n", \
                      __func__, #x); \
      rc = -ENOENT; \
      goto fail1; \
    }
    FOR_EACH_EF_CP_FUNCTION(CP_FUNC_INIT_FUNC_PTR)
  }

  rc = zf_state.cp.init(&zf_state.cp_handle, 0);
  if( rc < 0 ) {
    zf_log_stack_err(NO_STACK, "%s: Failed to initialize ef_vi Control Plane: %s\n",
                     __func__, strerror(-rc));
    goto fail1;
  }

  zf_log_stack_info(NO_STACK, "ZF library initialized\n");
  return 0;

fail1:
  dlclose(zf_state.efcp_so_handle);
  FOR_EACH_EF_CP_FUNCTION(CP_FUNC_SET_TO_ERR);
fail:
  zf_log_stderr();
  return rc;
}


extern int zf_deinit(void)
{
  zf_state.cp.fini(zf_state.cp_handle);
  if (zf_state.efcp_so_handle && zf_state.efcp_so_handle != &zf_state)
  {
    dlclose(zf_state.efcp_so_handle);
    FOR_EACH_EF_CP_FUNCTION(CP_FUNC_SET_TO_ERR);
  }
  zf_log_stderr();
  return 0;
}


#include <ci/internal/syscall.h>
#include ONLOAD_VERSION_HDR

static const char* version =
  "TCPDirect Library version: "ZF_VERSION"\n"
  "TCPDirect built with Onload version: "ONLOAD_VERSION"\n"
  ONLOAD_COPYRIGHT"\n"
  "Built: "__DATE__" "__TIME__" "
#ifdef NDEBUG
  "(release)"
#else
  "(debug)"
#endif
  "\n";

const char* zf_version(void)
{
  return version;
}

const char* zf_version_short(void)
{
  return ZF_VERSION;
}

const char* onload_version_short(void)
{
  return ONLOAD_VERSION;
}

/* This function is called when the library is executed directly.
 * The .plt isn't set up because there is no .interp section,
 * so we should not use libc or extern functions.
 * The strlen call below should be evaluated at compile time. */
void zf_print_version(void)
{
  my_syscall3(write, 2, (uintptr_t)version, strlen(version));
  my_syscall3(exit, 0, 0, 0);
}
