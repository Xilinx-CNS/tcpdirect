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


struct zf_state zf_state;

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
      goto fail;
    }

#define CP_FUNC_INIT_FUNC_PTR(x) \
    zf_state.cp.x = reinterpret_cast<decltype(zf_state.cp.x)>( \
                                    dlsym(zf_state.efcp_so_handle, "ef_cp_" #x)); \
    if( ! zf_state.cp.x ) { \
      zf_log_stack_err(NO_STACK, "%s: Failed to link to ef_vi Control Plane: %s\n", \
                      __func__, #x); \
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
fail:
  zf_log_stderr();
  return rc;
}


extern int zf_deinit(void)
{
  zf_state.cp.fini(zf_state.cp_handle);
  dlclose(zf_state.efcp_so_handle);
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
