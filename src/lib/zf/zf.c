/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF library lifetime management routines */

#include <zf/zf.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/private/zf_hal.h>


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

  rc = oo_fd_open(&zf_state.cplane_fd);
  if( rc < 0 ) {
    zf_log_stack_err(NO_STACK, "%s: Can't open cplane fd: %s\n",
                     __func__, strerror(-rc));
    goto fail;
  }
  
  rc = oo_cp_create(zf_state.cplane_fd, &zf_state.cplane_handle,
                    CP_SYNC_LIGHT, 0);
  if( rc < 0 ) {
    zf_log_stack_err(NO_STACK, "%s: Failed to initialize Control Plane: %s\n",
                     __func__, strerror(-rc));
    oo_fd_close(zf_state.cplane_fd);
    goto fail;
  }

  zf_log_stack_info(NO_STACK, "ZF library initialized\n");
  return 0;

fail:
  zf_log_stderr();
  return rc;
}


extern int zf_deinit(void)
{
  oo_fd_close(zf_state.cplane_fd);
  zf_log_stderr();
  return 0;
}


#include <ci/internal/syscall.h>
#include "onload_version.h"

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
