/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file Implementation of "donation" shared memory API.
 *
 * These are wrappers around functionality implemented in the Onload driver.
 * For now, they are built directly into ZF, but if in the future we have other
 * uses for them, they could be moved into a separate library built as part of
 * the Onload build.
 */


#include <errno.h>

#include <ci/compat.h>
#include <ci/driver/efab/open.h>
#include <cplane/cplane.h>
#include <onload/dshm.h>
#include <onload/ioctl_dshm.h>
#include <onload/mmap.h>

/* Work around the fact that we want to use oo_resource_op() without depending
 * on the whole of lib/transport/unix. */
int (* ci_sys_ioctl)(int, long unsigned int, ...) = ioctl;


int
oo_dshm_register(int onload_dh, ci_int32 shm_class, void* buffer,
                 ci_uint32 length)
{
  int rc;
  oo_dshm_register_t args;
  args.shm_class = shm_class;
  args.length = length;
  CI_USER_PTR_SET(args.buffer, buffer);

  rc = oo_resource_op(onload_dh, OO_IOC_DSHM_REGISTER, &args);
  return (rc >= 0) ? args.buffer_id : rc;
}


int
oo_dshm_list(int onload_dh, ci_int32 shm_class, ci_int32* buffer_ids,
             ci_uint32 count)
{
  int rc;
  oo_dshm_list_t args;
  args.shm_class = shm_class;
  args.count = count;
  CI_USER_PTR_SET(args.buffer_ids, buffer_ids);

  rc = oo_resource_op(onload_dh, OO_IOC_DSHM_LIST, &args);
  return (rc >= 0) ? args.count : rc;
}


int
oo_dshm_map(int onload_dh, ci_int32 shm_class, ci_int32 buffer_id,
            unsigned length, void **addr_out)
{
  return oo_resource_mmap(onload_dh, OO_MMAP_TYPE_DSHM,
                          OO_MMAP_DSHM_MAKE_ID(shm_class, buffer_id), length,
                          OO_MMAP_FLAG_READONLY, addr_out);
}
