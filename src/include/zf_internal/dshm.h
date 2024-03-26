/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file "Donation" shared memory API.
 *
 * This is intended to provide a mechanism for ZF stacks and packet buffers
 * to be mapped into other processes for debugging purposes.
 *
 * A client wishing to allow a buffer to be shared by another process first
 * allocates memory using its favourite mechanism (malloc(), mmap(), ...).  It
 * then calls oo_dshm_register() on that buffer to make it available to other
 * processes via oo_dshm_map().  Shared buffers are grouped into 'classes',
 * which are identified by statically-defined integer constants.  The
 * oo_dshm_list() call lists all of the shared buffers in a specified class.
 */

#ifndef __ZF_INTERNAL_DSHM_H__
#define __ZF_INTERNAL_DSHM_H__

#include <onload/dshm.h>


/**
 * \brief Registers an arbitrary buffer as a shared buffer.
 *
 * The registered buffer will be available to be mapped by other processes
 * until the driver handle passed to oo_dshm_register() is closed.  At such a
 * time, existing mappings will continue to be valid until they are closed.
 *
 * \ret Index of buffer on success, or -errno.
 */
extern int
oo_dshm_register(int onload_dh, ci_int32 shm_class, void* buffer,
                 ci_uint32 length);


/**
 * \brief Lists all shared buffers in a specified class.
 *
 * This function returns up to \p count IDs of shared buffers in \p buffer_ids.
 * Only buffers that the process has permission to map will be returned.  There
 * is no guarantee that the buffers will persist between this call returning
 * and a subsequent call to oo_dshm_map().
 */
extern int
oo_dshm_list(int onload_dh, ci_int32 shm_class, ci_int32* buffer_ids,
             ci_uint32 count);


/**
 * \brief Maps a shared buffer into the current process.
 *
 * The buffer is mapped read-only.  It will continue to be valid until the
 * mapping is closed.  (We do not provide an API to close mappings.  This
 * happens automatically when the memory is unmapped, i.e. when munmap() is
 * called or when the process exits.)
 *
 * \ret Zero on success, -errno on error.
 */
extern int
oo_dshm_map(int onload_dh, ci_int32 shm_class, ci_int32 buffer_id,
            unsigned length, void **addr_out);


#endif /* ! defined(__ZF_INTERNAL_DSHM_H__) */
