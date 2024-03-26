/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF pool resource management and slow path */

#ifndef __ZF_POOL_RES_H__
#define __ZF_POOL_RES_H__

#include <zf/zf.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/utils.h>

#include <etherfabric/memreg.h>


struct zf_pool_res_nic {
  struct ef_memreg memreg;
};


/** \brief Stores pool state that is not needed on critical path */
struct zf_pool_res {
  struct zf_pool* pool;
  struct zf_stack* st;
  /* per NIC state */
  struct zf_pool_res_nic nic[ZF_MAX_NICS];
  size_t pkt_bufs_mmap_len;
  int pkt_bufs_shm_id;
};


/**
 * \brief Allocates pool of pkt buffers,
 *
 * The pool structure is allocated and initialised, and the buffer memory
 * is registered for visibility to stackdump.
 *
 * The packet buffers are not mapped in to any NICs, this is done by
 * zf_pool_map().
 *
 * \param pool Place to store fast path related state.
 * \param pres Place to store other state including resource management
 * \param st stack.
 * \param n_bufs size of the pool.
 */
extern int zf_pool_alloc(struct zf_pool_res* pres, struct zf_pool* pool,
                         struct zf_stack* st, unsigned n_bufs);

extern int zf_pool_free(struct zf_stack*, struct zf_pool_res*);

/**
 * \brief Maps a pkt buffer pool for a specific NIC
 */
extern int zf_pool_map(struct zf_stack* st, struct zf_pool_res* pres,
                       int nicno);


#endif /* __ZF_POOL_RES_H__ */
