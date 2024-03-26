/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF pool performance critical data and routines */

#ifndef __ZF_POOL_H__
#define __ZF_POOL_H__

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/stack_params.h>

#include <etherfabric/ef_vi.h> /* for ef_addr */

#include <stddef.h>
#include <sys/uio.h>


static const zf_logger zf_log_pool_err(ZF_LC_POOL, ZF_LL_ERR);
static const zf_logger zf_log_pool_warn(ZF_LC_POOL, ZF_LL_WARN);
static const zf_logger zf_log_pool_info(ZF_LC_POOL, ZF_LL_INFO);
#ifndef NDEBUG
static const zf_logger zf_log_pool_trace(ZF_LC_POOL, ZF_LL_TRACE);
#else
#define zf_log_pool_trace(...) do{}while(0)
#endif

#define PKT_BUF_SIZE         2048u
#define NIC_PAGE_SIZE        (1u<<20) /* 1MB assuming host delivers huge page */
#define PKT_BUFS_IN_NIC_PAGE (NIC_PAGE_SIZE/PKT_BUF_SIZE)

/* Allow up to 32K packet buffers.
 * Fix zf_tx_req_id flags and mask if you are changing this. */
#define MAX_PKT_NIC_PAGES 64u
typedef uint16_t pkt_id;
#define PKT_INVALID ((pkt_id)~0u)

struct zf_attr;
struct zf_stack;

struct zf_pool_nic {
  /* I/O address corresponding to the start of pkt buf
   * For now we assume buffers are allocated from huge pages
   * and NIC can allocate single 1MB page per huge pages,
   * therefore 512 pkt buffers share efaddr.
   */
  ef_addr efaddr[MAX_PKT_NIC_PAGES];
};

struct zf_pool {
  /* registered memory for DMA */
  char* pkt_bufs;
  uint32_t pkt_bufs_n;
  #define ZF_POOL_FREE_PENDING 0x1
  int flags;

  /* Array containing ids of free packets
   *
   * This is LIFO implementation.
   *
   * first_free is index to this array,
   * designating first free pkt in the array.
   * All entries with indexes preceding first_free are allocated pkts.
   * All entries with indexes following first_free are free_pkts.
   *
   * We probably need better scheme with pkt buffer clustering.
   */
  pkt_id* free_pkts;

  uint32_t first_free; /* larger type than pkt_id to represent pkt_bufs_n */

  /* per nic */
  struct zf_pool_nic nic[ZF_MAX_NICS];
};

static inline void zf_assume_packet_id_valid(struct zf_pool* pool, uint32_t id)
{
  zf_assume_lt(id, pool->pkt_bufs_n);
}

#define PKT_BUF_ID_FROM_PTR     PKT_BUF_ID
#define PKT_BUF_ID(pool, pktb)  zf_packet_buffer_id((pool), (char*) (pktb))
static inline pkt_id zf_packet_buffer_id(struct zf_pool* pool, char* pktb)
{
  uint32_t id = (pktb - pool->pkt_bufs) / PKT_BUF_SIZE;
  zf_assume_packet_id_valid(pool, id);
  return id;
}

#define PKT_BUF_BY_ID zf_packet_buffer_by_id
static inline char* zf_packet_buffer_by_id(struct zf_pool* pool, pkt_id id)
{
  zf_assume_packet_id_valid(pool, id);
  return pool->pkt_bufs + id * PKT_BUF_SIZE;
}

#define PKT_EFADDR_BY_ID(pool, nic_i, id) \
    ((pool)->nic[(nic_i)].efaddr[(id)/PKT_BUFS_IN_NIC_PAGE] + \
     ((id) & (PKT_BUFS_IN_NIC_PAGE - 1)) * PKT_BUF_SIZE)

#define NUM_FREE_PKTS(pool) ((pool)->pkt_bufs_n - (pool)->first_free)



/* note: this returns pointer to internal free pkt array
 * Pool is locked until zf_pool_get_free_pkts_done() is called.
 */
ZF_HOT static inline int
zf_pool_get_free_pkts(struct zf_pool* pool, pkt_id* restrict * pkts, unsigned *count)
{
  zf_assume_nflags(pool->flags, ZF_POOL_FREE_PENDING);

  unsigned pkt_idx = pool->first_free;
  if( pkt_idx == pool->pkt_bufs_n)
    return -ENOMEM;
  zf_assume_packet_id_valid(pool, pkt_idx);

#ifndef NDEBUG
  pool->flags |= ZF_POOL_FREE_PENDING;
#endif
  *count = MIN(*count, pool->pkt_bufs_n - pkt_idx);

  *pkts = &pool->free_pkts[pkt_idx];
  for( unsigned i = 0; i < *count; ++i )
    zf_assume_packet_id_valid(pool, (*pkts)[i]);

  pool->first_free += *count;

  for( unsigned i = 0; i < *count; ++i)
    zf_log_pool_trace(pool, "%s: %x\n", __func__, pool->free_pkts[pkt_idx+i]);
  return 0;
}


/* Completes zf_pool_get_free_pkts and unlocks pool
 *
 * The only purpose is diagnostics */
ZF_HOT static inline void
zf_pool_get_free_pkts_done(struct zf_pool* pool)
{
  zf_assert_flags(pool->flags, ZF_POOL_FREE_PENDING);
#ifndef NDEBUG
  pool->flags &= ~ZF_POOL_FREE_PENDING;
#endif
}

/* Do we need one having zf_pool_get_free_pkts()?
 *
 * It can be called even when pool is locked with ZF_POOL_FREE_PENDING. */
ZF_HOT static inline pkt_id
zf_pool_get_free_pkt(struct zf_pool* pool)
{
  unsigned pkt_idx = pool->first_free;
  if( pkt_idx == pool->pkt_bufs_n ) {
    zf_log_pool_trace(pool, "%s: out of buffers\n", __func__);
    return PKT_INVALID;
  }
  zf_assume_lt(pkt_idx, pool->pkt_bufs_n);
  pkt_id id = pool->free_pkts[pkt_idx];
  zf_assume_lt(id, pool->pkt_bufs_n);
  ++pool->first_free;
  zf_log_pool_trace(pool, "%s: %x\n", __func__, id);
  return id;
}


ZF_HOT static inline void
zf_pool_free_pkt(struct zf_pool* pool, pkt_id id)
{
  zf_log_pool_trace(pool, "%s: %x\n", __func__, id);
  zf_assume_nflags(pool->flags, ZF_POOL_FREE_PENDING);
  zf_assume_lt(id, pool->pkt_bufs_n);
  unsigned pkt_idx = pool->first_free;
  zf_assume_gt(pkt_idx, 0);
  zf_assume_le(pkt_idx, pool->pkt_bufs_n);
  --pkt_idx;
  pool->free_pkts[pkt_idx] = id;
  --pool->first_free;
}


ZF_HOT static inline void
zf_pool_free_pkts(struct zf_pool* pool, struct iovec* restrict iov, unsigned count)
{
  zf_assume_nflags(pool->flags, ZF_POOL_FREE_PENDING);
  unsigned pkt_idx = pool->first_free;
  zf_assume_ge(pkt_idx, count);
  zf_assume_le(pkt_idx, pool->pkt_bufs_n);
  pkt_idx -= count;
  for( unsigned i = 0; i < count; ++i, ++pkt_idx, ++iov ) {
    pkt_id id = PKT_BUF_ID_FROM_PTR(pool, iov->iov_base);
    zf_log_pool_trace(pool, "%s: %x\n", __func__, id);
    zf_assume_lt(id, pool->pkt_bufs_n);
    pool->free_pkts[pkt_idx] = id;
  }
  pool->first_free -= count;
}


ZF_HOT static inline bool
zf_pool_empty(const struct zf_pool* pool)
{
  return (pool->first_free == pool->pkt_bufs_n);
}

#endif /* __ZF_POOL_H__ */
