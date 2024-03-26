/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF packet management */

#include <zf_internal/zf_pool.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/platform.h> /* HUGE_PAGE_SIZE */

#include <zf_internal/private/zf_hal.h>

#include <errno.h>
#include <sys/mman.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000u
#endif

int zf_pool_map(struct zf_stack* st, struct zf_pool_res* pi, int nicno)
{
  struct zf_pool* pool = pi->pool;
  ef_driver_handle dh = zf_stack_get_driver_handle(st, nicno);
  ef_pd* pd = zf_stack_get_pd(st, nicno);

  struct zf_pool_nic* p_nic = &pool->nic[nicno];
  struct zf_pool_res_nic* pi_nic = &pi->nic[nicno];

  /* We shouldn't try and map a pool for the same NIC twice */
  zf_assert_equal(pi_nic->memreg.mr_dma_addrs, NULL);

  /* Register the memory so that the adapter can access it. */
  int rc = ef_memreg_alloc(&pi_nic->memreg, dh, pd, dh, pool->pkt_bufs,
                           pi->pkt_bufs_mmap_len);
  if( rc < 0 ) {
    pi_nic->memreg.mr_dma_addrs = NULL;
    return rc;
  }

  zf_log_pool_info(pool, "allocated %d pkt buffers \n", pool->pkt_bufs_n);
  for( unsigned i = 0; i < pool->pkt_bufs_n; ++i ) {
    ef_addr addr = ef_memreg_dma_addr(&pi_nic->memreg, i * PKT_BUF_SIZE);
    /* For ef10 512 buffers should fit single NIC page,
     * we store base address only once per the lot */
    if( (i & (PKT_BUFS_IN_NIC_PAGE - 1)) == 0 ) {
      zf_assert_lt(i/PKT_BUFS_IN_NIC_PAGE, MAX_PKT_NIC_PAGES);
      p_nic->efaddr[i/PKT_BUFS_IN_NIC_PAGE] = addr;
      zf_log_pool_trace(pool, "  efaddr %p, vaddr %p pkts %d\n", (void*)addr,
                        PKT_BUF_BY_ID(pool,i), PKT_BUFS_IN_NIC_PAGE);
    }
    zf_assert_equal(addr, PKT_EFADDR_BY_ID(pool, nicno, i));
  }

  return 0;
}


int zf_pool_alloc(struct zf_pool_res* pi, struct zf_pool* pool,
                  struct zf_stack* st, unsigned n_bufs)
{
  int rc;

  pi->pool = pool;
  pi->st = st;

  int onload_dh = zf_stack_get_onload_handle(st);

  pool->pkt_bufs_n = n_bufs;
  if( pool->pkt_bufs_n > PKT_BUFS_IN_NIC_PAGE * MAX_PKT_NIC_PAGES ) {
    zf_log_pool_warn(pool, "ZF: Can not allocate more than %d packets "
                     "(requested to allocated %d)\n",
                     PKT_BUFS_IN_NIC_PAGE * MAX_PKT_NIC_PAGES,
                     pool->pkt_bufs_n);
    pool->pkt_bufs_n = PKT_BUFS_IN_NIC_PAGE * MAX_PKT_NIC_PAGES;
  }

  size_t alloc_size = pool->pkt_bufs_n * PKT_BUF_SIZE;
  alloc_size = ROUND_UP(alloc_size, HUGE_PAGE_SIZE);

  /* Allocate huge pages for the packet buffers.  Since these are MAP_SHARED,
   * they will preserved across fork() (rather than ending up with copy-on-
   * write mappings, which would otherwise be the case), which allows children
   * to continue to use them as DMA buffers. */
  pool->pkt_bufs =
    (char*) zf_hal_mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_SHARED | MAP_HUGETLB, -1, 0);
  pi->pkt_bufs_mmap_len = alloc_size;

  /* Huge pages only */
  if( pool->pkt_bufs == MAP_FAILED ) {
    zf_log_pool_err(pool, "Failed to allocate huge page for pool, "
                    "are huge pages available?\n");
    return -errno;
  }


  pool->free_pkts = (pkt_id*) calloc(pool->pkt_bufs_n, sizeof(pkt_id));
  if( pool->free_pkts == NULL ) {
    rc = -ENOMEM;
    goto fail1;
  }

  pool->first_free = 0;
  for( unsigned i = 0; i < pool->pkt_bufs_n; ++i ) {
    pool->free_pkts[i] = i;
  }

  /* Register the buffer so that stackdump can map it. */
  pi->pkt_bufs_shm_id = -1;
  rc = oo_dshm_register(onload_dh, OO_DSHM_CLASS_ZF_PACKETS,
                            pool->pkt_bufs, alloc_size);
  if( rc < 0 ) {
    zf_log_pool_err(pool, "Failed to register pool shm (rc = %d)\n", rc);
    goto fail2;
  }
  pi->pkt_bufs_shm_id = rc;

  /* Ensure that we know which nics have mapped the pool when we come to
   * clean up.
   */
  for( int i = 0; i < ZF_MAX_NICS; i++ )
    pi->nic[i].memreg.mr_dma_addrs = NULL;

  return 0;

 fail2:
  free(pool->free_pkts);
 fail1:
  zf_hal_munmap(pool->pkt_bufs, pi->pkt_bufs_mmap_len);
  return rc;
}

int zf_pool_free(struct zf_stack* stack, struct zf_pool_res* pi)
{
  /* Tolerate freeing of an uninitialised pool. */
  if( pi->pool != NULL ) {
    for( int i = 0; i < ZF_MAX_NICS; i++ ) {
      if( pi->nic[i].memreg.mr_dma_addrs ) {
        int rc1 = ef_memreg_free(&pi->nic[i].memreg,
                                 zf_stack_get_driver_handle(stack, i));
        zf_assert_equal(rc1, 0);
      }
    }
    free(pi->pool->free_pkts);
    int rc2 = zf_hal_munmap(pi->pool->pkt_bufs, pi->pkt_bufs_mmap_len);
    return (rc2 < 0) ? rc2 : 0;
    
    /* The pool's dshm segments will be unregistered when the stack is freed,
     * so there's nothing to do here in that regard.
     */
  }

  return 0;
}
