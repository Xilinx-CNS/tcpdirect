/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Unit test for ZF packet management.
**   \date  2015/11/02
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/zf_pool_res.h>

#include <stdio.h>

#include "../tap/tap.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}


static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}

#define CHECK_RC(x) \
({ int rc = (x); if( rc != 0 ) { diag("Fail: " #x"\n"); return rc; } })

#define CHECK_TRUE(x) \
({ int rc = (x); if( ! rc ) { diag("False: " #x "\n"); return rc; } })


int cmpfunc (const void * a, const void * b)
{
   return ( *(pkt_id*)a - *(pkt_id*)b );
}


int test_play(struct zf_pool* pool, unsigned size)
{
  pkt_id stored_ids[size];
  CHECK_TRUE( (size & 0xF) == 0 );
  /* we will be allocating in differnt batches */
  for(unsigned batch = 1; batch < 16; ++batch) {
    /* repeat the test few times */
    for(int it = 0; it < 3; ++it) {
      for(int i = 0; i * batch < size; ++i) {
        unsigned count = batch;
        pkt_id* pkts;
        CHECK_RC(zf_pool_get_free_pkts(pool, &pkts, &count));
        CHECK_TRUE(count == MIN(batch, size - i * batch));
        for(unsigned j = 0; j < count; ++ j)
            stored_ids[i * batch + j] = pkts[j];
        zf_pool_get_free_pkts_done(pool);
      }
      qsort(stored_ids, size, sizeof(pkt_id), cmpfunc);
      /* check no dups */
      for(unsigned i = 0; i < size - 1; ++i) {
        CHECK_TRUE(stored_ids[i] != stored_ids[i+1]);
      }
      for(unsigned i = 0; i < size; ++i) {
        /* we free packets in slightly different order */
        zf_pool_free_pkt(pool, stored_ids[i ^ (1<<it)]);
      }
    }
  }
  return 0;
}


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  int n_bufs[] = {
    512,
    4096,
    1 << 15,
#if 0
    /* Currently, zf_pool_alloc() will exit the application on failure, but in
     * case this is ever extended to return a failure code: */
    1 << 30,  /* Should fail with ENOMEM. */
    -1,       /* Should fail with EINVAL (?). */
    0,        /* Should fail with EINVAL (?). */
#endif
  };

  int i;
  int len = sizeof(n_bufs) / sizeof(n_bufs[0]);

  plan(len * 2);

  for( i = 0; i < len; ++i ) {
    int tx = n_bufs[i];
    int rc;
    struct zf_pool_res pool_res;
    struct zf_pool pool;
    memset(&pool, 0, sizeof(pool));

    /* Feed dummy structures to zf_pool_alloc().  Normally these would be
     * part of the stack structures.  XXX: In principle we will leak the
     * stack's initial pool and double-free the last pool that we allocate.
     * At present we don't have the necessary apparatus to work around this
     * as pool-freeing has not been implemented and there's no clean way to
     * free the initial pool. */
    cmp_ok(rc = zf_pool_alloc(&pool_res, &pool, stack, tx), "==", 0,
           "Call zf_pool_alloc: n_bufs=%d", tx);

    if( rc != 0 )
      continue;

    /* insight into zf_pool_alloc */
    int pkt_bufs_n = tx;

    cmp_ok(test_play(&pool, pkt_bufs_n), "==", 0,
           "Basic pool manipulation");
    if( rc == 0 ) zf_pool_free(stack, &pool_res);
    /* TODO: Validate the sanity of the allocated pool once its
     * implementation has stabilised. */
  }

  done_testing();
}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}
