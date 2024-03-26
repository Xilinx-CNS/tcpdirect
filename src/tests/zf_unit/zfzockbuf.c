/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  gd
**  \brief  Unit test for zocket allocation.
**   \date  2016/02/01
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_stack_impl.h>

#include "../tap/tap.h"


static int ptr_comparator(const void* a, const void* b)
{
  return *((const intptr_t*) a) - *((const intptr_t*) b);
}


#define MAX_ZOCKETS 8


#define TESTS_PER_ZOCKET_TYPE  (MAX_ZOCKETS * 2 + 4)

/* For each zocket type, we test that allocation and freeing works as expected,
 * and that the limits on the number of zockets are respected. */
#define TEST_TEMPLATE(type, desc, zock_alloc, zock_free)                     \
  static void test_##type(struct zf_stack* st)                               \
  {                                                                          \
    struct type* zockets[MAX_ZOCKETS + 1];                                   \
    for( int i = 0; i < MAX_ZOCKETS; ++i )                                   \
      cmp_ok(zock_alloc(st, &zockets[i]), "==", 0,                           \
             "Allocated " desc " zocket %d", i);                             \
    cmp_ok(zock_alloc(st, &zockets[MAX_ZOCKETS]), "==", -ENOBUFS,            \
           "Didn't allow " desc " allocation beyond maximum");               \
    cmp_ok(zock_free(st, zockets[MAX_ZOCKETS - 1]), "==", 0,                 \
           "Freed " desc " zocket");                                         \
    cmp_ok(zock_alloc(st, &zockets[MAX_ZOCKETS - 1]), "==", 0,               \
           "Can alloc " desc " again now");                                  \
    qsort(zockets, MAX_ZOCKETS, sizeof(zockets[0]), ptr_comparator);         \
    int all_different = 1;                                                   \
    for( int i = 0; i < MAX_ZOCKETS - 1; ++i )                               \
      if( zockets[i] == zockets[i + 1] )                                     \
        all_different = 0;                                                   \
    ok(all_different, "All " desc " zockets are different");                 \
    for( int i = 0; i < MAX_ZOCKETS; ++i )                                   \
      cmp_ok(zock_free(st, zockets[i]), "==", 0, "Freed " desc " zocket %d", \
             i);                                                             \
  }

TEST_TEMPLATE(zf_udp_rx, "UDP RX", zf_stack_alloc_udp_rx, zf_stack_free_udp_rx)
TEST_TEMPLATE(zf_udp_tx, "UDP TX", zf_stack_alloc_udp_tx, zf_stack_free_udp_tx)
TEST_TEMPLATE(zf_tcp, "TCP",    zf_stack_alloc_tcp, zf_stack_free_tcp)


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  rc = zf_attr_set_int(*attr_out, "max_udp_rx_endpoints", MAX_ZOCKETS);
  if( rc != 0 )
    return rc;
  rc = zf_attr_set_int(*attr_out, "max_udp_tx_endpoints", MAX_ZOCKETS);
  if( rc != 0 )
    return rc;
  rc = zf_attr_set_int(*attr_out, "max_tcp_endpoints", MAX_ZOCKETS);
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


static void test(struct zf_stack* st)
{
  plan(TESTS_PER_ZOCKET_TYPE * 3);

  test_zf_udp_rx(st);
  test_zf_udp_tx(st);
  test_zf_tcp(st);
}


int main(void)
{
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  test(stack);
  ZF_TRY(fini(stack, attr));

  return 0;
}

