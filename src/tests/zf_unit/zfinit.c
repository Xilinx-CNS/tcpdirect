/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  verify build with zf library, sanitize initialization
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>

#include <arpa/inet.h>

#include "../tap/tap.h"


#define ZFINIT_TESTS 6

#define CHECK_OK(it,x) \
  do { int rc = (x); ok(rc == 0, "%d %s=%d", it, #x, rc);       \
    if(rc) { done_testing(); } } while(0)


int test_iteration(int it)
{
  struct zf_attr* attr;
  struct zf_stack* stack;
  struct zfur* ur;

  CHECK_OK(it, zf_init());
  CHECK_OK(it, zf_attr_alloc(&attr));
  CHECK_OK(it, zf_stack_alloc(attr, &stack));
  CHECK_OK(it, zfur_alloc(&ur, stack, attr));

  struct sockaddr_in laddr = {
    AF_INET,
    htons(2000),
    { inet_addr("127.0.0.1") },
    };
  struct sockaddr_in raddr = {
    AF_INET,
    htons(2001),
    { inet_addr("192.168.0.2") },
    };

  CHECK_OK(it, zfur_addr_bind(ur, (struct sockaddr*)&laddr, sizeof(laddr),
                              (struct sockaddr*)&raddr, sizeof(raddr), 0));
  CHECK_OK(it, zf_stack_free(stack));
  zf_attr_free(attr);
  zf_deinit();

  return 0;
}

int main(void)
{
  /* Higher then some number of resources e.g. there is 15 pio buffers.
   * Also repeated testing checks reliability of license validation.
   */
  int iterations = 20;
  int i;
  plan(ZFINIT_TESTS * iterations);

  for( i = 0; i < iterations; ++i )
    if( test_iteration(i) )
      done_testing();

  done_testing();
}
