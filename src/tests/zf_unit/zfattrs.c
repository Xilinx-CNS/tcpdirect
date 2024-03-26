/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>

#include "../tap/tap.h"


struct attr_value {
  char name[32];
  int value;  /* A non-default value to test */
};

struct attr_value test_attrs[] = {
  { "log_level", 0x7777 },
  { "log_format", 0 },
  { "log_to_kmsg", 1 },
  { "tcp_delayed_ack", 0 },
  { "tcp_wait_for_time_wait", 1 },
  { "tcp_timewait_ms", ZF_TCP_TIMEWAIT_TIME_MS / 2 },
  { "tcp_finwait_ms", ZF_TCP_TIMEWAIT_TIME_MS / 2 },
  { "tcp_syn_retries", 2 },
  { "tcp_synack_retries", 2 },
  { "tcp_retries", 7 },
  { "tcp_initial_cwnd", 5 * TCP_MSS },
  { "tcp_alt_ack_rewind", 16384 },
  { "rx_ring_max", 1024 },
  { "reactor_spin_count", 32 },
  { "rx_ring_refill_batch_size", 8 },
  { "rx_ring_refill_interval", 2 },
  { "tx_ring_max", 1024 },
  { "alt_buf_size", 4096 },
  { "alt_count", 1 },
};


static int set_test_attrs(struct zf_attr* attr)
{
  int num_attrs = sizeof(test_attrs) / sizeof(test_attrs[0]);
  unsigned int seed = zf_frc64();
  int random = rand_r(&seed);

  /* Make sure the 32-bit random number will cover all attributes */
  zf_assert_le(num_attrs, 32);

  diag("attr test bitmask 0x%x\n", (random & ((1 << num_attrs) - 1)));

  /* Always set n_bufs in case rx_ring_max or tx_ring_max are increased */
  zf_attr_set_int(attr, "n_bufs", 4096);

  for( int i = 0; i < num_attrs; ++i ) {
    int rc;

    if( (random & (1 << i)) == 0 )
      continue;

    rc = zf_attr_set_int(attr, test_attrs[i].name, test_attrs[i].value);
    if( rc != 0 )
      return rc;
  }

  return 0;
}


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

  rc = set_test_attrs(*attr_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

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

  return 0;
}


#define TESTS_PER_ITER 2

static void test(struct zf_stack* stack, struct zf_attr* attr,
                unsigned int iter)
{
  struct sockaddr_in listen_addr, tx_addr;
  struct zftl* listener = NULL;
  struct zft_handle* tx_handle;
  struct iovec iov = { &iter, sizeof(iter) };
  struct {
    struct zft_msg header;
    struct iovec iov[1];
  } msg;
  struct zft* tcp_rx;
  struct zft* tcp_tx;
  int rc;

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(4000 + iter);
  listen_addr.sin_addr.s_addr = inet_addr("127.0.0.4");

  ZF_TRY(zftl_listen(stack, (struct sockaddr*)&listen_addr, sizeof(listen_addr),
                     attr, &listener));

  tx_addr.sin_family = AF_INET;
  tx_addr.sin_port = htons(3000 + iter);
  tx_addr.sin_addr.s_addr = inet_addr("127.0.0.3");

  ZF_TRY(zft_alloc(stack, attr, &tx_handle));
  ZF_TRY(zft_addr_bind(tx_handle, (struct sockaddr*)&tx_addr,
                       sizeof(tx_addr), 0));

  ZF_TRY(zft_connect(tx_handle, (struct sockaddr*)&listen_addr,
                     sizeof(listen_addr), &tcp_tx));

  do {
    while( zf_reactor_perform(stack) == 0 );
  } while( (rc = zftl_accept(listener, &tcp_rx)) == -EAGAIN );
  ZF_TRY(rc);

  rc = zft_send(tcp_tx, &iov, 1, 0);
  cmp_ok(rc, "==", sizeof(iter), "Data sent");

  while( zf_reactor_perform(stack) == 0 );

  msg.header.iovcnt = 1;
  zft_zc_recv(tcp_rx, &msg.header, 0);
  rc = (msg.iov[0].iov_len == sizeof(iter)) &&
       (memcmp(msg.iov[0].iov_base, &iter, sizeof(iter)) == 0);
  cmp_ok(rc, "!=", 0, "Correct data received");

  zft_zc_recv_done(tcp_rx, &msg.header);
}


#define ITERS 50

int main(void)
{
  plan(TESTS_PER_ITER * ITERS);

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  for( unsigned int i = 0; i < ITERS; ++i ) {
    struct zf_stack* stack;
    struct zf_attr* attr;

    ZF_TRY(init(&stack, &attr));
    test(stack, attr, i);
    ZF_TRY(fini(stack, attr));
  }

  zf_deinit();

  return rc;
}

