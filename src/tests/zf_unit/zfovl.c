/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2020-2021 Advanced Micro Devices, Inc. */
#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>
#include <zf_internal/rx_res.h>

#include <zf_internal/private/tcp_fast.h>
#include <zf_internal/private/zf_stack_def.h>

#include "../tap/tap.h"

#include "abstract_zocket_pair.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out, const char* interface)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* Request the default allocation of buffers explicitly. */
  zf_attr_set_int(*attr_out, "n_bufs", 0);

  ZF_TRY(zf_attr_set_str(*attr_out, "interface", interface));

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




struct  {
  int total_reads;
  int count;
  int wait_fail;
  int no_data;
  int normal_reads;
} pftf_stats {};

int pftf_sync_enable = 1;

void prep_buf(char* buf, int len, int magic)
{
  for(int i = 0, v = magic; i < len; ++i, ++v )
    buf[i] = v;
}

static int recv_ovl(struct zf_stack* stacks[], zf_muxer_set* muxer, struct zft* tcp,
                    int magic, int len, int alien_event)
{
  int recved = 0;
  struct {
    struct zft_msg header;
    struct iovec iov[SW_RECVQ_MAX];
  } msg;

  char buf[TCP_MAX_MSS*2];
  prep_buf(buf, len, magic);

  int pftf_resume = pftf_sync_enable;

  /* The timing of running with loopback emulation means that some packets
   * might not be received before the first zft_zc_recv() call, so loop
   * until the required length is received.
   */
  do {
    unsigned recved1 = 0;
    epoll_event event;

    int cnt = zf_muxer_wait(muxer, &event, 1, 0);

    if( pftf_resume )
        /* resume arrival of events to rxq */
      zf_emu_pftf_resume(stacks[0], 0);
    pftf_resume = 0;

    if( cnt == 0 )
      continue;

    msg.header.iovcnt = SW_RECVQ_MAX;

    if( event.events & ZF_EPOLLIN_OVERLAPPED ) {
      /* sort out pftf ovl event */
      ++pftf_stats.count;
      msg.iov[0].iov_len = 1;
      zft_zc_recv(tcp, &msg.header, ZF_OVERLAPPED_WAIT);
      if( msg.header.iovcnt == 0 ) {
        ++pftf_stats.wait_fail;
        continue;
      }
      cmp_mem(msg.iov[0].iov_base, buf + recved, msg.iov[0].iov_len,
              "wait payload");

      zft_zc_recv(tcp, &msg.header, ZF_OVERLAPPED_COMPLETE);
      if( msg.header.iovcnt == 0 ) {
        ++pftf_stats.no_data;
        continue;
      }
    }
    else {
      zft_zc_recv(tcp, &msg.header, 0);
      ++pftf_stats.normal_reads;
    }

    for( int i = 0; i < msg.header.iovcnt; i++ ) {
      cmp_mem(msg.iov[i].iov_base, buf + recved + recved1, msg.iov[i].iov_len,
              "payload ok");
      recved1 += msg.iov[i].iov_len;
    }

    if( recved1 == 0 )
      continue;

    zft_zc_recv_done(tcp, &msg.header);

    recved += recved1;
    ++pftf_stats.total_reads;
  } while (recved < len);

  return recved;
}


static void send_n(struct zf_stack* stack, struct zft* tcp, int magic, size_t len)
{
  char buf[TCP_MAX_MSS*2];

  prep_buf(buf, len, magic);
  struct iovec iov = { buf, len };
  cmp_ok(zft_send(tcp, &iov, 1, 0), "==", len, "managed to send %d bytes", len);
}

static void test_ovl(struct zf_stack* stacks[],
                     struct zfut* udp_tx, zf_muxer_set* muxer,
                     struct zft* tcp_tx,
                     struct zft* tcp_rx, size_t len, int count)
{
  for(int i = 0; i < count; ++i) {
    while(zf_reactor_perform(stacks[1]));

    /* block arrival of events to rxq */
    if( udp_tx ) {
      char buf[1] {};
      ZF_TRY(zfut_send_single(udp_tx, buf, 1));
    }
    if( pftf_sync_enable )
      zf_emu_pftf_pause(stacks[0], 0);
    send_n(stacks[1], tcp_tx, i, len);
    cmp_ok(recv_ovl(stacks, muxer, tcp_rx, i, len, udp_tx != 0), "==", len,
          "cnt %d len %d", i, len);
  }
}


constexpr auto OVL_COUNT = 10;


static int test_tcp(struct zf_stack* stacks[], struct zf_attr* attr)
{
  struct abstract_zocket_pair zockets;
  int iterations = 0;
  auto stack = stacks[0];

  /* Allocate TCP zockets */
  auto nop = [] {};
  alloc_tcp_pair_t(stacks[1], stacks[0], attr, &zockets, nop);
  struct zft* tcp_tx = (struct zft*)zockets.opaque_tx;
  struct zft* tcp_rx = (struct zft*)zockets.opaque_rx;


  zf_muxer_set* muxer;
  ZF_TRY(zf_muxer_alloc(stack, &muxer));

  const struct epoll_event in_event_ovl  = {
    .events = ZF_EPOLLIN_OVERLAPPED | EPOLLIN,
    .data = { .u32 = ZF_EPOLLIN_OVERLAPPED },
  };
  const struct epoll_event in_event  = {
    .events = EPOLLIN,
    .data = { .u32 = EPOLLIN },
  };
  (void) in_event;

  /* a bit of hack we do not use muxer but mark zocket
   * for overlapped events this way */
  ZF_TRY(zf_muxer_add(muxer, zft_to_waitable(tcp_rx), &in_event_ovl));


  for( size_t sz = 1; sz < TCP_MAX_MSS; sz += 11 ) {
    pftf_sync_enable = 1;
    pftf_stats = {};
    test_ovl(stacks, NULL, muxer, tcp_tx, tcp_rx, sz, OVL_COUNT);

    //cmp_ok(pftf_stats.normal_reads, "==", 0, "normal reads as expected #TODO blah");
    cmp_ok(pftf_stats.count, "==", OVL_COUNT, "ovl count as expected %d", pftf_stats.normal_reads);
    cmp_ok(pftf_stats.no_data, "==", 0, "no data failures");
    cmp_ok(pftf_stats.wait_fail, "==", 0, "no wait failures");
    ++iterations;
  }


  ZF_TRY(zf_muxer_mod(zft_to_waitable(tcp_rx), &in_event));

  { /* verify no ovl events */
    pftf_stats = {};
    pftf_sync_enable = 0;
    test_ovl(stacks, NULL, muxer, tcp_tx, tcp_rx, 1, OVL_COUNT);

    cmp_ok(pftf_stats.count, "==", 0, "did not expect ovl events");
    cmp_ok(pftf_stats.no_data, "==", 0, "no data failures");
    cmp_ok(pftf_stats.wait_fail, "==", 0, "no wait failures");
    ++iterations;
  }

  ZF_TRY(zf_muxer_mod(zft_to_waitable(tcp_rx), &in_event_ovl));

  /* interleaving with normal reads */
  for( size_t sz = TCP_MAX_MSS; sz < TCP_MAX_MSS * 2; sz += 500 ) {
    pftf_sync_enable = 1;
    pftf_stats = {};
    test_ovl(stacks, NULL, muxer, tcp_tx, tcp_rx, sz, OVL_COUNT);

    cmp_ok(pftf_stats.count, ">=", OVL_COUNT, "ovl count as expected");
    cmp_ok(pftf_stats.no_data, "==", 0, "no data failures");
    cmp_ok(pftf_stats.wait_fail, "==", 0, "no wait failures");
    ++iterations;
  }

  /* TODO: verify rollback due to unrelated events */

  zf_muxer_del(zft_to_waitable(tcp_rx));
  zf_muxer_free(muxer);
  return 0;
}


static int test(struct zf_stack* stacks[], struct zf_attr* attr)
{

  test_tcp(stacks, attr);
  done_testing();

  plan(-1);
}


int main(void)
{
  int rc;
  struct zf_stack* stack[2];
  struct zf_attr* attr[2];

  ZF_TRY(init(&stack[0], &attr[0], ZF_EMU_B2B0));
  ZF_TRY(init(&stack[1], &attr[1], ZF_EMU_B2B1));
  rc = test(stack, attr[0]);
  ZF_TRY(fini(stack[1], attr[1]));
  ZF_TRY(fini(stack[0], attr[0]));

  return rc;
}

