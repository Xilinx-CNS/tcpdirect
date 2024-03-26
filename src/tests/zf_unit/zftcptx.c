/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"


static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

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

/* We want sends to be smaller than the MSS, so that one-message-per-sendq-
 * buffer is insufficient, but large enough that we don't have to make a
 * gazillion sends to fill the sendq. */
#define MSG_SIZE 512

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  struct abstract_zocket_pair zockets;

  /* We leave the plan until the end: the number of sends it take to fill the
   * sendq, although approximately determined by the size of the sendq and the
   * size of the sends, is an implementation detail. */

  /* Allocate TCP zockets */
  alloc_tcp_pair(stack, attr, &zockets);
  struct zf_tcp* tcp_tx_state = (struct zf_tcp*) zockets.opaque_tx;
  struct zft* tcp_tx = &tcp_tx_state->ts;

  size_t initial_send_space;
  ZF_TRY(zft_send_space(tcp_tx, &initial_send_space));

  const int INITIAL_TESTS = 1;
  cmp_ok(zft_get_mss(tcp_tx), "==",
         attr->emu_mtu - sizeof(struct tcphdr) - sizeof(struct iphdr),
         "zft_get_mss() returned correct MSS");

  /* We want to test two things: that the zocket ceases to be EPOLLOUT-ready
   * when its sendq-fill-level passes the watermark, and that that watermark is
   * sane.  We do this by repeatedly sending a packet, querying EPOLLOUT-ness,
   * and range-checking the sendq-level. */

  int rc;
  int num_sends;
  size_t send_space;
  char buf[MSG_SIZE] = {0};

  const int TESTS_PER_SEND = 2;

  for( num_sends = 0; (rc = zft_send_single(tcp_tx, buf, MSG_SIZE, 0)) >= 0;
       ++num_sends ) {
    /* The exact value of the sendq theshold is an implementation detail.
     * What we want to test is that the threshold is reasonable: it mustn't be
     * so small as to necessitate repeated send-backoffs, but not so large as
     * to be wasteful.  We take "too large" to be half of the sendq-size, and
     * "too small" to be an eighth of it. */

    if( tcp_tx_advertise_space(tcp_tx_state) ) {
      ZF_TRY(zft_send_space(tcp_tx, &send_space));
      cmp_ok(tcp_tx_state->w.readiness_mask, "&", EPOLLOUT,
             "Zocket ready for EPOLLOUT when TX-space advertised.");
      cmp_ok(send_space, ">=", initial_send_space / 8,
             "A reasonable amount of sendq space is available.");
    }
    else {
      cmp_ok(~tcp_tx_state->w.readiness_mask, "&", EPOLLOUT,
             "Zocket not ready for EPOLLOUT when TX-space not advertised.");
      /* Here we check that we have queued sufficient payload, rather than that
       * the available space has shrunk.  This is a stronger test: it
       * ensures that we make efficient use of sendq space for payload. */
      todo("bug64944: This can fail in the absence of support for sendq-"
           "coalescing.");
        cmp_ok(num_sends * MSG_SIZE, ">=", initial_send_space / 2,
               "Most of the initial sendq space has been consumed.");
      end_todo;
    }
  }

  const int FINAL_TESTS = 4;

  cmp_ok(rc, "==", -EAGAIN, "zft_send() finally returned -EAGAIN");

  ZF_TRY(zft_send_space(tcp_tx, &send_space));
  cmp_ok(send_space, "<", MSG_SIZE, "sendq is exhausted");

  todo("bug64944: This can fail in the absence of support for sendq-"
       "coalescing.");
    cmp_ok(num_sends, ">=", initial_send_space / MSG_SIZE,
           "Initially-advertised send space was indeed available.");
  end_todo;

  ZF_TRY(zft_free(tcp_tx));
  cmp_ok(zft_get_mss(tcp_tx), "==", -ENOTCONN,
         "zft_get_mss() returned -ENOTCONN on closed zocket");

  plan(INITIAL_TESTS + num_sends * TESTS_PER_SEND + FINAL_TESTS);

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

