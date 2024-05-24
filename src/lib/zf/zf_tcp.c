/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_stackdump.h>


void zf_tcp_acquire(struct zf_tcp* tcp)
{
  zf_log_tcp_conn_trace(tcp, "%s\n", __func__);

  zf_assert_ge(tcp->refcount, 0);
  tcp->refcount++;
}


static void zf_tcp_free(struct zf_stack* stack, struct zf_tcp* tcp)
{
  zf_assert_equal(tcp->refcount, 0);
  zf_rx_res* rx_res;
  zf_stack_tcp_to_res(stack, tcp, &rx_res);
  /* In case zocket was never connected but bound we need to free port
   * the same applies to zft_handle */
  zfrr_release_port(stack, rx_res);
  memset(&tcp->laddr, 0, sizeof(tcp->laddr));

  if( tcp->eof_pkt != PKT_INVALID ) {
    zf_pool_free_pkt(&stack->pool, tcp->eof_pkt);
    tcp->eof_pkt = PKT_INVALID;
  }

  /* We should have purged the RX queue by this point, or else we'll leak
   * packets. */
  zf_assert(zfr_queue_all_packets_processed(&tcp->tsr));
  zf_assert(zfr_queue_all_packets_read(&tcp->tsr));

  zf_stack_free_tcp(stack, tcp);
}


void zf_tcp_release(struct zf_stack* stack, struct zf_tcp* tcp)
{
  zf_log_tcp_conn_trace(tcp, "%s\n", __func__);
  zf_assert_gt(tcp->refcount, 0);
  if( --tcp->refcount == 0 )
    zf_tcp_free(stack, tcp);
  else if( tcp->pcb.state & FIN_WAIT_STATE_MASK )
    tcp_finwait_timeout_start(stack, tcp);
}


void zf_tcp_on_stack_free(struct zf_stack* stack, struct zf_tcp* tcp)
{
  zf_log_tcp_conn_trace(tcp, "%s\n", __func__);
  zf_assert_gt(tcp->refcount, 0);

  /* There is at least one reference here, but we don't care if it's that of
   * the app, or the state machine.  The stack will never be polled again,
   * and we don't care about attempting to reset connections, so all we have
   * to do is to free the resources. */

   /* Try to send RST if needed.
   * In debug build, we also want to release all packets to check for
   * packet leak. */
  if( ! tcp_is_orphan(tcp) )
    zft_free(&tcp->ts);

  /* If all references have been released, then we're done here. */
  if( tcp->refcount == 0 )
    return;

  /* Otherwise the TCP core is keeping a reference. */
  zf_assert(tcp->pcb.state & (FIN_WAIT_STATE_MASK | TIME_WAIT));
  tcp_finwait_timeout(stack, tcp);
}


int zf_tcp_new(struct zf_stack* st, struct zf_tcp** tcp_out)
{
  struct zf_tcp* tcp;

  int rc = zf_stack_alloc_tcp(st, &tcp);
  if( rc < 0 )
    return rc;

  struct zf_rx_res* rx_res;
  zf_stack_tcp_to_res(st, tcp, &rx_res);
  zfrr_init(rx_res);

  memset(&tcp->tst.pkt, 0, sizeof(tcp->tst.pkt));
  zfr_init(&tcp->tsr);
  zf_waitable_init(&tcp->w);
  tcp->refcount = 0;

  /* Allocate a packet for queuing EOF.  This must succeed */
  rc = zft_alloc_pkt(&st->pool, &tcp->eof_pkt);
  if( rc != 0 ) {
    zf_stack_free_tcp(st, tcp);
    return rc;
  }

  tcp_init(tcp);

  tcp->zocket_mask = 1ull << TCP_ID(st, tcp);
  tcp->zocket_alts = 0;

  *tcp_out = tcp;
  return 0;
}


void zf_tcp_dump(SkewPointer<zf_stack> stack, SkewPointer<zf_tcp> tcp)
{
  ZF_INET_NTOP_DECLARE_BUF(lbuf);
  ZF_INET_NTOP_DECLARE_BUF(rbuf);

  zf_dump("TCP %." ZF_STRINGIFY(ZF_STACK_NAME_SIZE)
          "s:%d lcl=%s:%d rmt=%s:%d retransmits=%d %s\n",
          stack->st_name, TCP_ID(stack, tcp),
          ZF_INET_NTOP_CALL(tcp->laddr.sin_addr.s_addr, lbuf),
          ntohs(tcp->laddr.sin_port),
          ZF_INET_NTOP_CALL(tcp->raddr.sin_addr.s_addr, rbuf),
          ntohs(tcp->raddr.sin_port),
          tcp->pcb.stats.retransmits,
          tcp_state_num_str(tcp->pcb.state));
  zf_waitable_dump(tcp.propagate_skew(&tcp->w));
  zf_tx_dump(&tcp->tst, IPPROTO_TCP);
  zf_rx_dump(&tcp->tsr);
  tcp_dump(tcp);
}


void zf_tcp_listen_dump(SkewPointer<zf_stack> stack,
                        SkewPointer<zf_tcp_listen_state> listen)
{
  zf_dump("TCP LISTEN %." ZF_STRINGIFY(ZF_STACK_NAME_SIZE) "s:%d lcl=%s:%d\n",
          stack->st_name, TCP_LISTEN_ID(stack, listen),
          inet_ntoa(listen->laddr.sin_addr), ntohs(listen->laddr.sin_port));
  zf_waitable_dump(listen.propagate_skew(&listen->w));
  zf_dump("  acceptq: %s\n",
          listen->acceptq_head == ZF_ZOCKET_ID_INVALID ? "no" : "yes");
}

