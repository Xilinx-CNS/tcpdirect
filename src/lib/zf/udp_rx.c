/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** UDP RX slow path and resource management */

#include <zf/zf.h>
#include <zf_internal/rx.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/private/zf_stack_rx.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/utils.h>
#include <zf_internal/timestamping.h>
#include <zf_internal/zf_stackdump.h>
#include <zf_internal/private/zf_stack_rx.h>

#include <netinet/in.h>

_Static_assert(sizeof(zf_udp_rx::zocket_mask) * 8 >= zf_stack::MAX_ZOCKET_COUNT);

extern int zfur_alloc(struct zfur** us_out, struct zf_stack* st, const struct zf_attr* attr)
{

  if ( ef_vi_receive_capacity(&st->nic[0].vi) == 0 ) {
    zf_log_stack_err(st, "Failed to allocate RX UDP zocket in a stack with no RX capability\n");
    return -EINVAL;
  }

  struct zf_udp_rx* udp_rx;
  struct zf_rx* rx;
  int rc = zf_stack_alloc_udp_rx(st, &udp_rx);
  if( rc < 0 )
    return rc;
  rx = &udp_rx->rx;

  zfr_init(rx);

  udp_rx->zocket_mask = 1ull << UDP_RX_ID(st, udp_rx);

  udp_rx->counters.q_drops = 0;

  struct zf_rx_res* rx_res;
  zf_stack_udp_rx_to_res(st, udp_rx, &rx_res);
  zfrr_init(rx_res);

  zf_waitable_init(&udp_rx->w);
  *us_out = &udp_rx->handle;
  return 0;
}


/* This function is effectively "please install a filter for me".  It can be
 * called multiple times.
 */
extern int zfur_addr_bind(struct zfur* us, struct sockaddr* laddr_sa,
                          socklen_t laddrlen, const struct sockaddr* raddr_sa,
                          socklen_t raddrlen, int flags)
{
  struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, us);
  struct zf_stack* st = zf_stack_from_zocket(us);
  struct zf_rx_res* rx_res;

  if( raddr_sa != NULL )
    ZF_CHECK_SOCKADDR_IN(raddr_sa, raddrlen);


  ZF_CHECK_SOCKADDR_IN(laddr_sa, laddrlen);

  struct sockaddr_in* raddr = (struct sockaddr_in*)raddr_sa;
  struct sockaddr_in* laddr = (struct sockaddr_in*)laddr_sa;

  /* ON-11555: allow zfur_addr_bind() with remote addr and
   * 0 remote port only if the laddr is multicast.
   */
  if ( raddr != NULL ) {
    bool raddr_is_all = raddr->sin_addr.s_addr == INADDR_ANY;
    bool raddr_port_is_0 = raddr->sin_port == 0;
    bool laddr_is_multicast = CI_IP_IS_MULTICAST(laddr->sin_addr.s_addr);
    if ( raddr_is_all && raddr_port_is_0 ) {
      /*
       * Convert raddr INADDR_ANY:0 to NULL for lower layers.
       * This is a deliberate precondition necessary for adding
       * local wild filters in lower layers.
       */
      raddr = NULL;
    } else if ( raddr_is_all || ( !laddr_is_multicast && raddr_port_is_0 ) ) {
        return -EINVAL;
    } 
  }

  /* No INADDR_ANY supported for laddr */
  if( laddr->sin_addr.s_addr == INADDR_ANY )
    return -EINVAL;


  zf_stack_udp_rx_to_res(st, udp_rx, &rx_res);
  return zfrr_add(st, rx_res, UDP_RX_ID(st, udp_rx), ZFRR_ALL_NICS,
                  IPPROTO_UDP,
                  zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_UDP),
                  st->rx_table[ZF_STACK_RX_TABLE_UDP], laddr, raddr, 1);
}


int zfur_addr_unbind(struct zfur* us, const struct sockaddr* laddr,
                     socklen_t laddrlen, const struct sockaddr* raddr,
                     socklen_t raddrlen, int flags)
{
  struct zf_stack* st = zf_stack_from_zocket(us);

  if( laddr != NULL )
    ZF_CHECK_SOCKADDR_IN(laddr, laddrlen);
  if( raddr != NULL )
    ZF_CHECK_SOCKADDR_IN(raddr, raddrlen);

  return zfrr_remove(st, zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_UDP), 0,
                     (struct sockaddr_in*)laddr, (struct sockaddr_in*)raddr);
}


int zfur_free(struct zfur* us)
{
  struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, us);
  struct zf_rx* rx = &udp_rx->rx;
  struct zf_stack* st = zf_stack_from_zocket(us);
  struct zf_rx_res* rx_res;
  int rc;

  /* Drop all unread packets. */
  zfr_drop_queue(&st->pool, rx);
  udp_rx->rx.release_n = 0;

  zf_stack_udp_rx_to_res(st, udp_rx, &rx_res);

  /* Remove all RX-table entries, filters and backing sockets. */
  rc = zfrr_remove_all(st, zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_UDP),
                       &rx_res->filter_list);
  if( rc < 0 ) {
    zf_log_stack_warn(st, "%s: Failed to release resources: rc = %d\n",
                      __FUNCTION__, rc);
    /* This should only happen if filter-removal failed, which means something
     * has gone badly wrong. */
    zf_assert(0);
  }

  zf_muxer_del(&udp_rx->w);

  /* Free the zocket buffers. */
  zf_stack_free_udp_rx(st, udp_rx);
  return 0;
}


void zfur_dump(SkewPointer<zf_stack> stack, SkewPointer<zf_udp_rx> udp_rx)
{
  struct zf_rx_res* rx_res;
  zf_stack_udp_rx_to_res(stack, udp_rx, &rx_res);

  zf_dump("UDP RX %." ZF_STRINGIFY(ZF_STACK_NAME_SIZE) "s:%u\n",
          stack->st_name, UDP_RX_ID(stack, udp_rx));

  struct zf_rx_table_res* rx_table_res =
    zf_stack_get_rx_table(stack, ZF_STACK_RX_TABLE_UDP);
  zf_rx_table_dump_list(stack.adjust_pointer(rx_table_res),
                        stack.propagate_skew(&rx_res->filter_list));

  zf_waitable_dump(udp_rx.propagate_skew(&udp_rx->w));
  zf_rx_dump(&udp_rx->rx);
  zf_dump("  udp rx: release_n=%u q_drops=%d\n", udp_rx->rx.release_n,
          udp_rx->counters.q_drops);
}


ZF_HOT static void
zf_pftf_recv_wait(zf_stack* st, zf_udp_rx* udp_rx, zfur_msg* restrict msg, int flags)
{
  unsigned len = zf_pftf_wait(st, msg->iov[0].iov_len);
  if(CI_UNLIKELY( len < 0 )) {
    /* Something got in the way (an event arrived), for simplicity:
     * let's complete the event,
     * tell the customer that there is nothing for now and make sure
     * the next run of reactor reports an event quickly */
    st->pftf.event_occurred_carry |= zf_stack_udp_finish_pftf(st, udp_rx);
    msg->iovcnt = 0;
    return;
  }
  msg->iovcnt = 1;
  msg->iov[0].iov_len = len;
  msg->iov[0].iov_base = st->pftf.payload;
}


ZF_HOT extern void
zfur_zc_recv(struct zfur *us, struct zfur_msg* restrict msg, int flags)
{
  zf_stack* stack = zf_stack_from_zocket(us);
  zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, us);
  zf_assert_nflags(flags, ~(ZF_OVERLAPPED_WAIT | ZF_OVERLAPPED_COMPLETE));
  zf_assert_impl(flags, ZF_IS_POW2(flags)); /* one flag only */

  if( flags & (ZF_OVERLAPPED_WAIT | ZF_OVERLAPPED_COMPLETE)) {
    zf_assert_equal(&udp_rx->w, stack->pftf.w);
    zf_assert(zfr_queue_all_packets_read(&udp_rx->rx));
    zf_assert_ge(msg->iovcnt, 1);
    zf_assert_equal(udp_rx->rx.release_n, 0);
    if( flags & ZF_OVERLAPPED_WAIT ) {
      zf_pftf_recv_wait(stack, udp_rx, msg, flags);
      return;
    }
    else {
      zf_stack_udp_finish_pftf(stack, udp_rx);
      /* fall through to normal recv */
    }
  }

  /* TODO: prefetch pkt payload */
  zfr_zc_read(&stack->pool, udp_rx, msg);
  zf_stack_udp_set_deferred_rx(stack, udp_rx->zocket_mask);
}


ZF_HOT void
zfur_zc_recv_done(struct zfur* us, struct zfur_msg* msg)
{
  struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, us);
  zf_assert(udp_rx->rx.release_n);
  zf_assert_equal(udp_rx->rx.release_n, (uint32_t) msg->iovcnt);

  zfr_zc_read_done_udp(&udp_rx->rx);

  if( ! zfr_queue_packets_unread_n(&udp_rx->rx) )
    zf_muxer_mark_waitable_not_ready(&udp_rx->w, EPOLLIN);
}

int zfur_pkt_get_timestamp(struct zfur* us, const struct zfur_msg* msg,
                           struct timespec* ts, int pktind, unsigned* flags)
{
  return zfr_pkt_get_timestamp(us, msg, ts, pktind, flags);
}

ZF_HOT int
zfur_pkt_get_header(struct zfur* us, const struct zfur_msg* restrict msg,
                    const struct iphdr** ip, const struct udphdr** udp, int pktind)
{
  if ( pktind < 0 || pktind >= msg->iovcnt )
    return -EINVAL;

  zf_stack* st = zf_stack_from_zocket(us);
  pkt_id id = PKT_BUF_ID_FROM_PTR(&st->pool, msg->iov[pktind].iov_base);
  const char* pkt = PKT_BUF_RX_START_BY_ID(&st->pool, id);
  zf_log_udp_rx_trace(ZF_CONTAINER(struct zf_udp_rx, handle, us),
                      "%s: pkt %x data %p\n", __func__, id, pkt);
  pkt += st->nic[0].rx_prefix_len;
  *ip = zf_ip_hdr((char*)pkt);
  *udp = (const struct udphdr*)((char*)*ip + sizeof(struct iphdr));

  return 0;
}


struct zf_waitable* zfur_to_waitable(struct zfur* us)
{
  struct zf_udp_rx* udp_rx = ZF_CONTAINER(struct zf_udp_rx, handle, us);
  return &udp_rx->w;
}

