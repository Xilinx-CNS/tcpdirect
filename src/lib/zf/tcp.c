/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF TCP API */

#include <zf/zf.h>
#include <zf_internal/zf_tcp.h>
#include <zf_internal/tx.h> 
#include <zf_internal/tx_warm.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/tcp.h>
#include <zf_internal/attr.h>
#include <zf_internal/stack_params.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_stack_rx.h>
#include <zf_internal/zf_tcp_timers.h>
#include <zf_internal/timestamping.h>
#include <zf_internal/cplane.h>
#include <zf_internal/utils.h>

#include <netinet/in.h>


/* This allocates the handle which is used to refer to the zocket until we
 * create the real zft structure, which requires knowing what filters we
 * need.
 *
 * At the moment the handle structure is actually the same thing, but we
 * don't guarantee this.
 *
 * This function just does basic zf initialisation.
 * 
 */
int zft_alloc(struct zf_stack* st, const struct zf_attr* attr,
              struct zft_handle** ts_out)
{

  if ( ef_vi_transmit_capacity(zf_stack_nic_tx_vi(&st->nic[0])) == 0 || ef_vi_receive_capacity(&st->nic[0].vi) == 0 ) {
    zf_log_stack_err(st, "Failed to allocate TCP zocket in a stack with TX or RX path disabled.\n");
    return -EINVAL; 
  }

  struct zf_tcp* tcp;

  int rc = zf_tcp_new(st, &tcp);
  if( rc == 0 ) {
    zf_tcp_acquire(tcp);
    zf_muxer_mark_waitable_ready(&tcp->w, EPOLLOUT | EPOLLHUP);
    tcp->laddr.sin_family = AF_INET;
    tcp->raddr.sin_family = AF_INET;
    *ts_out = (struct zft_handle*)&tcp->ts;
  }

  return rc;
}


static int __zft_handle_free(zf_stack* stack, zf_tcp* tcp)
{
  struct zf_rx_res* rx_res;

  zf_assert_nflags(tcp->tcp_state_flags, ZF_TCP_STATE_FLAGS_INITIALISED);

  zf_stack_tcp_to_res(stack, tcp, &rx_res);
  zfrr_release_port(stack, rx_res);
  memset(&tcp->laddr, 0, sizeof(tcp->laddr));

  if( tcp->eof_pkt != PKT_INVALID ) {
    zf_pool_free_pkt(&stack->pool, tcp->eof_pkt);
    tcp->eof_pkt = PKT_INVALID;
  }

  /* Release our reference to the zf_tcp. This should only be called before
   * successful connect, so we can assert that we only have one reference
   * here.
   */
  zf_assert_equal(tcp->refcount, 1);
  zf_tcp_release(stack, tcp);

  return 0;
}


/* This function initialises the IP header in a TCP segment */
void zft_init_tx_ip_hdr(struct iphdr* ip, uint32_t laddr_be,
                        uint32_t raddr_be)
{
  ip->version = IPVERSION;
  ip->ihl = 5;
  /* tot_len field populated by tcp layer */
  ip->ttl = 128;
  ip->protocol = IPPROTO_TCP;
  ip->saddr = laddr_be;
  ip->daddr = raddr_be;
  ip->frag_off = htons(IP_DF);
  /* With IP_DF set, we are entitled not to set the ID field (RFC6864), and so
   * we don't.
   */
}


extern int zft_addr_bind(struct zft_handle* handle,
                         const struct sockaddr* laddr_sa,
                         socklen_t laddrlen,
                         int flags)
{
  struct zft* ts = (struct zft*)handle;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_stack* st = zf_stack_from_zocket(tcp);
  struct zf_rx_res* rx_res;

#ifndef NDEBUG
  if( flags != 0 )
    return -EINVAL;
#endif

  ZF_CHECK_SOCKADDR_IN(laddr_sa, laddrlen);

  tcp->laddr = *(struct sockaddr_in*)laddr_sa;

  zf_stack_tcp_to_res(st, tcp, &rx_res);
  int rc = zfrr_reserve_port(st, rx_res, IPPROTO_TCP, &tcp->laddr, NULL);

  if( rc == 0 ) {
    /* tcp layer is responsible for populating tcp header field when sending
     * data, but we use it to remember what we're bound to
     */

    zf_tx_tcphdr(&tcp->tst)->source = tcp->laddr.sin_port;
    zf_tx_iphdr(&tcp->tst)->saddr = tcp->laddr.sin_addr.s_addr;
  }

  return rc;
}

void
zft_handle_getname(struct zft_handle* handle, struct sockaddr* laddr_out,
                   socklen_t* laddrlen)
{
  struct zft* ts = (struct zft*)handle;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);

  memcpy(laddr_out, &tcp->laddr, MIN(sizeof(tcp->laddr), *laddrlen));
  *laddrlen = sizeof(tcp->laddr);
}


int zft_connect(struct zft_handle* handle, const struct sockaddr* raddr_sa,
                socklen_t raddrlen, struct zft** ts_out)
{
  struct zft* ts = (struct zft*)handle;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_stack* st = zf_stack_from_zocket(tcp);
  struct zf_rx_res* tcp_res;

  ZF_CHECK_SOCKADDR_IN(raddr_sa, raddrlen);

  tcp->raddr = *(struct sockaddr_in*)raddr_sa;

  zf_init_tx_state(st, &tcp->tst);

  zf_path_init(&tcp->tst.path, tcp->raddr.sin_addr.s_addr,
               tcp->laddr.sin_addr.s_addr);
  zf_cplane_get_path(st, &tcp->tst.path, true/*wait*/);
  if( tcp->tst.path.rc != ZF_PATH_OK )
    return -EHOSTUNREACH;

  zf_init_tx_ethhdr(st, &tcp->tst);

  if( tcp->laddr.sin_addr.s_addr == INADDR_ANY )
    tcp->laddr.sin_addr.s_addr = tcp->tst.path.src;

  /* Filter install is done before passing the request to the tcp layer */
  zf_stack_tcp_to_res(st, tcp, &tcp_res);
  int rc = zfrr_add(st, tcp_res, TCP_ID(st, tcp), ZFRR_ALL_NICS, IPPROTO_TCP,
                    zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_TCP),
                    st->rx_table[ZF_STACK_RX_TABLE_TCP],
                    &tcp->laddr, &tcp->raddr, 1);
  if( rc < 0 )
    return rc;

  zft_init_tx_ip_hdr(zf_tx_iphdr(&tcp->tst), tcp->laddr.sin_addr.s_addr,
                     tcp->raddr.sin_addr.s_addr);
  tcp_populate_header_common(zf_tx_tcphdr(&tcp->tst),
                             ntohs(tcp->laddr.sin_port),
                             ntohs(tcp->raddr.sin_port));

  zf_path_pin_zock(st, &tcp->tst);

  zf_tcp_acquire(tcp);
  rc = tcp_bind(tcp, &tcp->laddr);
  if( rc < 0 )
    goto fail;
  rc = tcp_connect(tcp, &tcp->raddr);
  if( rc < 0 )
    goto fail;
  if( st->flags & ZF_STACK_FLAG_TCP_NO_DELACK )
    tcp->pcb.flags_ack_delay |= TF_ON;

  tcp->tcp_state_flags |= ZF_TCP_STATE_FLAGS_INITIALISED;

  *ts_out = ts;
  return 0;

 fail:
  zfrr_remove(st, zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_TCP),
              0 /* unused nic */, &tcp->laddr, &tcp->raddr);
  /* Set refcount manually, rather than call zf_tcp_release(), as that
   * would also free the zf_tcp and we just want to put it back how it
   * was */
  zf_assert_equal(tcp->refcount, 1);
  tcp->refcount = 0;
  return rc;
}

int zft_shutdown_tx(struct zft* ts)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  if( tcp->pcb.snd_delegated )
    return -EBUSY;
  return tcp_shutdown_tx(tcp);
}


int zft_free(struct zft* ts)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_stack* st = zf_stack_from_zocket(tcp);

  if( (tcp->tcp_state_flags & ZF_TCP_STATE_FLAGS_INITIALISED) == 0 )
    return __zft_handle_free(st, tcp);

  tcp_shutdown(tcp);
  zf_muxer_del(&tcp->w);
  zf_tcp_release(st, tcp);
  return 0;
}


int zft_handle_free(struct zft_handle* handle)
{
  struct zft* ts = (struct zft*) handle;
  return zft_free(ts);
}


int zft_state(struct zft* ts)
{
  return ffs(ZF_CONTAINER(struct zf_tcp, ts, ts)->pcb.state) - 1;
}


int zft_error(struct zft* ts)
{
  return ZF_CONTAINER(struct zf_tcp, ts, ts)->pcb.error;
}


void
zft_getname(struct zft* ts, struct sockaddr* laddr_out, socklen_t* laddrlen,
            struct sockaddr* raddr_out, socklen_t* raddrlen)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);

  if( laddr_out != NULL ) {
    memcpy(laddr_out, &tcp->laddr, MIN(sizeof(tcp->laddr), *laddrlen));
    *laddrlen = sizeof(tcp->laddr);
  }
  if( raddr_out != NULL ) {
    memcpy(raddr_out, &tcp->raddr, MIN(sizeof(tcp->raddr), *raddrlen));
    *raddrlen = sizeof(tcp->raddr);
  }
}

static void
zf_pftf_tcp_recv_wait(zf_stack* st, zf_tcp* tcp, zft_msg* restrict msg, int flags)
{
  int len = zf_pftf_wait(st, msg->iov[0].iov_len);
  if( len < 0 ) {
    /* Something got in the way (an event arrived before payload), for simplicity:
     *  * let's complete the overlapped pftf event,
     *  * tell the caller that there is nothing for now and make sure
     *  * the next run of reactor reports the event quickly (iff packet is good),
     *    the muxer will report the data in normal non-overlapped way
     */
    st->pftf.event_occurred_carry |= zf_stack_tcp_finish_pftf(st, tcp);
    msg->iovcnt = 0;
    return;
  }
  msg->iovcnt = 1;
  msg->iov[0].iov_len = len;
  msg->iov[0].iov_base = st->pftf.payload;
}


void zft_zc_recv(struct zft *ts, struct zft_msg* restrict msg, 
                        int flags)
{
  zf_stack* stack = zf_stack_from_zocket(ts);
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);

  zf_assert_nflags(flags, ~(ZF_OVERLAPPED_WAIT | ZF_OVERLAPPED_COMPLETE));
  zf_assert_impl(flags, ZF_IS_POW2(flags)); /* one flag only */

  if( flags & (ZF_OVERLAPPED_WAIT | ZF_OVERLAPPED_COMPLETE)) {
    zf_assert_equal(&tcp->w, stack->pftf.w);
    zf_assert_equal(zfr_queue_packets_unread_n(&tcp->tsr), 1);
    zf_assert_ge(msg->iovcnt, 1);
    zf_assert_equal(tcp->tsr.release_n, 0);
    if( flags & ZF_OVERLAPPED_WAIT ) {
      zf_pftf_tcp_recv_wait(stack, tcp, msg, flags);
      return;
    }
    else {
      zf_stack_tcp_finish_pftf(stack, tcp);
      /* fall through to normal recv */
    }
  }

  /* TODO: prefetch pkt payload */
  zft_zc_read(tcp, msg);
}


static inline int __zft_recv_done(zf_tcp* tcp, unsigned int bytes,
                                  unsigned int count, bool isEOF)
{
  zf_stack* stack = zf_stack_from_zocket(tcp);
  int rc = 1;

  tcp_recved(tcp, bytes);

  if( count )
    zfr_zc_read_done(&stack->pool, &tcp->tsr, count, ZFR_ZC_KEEP_UNPROCESSED);

  if( ZF_UNLIKELY( isEOF ) ) {
    rc = tcp->pcb.state == CLOSED ? -tcp->pcb.error : 0;
  }

  /* All packets returned to caller, so not ready for reading */
  if( zfr_queue_all_packets_read(&tcp->tsr) )
    zf_muxer_mark_waitable_not_ready(&tcp->w, EPOLLIN);

  if( ZF_UNLIKELY(tcp->tcp_state_flags & (ZF_TCP_STATE_FLAGS_DEFER_EOF |
                                          ZF_TCP_STATE_FLAGS_DEFER_OOO)) ) {
    if( tcp->tcp_state_flags & ZF_TCP_STATE_FLAGS_DEFER_OOO &&
        zfr_queue_all_packets_processed(&tcp->tsr) ) {
      tcp->tcp_state_flags &= ~ZF_TCP_STATE_FLAGS_DEFER_OOO;
      tcp_handle_ooo_pkts(stack, tcp);
    }

    if( tcp->tcp_state_flags & ZF_TCP_STATE_FLAGS_DEFER_EOF ) {
      struct tcp_pcb* pcb = &tcp->pcb;
      /* We should only enqueue EOF marker if there is no OOO data */
      if( tcp->pcb.state == CLOSED || (pcb->ooo_added == pcb->ooo_removed) )
        tcp_queue_append_EOF_marker(stack, tcp);
    }
  }

  return rc;
}


/**
 * \brief Concludes pending zc_recv operation as done.
 **/
ZF_HOT static inline int
__zft_zc_recv_done_handling_EOF(zf_tcp* tcp, struct zft_msg* msg,
                                size_t tot_len, unsigned iovcnt)
{
  bool isEOF = iovcnt && msg->iov[iovcnt - 1].iov_len == 0;
  int count = iovcnt - isEOF;
  return __zft_recv_done(tcp, tot_len, count, isEOF);
}


/**
 * \brief Concludes part of a segment as read. Subsequent client's zft_zc_read
 * operation will provide iovec covering unread part of this segment only.
 *
 * Note: marking the whole segment as read would lead to inconsistent state.
 **/
ZF_HOT static inline void
__zft_zc_recv_done_tail(zf_tcp* tcp, size_t tail_len)
{
  /* TODO move to a routine at appropriate layer */
  struct zf_rx_ring* ring = &tcp->tsr.ring;
  struct iovec* data;
  unsigned available_iovs = zfr_ring_peek_unread(ring, &data);
  zf_assert_ge(available_iovs, 1);
  data->iov_base = (void*)(((char*)data->iov_base) + tail_len);
  data->iov_len -= tail_len;
  zf_assert_gt(data->iov_len, 0);
}


/**
 * \brief Concludes pending zc_recv operation as done and the whole data
 * indicated by msg to have been read.
 *
 * Must be called after each successful zft_zc_recv operation.
 * This releases resources and enables subseqent call to zft_zc_recv()
 * or zft_recv().
 **/
int zft_zc_recv_done(struct zft* ts, struct zft_msg* msg)
{
  /* The caller is not allowed to have modified the number of packets. */
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  unsigned iovcnt = msg->iovcnt;
  zf_assert_equal(iovcnt, tcp->tsr.release_n);

  unsigned len = 0;
  for( unsigned i = 0; i < iovcnt; i++ )
    len += msg->iov[i].iov_len;

  int rc = __zft_zc_recv_done_handling_EOF(tcp, msg, len, iovcnt);
  tcp->tsr.release_n = 0;
  return rc;
}


/**
 * \brief Concludes pending zc_recv operation as done acknowledging only some
 * data as having been read.
 *
 * Can be called after each successfull zft_zc_recv() operation
 * as an alternative to zft_zc_recv_done().
 * This releasese resources and enables subseqent call to zft_zc_recv()
 * or zft_recv().
 **/
int zft_zc_recv_done_some(struct zft* ts, struct zft_msg* msg, size_t len)
{
  /* The caller is not allowed to have modified the number of packets. */
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  zf_assert_equal((uint32_t) msg->iovcnt, tcp->tsr.release_n);

  unsigned iovcnt = 0;
  size_t tail_len = len;

  /* Calculate number of fully consumed iovecs and the remainder of the last one */
  for( ; iovcnt < (unsigned) msg->iovcnt &&
         tail_len >= msg->iov[iovcnt].iov_len; ++iovcnt ) {
    tail_len -= msg->iov[iovcnt].iov_len;
  }
  zf_assert_impl((unsigned) msg->iovcnt == iovcnt, tail_len == 0);

  int rc = __zft_zc_recv_done_handling_EOF(tcp, msg, len, iovcnt);
  if(ZF_LIKELY( rc >= 0 && tail_len > 0 )) {
    __zft_zc_recv_done_tail(tcp, tail_len);
  }
  tcp->tsr.release_n = 0;
  return rc;
}



/** \brief Non-zero copy receive */
int zft_recv(struct zft* ts, const struct iovec* iov, int iovcnt,
             int flags)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_rx_ring* ring = &tcp->tsr.ring;
  struct iovec* data;
  struct iovec dest = *iov;
  struct iovec* p_dest = &dest;
  size_t dest_cnt;
  unsigned available_iovs = 0;
  unsigned consumed_iovs = 0;
  unsigned total_bytes = 0;
  int rc = -EAGAIN;
  bool isEOF = false;

  zf_log_tcp_rx_trace(tcp, "%s: %d iovecs, %d/%d\n", __FUNCTION__,
                      iovcnt, ring->begin_read, ring->end);

  while( (iovcnt > 0) &&
         ((available_iovs = zfr_ring_peek_unread(ring, &data)) > 0) &&
         ! isEOF ) {

    /* We've found at least one buffer.  Clear the error condition. */
    if( rc == -EAGAIN )
      rc = 0;

    while( (iovcnt > 0) &&
           (available_iovs > 0) ) {

      zf_log_tcp_rx_trace(tcp, "iovcnt %d, dest.iov_len %d, available %d\n",
                          iovcnt, dest.iov_len, available_iovs);

      /* If we find an empty buffer in the recvq, we've hit EOF. */
      if( data->iov_len == 0 ) {
        zf_log_tcp_rx_trace(tcp, "%s: EOF\n", __FUNCTION__);
        /* This must be the last buffer.  We should not consume it as it must
         * be left in the recvq for subsequent reads. */
        zf_assert_equal(available_iovs, 1);
        isEOF = true;
        break;
      }

      p_dest = &dest;
      dest_cnt = 1;
      unsigned copied = zf_memcpy_flat2iov(&p_dest, &dest_cnt, 
                                           data->iov_base, data->iov_len, 1);
      total_bytes += copied;

      data->iov_base = (void*)(((char*)data->iov_base) + copied);
      data->iov_len -= copied;

      if( data->iov_len == 0 ) {
        zf_log_tcp_rx_trace(tcp, "%s: advance ring\n", __FUNCTION__);
        data++;
        consumed_iovs++;
        available_iovs--;
      }

      /* Advance to the next buffer in the destination iovec if we've filled
       * the current one.  We do this even if there's no source data left in
       * order to achieve uniformity that allows us to assert against short
       * reads later on. */
      if( dest_cnt == 0 ) {
        zf_log_tcp_rx_trace(tcp, "%s: advance dest\n", __FUNCTION__);
        iov++;
        iovcnt--;
        dest = *iov;
      }
    }

    rc += total_bytes;

    int rc1 = __zft_recv_done(tcp, total_bytes, consumed_iovs, isEOF);
    if( rc1 < 0 ) {
      /* Don't mask any bytes we have to return */
      if( rc == 0 )
        rc = rc1;
      break;
    }

    total_bytes = 0;
    consumed_iovs = 0;
  }

  /* Short reads are guaranteed against by the API.  Assert this. */
  if( rc > 0 && iovcnt > 0 && ! isEOF )
    zf_assume_equal(available_iovs, 0);

  return rc;
}


ssize_t zft_send_single(struct zft* restrict ts, const void* buf,
                        size_t buflen, int flags)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_waitable* w = &tcp->w;
  ssize_t rc;

  /* Only MSG_MORE flag supported */
  zf_assert_equal(flags & ~MSG_MORE, 0);

  iovec iov {(void*)buf, buflen};

  /* Below if-clause to get generated two separate inlined tcp_write() clones
   * One optimized for non-vlan tagged packets, the other one for vlan-tagged */
  if(ZF_LIKELY( ! zf_tx_do_vlan(&tcp->tst) )) {
    rc = tcp_write(tcp, &iov, flags);
  }
  else {
    rc = tcp_write(tcp, &iov, flags);
  }
  if( ! tcp_tx_advertise_space(tcp) ) {
    zf_log_tcp_tx_trace(tcp, "%s: clearing EPOLLOUT\n", __FUNCTION__);
    zf_muxer_mark_waitable_not_ready(w, EPOLLOUT);
  }
  else {
#ifndef NDEBUG
    /* We use FAST_SEND_STATE_MASK here as SYN-SENT and SYN-RECV are
     * not marked EPOLLOUT to make muxer compatible with epoll
     * behaviour.
     */
    if( tcp->pcb.state & FAST_SEND_STATE_MASK )
      zf_assert(w->readiness_mask & EPOLLOUT);
#endif
  }
  return rc;
}


ssize_t zft_send_single_warm(struct zft* restrict ts, const void* buf,
                            size_t buflen)
{
  ssize_t rc;
  zf_tx_warm_state tx_warm_state;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* st = zf_stack_from_zocket(&tcp->tst);
  struct zf_stack_nic* st_nic = &st->nic[tcp->tst.path.nicno];
  bool do_fast;
  size_t total_len = buflen + zft_get_header_size(ts);

  /* Warming is only valid on the PIO or CTPIO send path.
   * Return EMSGSIZE if data too long for transmit method
   * or EAGAIN if PIO buffer temporarily in use. */
  if( ! ctpio_is_allowed(st_nic, total_len) ) {
    /* CTPIO not enabled, temporarily disabled, or message too long
     * for CTPIO.  Check PIO. */
    if( ZF_UNLIKELY( total_len > max_pio_len(st_nic) ) )
      return -EMSGSIZE;
    if( ZF_UNLIKELY( ! pio_is_available(st_nic) ) )
      return -EAGAIN;
  }

  /* Mirror check in tcp_write to be sure we will go down fast path.
   * This also implies that socket is in suitable state to send. */
  do_fast = can_do_tcp_fast_send(pcb, buflen);
  if( ! do_fast )
    return -EAGAIN;

#ifndef NDEBUG
  /* In debug tcp_send_assert_validity will reset fast_send_len to 0 */
  int saved_fast_send_len = pcb->fast_send_len;
#endif

  /* Perform warm send. */
  rc = enable_tx_warm(&tcp->tst, &tx_warm_state);
  if( rc < 0 ) {
    zf_assert_equal(rc, -ENOBUFS);
    /* Make out of memory return code match zft_send_single() */
    return -ENOMEM;
  }
  rc = zft_send_single(ts, buf, buflen, 0);
  disable_tx_warm(&tcp->tst, &tx_warm_state);

#ifndef NDEBUG
  /* Restore fast_send_len if debug enabled */
  zf_assert_equal(pcb->fast_send_len, 0);
  pcb->fast_send_len = saved_fast_send_len;
#endif

  /* When stack warm flag is set tcp_fast_send_tail actions are
   * avoided so no state undo required for the non-debug case. */
  return rc;
}


ssize_t zft_send(struct zft* restrict ts, const struct iovec* restrict iov,
                 int iov_cnt, int flags)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  zf_stack* stack = zf_stack_from_zocket(tcp);
  struct zf_waitable* w = &tcp->w;
  ssize_t rc;

  /* Only MSG_MORE flag supported */
  zf_assert_equal(flags & ~MSG_MORE, 0);

  if( iov_cnt == 1 )
    rc = tcp_write(tcp, iov, flags);
  else
    rc = tcp_write_slow(stack, tcp, iov, iov_cnt, flags);

  if( ! tcp_tx_advertise_space(tcp) ) {
    zf_log_tcp_tx_trace(tcp, "%s: clearing EPOLLOUT\n", __FUNCTION__);
    zf_muxer_mark_waitable_not_ready(w, EPOLLOUT);
  }
  else {
#ifndef NDEBUG
    /* We use FAST_SEND_STATE_MASK here as SYN-SENT and SYN-RECV are
     * not marked EPOLLOUT to make muxer compatible with epoll
     * behaviour.
     */
    if( tcp->pcb.state & FAST_SEND_STATE_MASK )
      zf_assert(w->readiness_mask & EPOLLOUT);
#endif
  }
  return rc;
}


int zft_send_space(struct zft* restrict ts, size_t* restrict space)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  /* connection is in invalid state for data transmission? */
  if( !(tcp->pcb.state & FAST_SEND_STATE_MASK) )
    return -ENOTCONN;

  /* snd_buf is a little odd, as although it reports bytes, it is in
   * quanta of MSS, so we need to take account of any space in the
   * last packet of the send queue - see tcp_write_checks_fast()
   */
  *space = tcp->pcb.snd_buf;
  if( tcp_has_unsent(&tcp->pcb.sendq) )
    *space += (tcp_mss_max_seg(&tcp->pcb) - tcp_seg_last(&tcp->pcb.sendq)->len);

  return 0;
}


unsigned zft_get_header_size(struct zft *ts)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  const bool has_vlan = zf_tx_do_vlan(&tcp->tst);
  return ETH_IP_HLEN + (VLAN_HLEN * has_vlan) + TCP_HLEN;
}

int zft_pkt_get_timestamp(struct zft* ts, const struct zft_msg* restrict msg,
                          struct timespec* ts_out, int pktind, unsigned* flags)
{
  return zfr_pkt_get_timestamp(ts, msg, ts_out, pktind, flags);
}

int zft_get_tx_timestamps(struct zft* ts,
                          struct zf_pkt_report* reports_out,
                          int* count_in_out)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  bool more;
  zf_tx_reports::get(&stack->tx_reports, TCP_ID(stack, tcp), true,
                     reports_out, count_in_out, &more);
  if( ! more )
    zf_muxer_mark_waitable_not_ready(&tcp->w, EPOLLERR);
  return 0;
}

struct zf_waitable* zft_to_waitable(struct zft* ts)
{
  struct zf_tcp *tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  return &tcp->w;
}


int
zft_get_mss(struct zft *ts)
{
  struct zf_tcp *tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);

  if( !(tcp->pcb.state & FAST_SEND_STATE_MASK) )
    return -ENOTCONN;

  return tcp->pcb.mss;
}


static int
zftl_alloc_listenq_backing_buffer(zf_allocator* a, uint16_t len,
                                  struct zf_tcp_listenq_entry** lq_entries_out)
{
  zf_assert_gt(len, 0);

  struct zf_tcp_listenq_entry* lq_entries = (struct zf_tcp_listenq_entry*)
    zf_allocator_alloc(a, len * sizeof(struct zf_tcp_listenq_entry));
  if( lq_entries == NULL )
    return -ENOMEM;

  for( uint16_t i = 0; i < len; ++i )
    lq_entries[i].listener_id = ZF_ZOCKET_ID_INVALID;

  *lq_entries_out = lq_entries;

  return 0;
}


int zftl_listenq_alloc_size(uint16_t max_syn_backlog)
{
  return max_syn_backlog * sizeof(zf_tcp_listenq_entry);
}

int zftl_listenq_init(zf_allocator* a, struct zf_tcp_listenq* listenq,
                      uint16_t max_syn_backlog)
{
  if( max_syn_backlog <= 0 )
    return -EINVAL;
  listenq->max_syn_backlog = max_syn_backlog;
  listenq->lazy_alloc_index = 0;
  listenq->free_list_head = ZF_LISTENQ_INDEX_INVALID;
  return zftl_alloc_listenq_backing_buffer(a, max_syn_backlog, &listenq->table);
}


void zftl_listenq_fini(zf_allocator* a, struct zf_tcp_listenq* listenq)
{
  if( listenq->table != NULL )
    zf_allocator_free(a, listenq->table);
}


int zftl_listen(struct zf_stack* st, const struct sockaddr* laddr_sa,
                socklen_t laddrlen, const struct zf_attr* attr,
                struct zftl** tl_out)
{
  ZF_CHECK_SOCKADDR_IN(laddr_sa, laddrlen);

  struct sockaddr_in* laddr = (struct sockaddr_in*)laddr_sa;

  if( laddr->sin_addr.s_addr == INADDR_ANY )
    return -EOPNOTSUPP;

  /* Allocate. */
  struct zf_tcp_listen_state* tls;
  int rc = zf_stack_alloc_tcp_listen_state(st, &tls);
  if( rc != 0 )
    return rc;
  zf_log_tcp_conn_trace(tls, "%s:\n", __func__);

  tls->laddr = *laddr;

  zf_init_tx_state(st, &tls->tst);
  /* We don't populate the TX headers here, as these vary according to the
   * destination to which we must send replies.  As such, we do it in
   * tcp_listen_input(). */

  /* Init RX state. */

  struct zf_rx_res* rx_res;
  zf_stack_tcp_listen_state_to_res(st, tls, &rx_res);

  zfrr_init(rx_res);
  rc = zfrr_add(st, rx_res, TCP_LISTEN_ID(st, tls), ZFRR_ALL_NICS, IPPROTO_TCP,
                zf_stack_get_rx_table(st, ZF_STACK_RX_TABLE_TCP_LISTEN),
                st->rx_table[ZF_STACK_RX_TABLE_TCP_LISTEN],
                &tls->laddr, NULL, 1);
  if( rc != 0 )
    goto fail;

  zf_waitable_init(&tls->w);
  tls->acceptq_head = ZF_ZOCKET_ID_INVALID;
  /* The API caller holds a reference. */
  tls->refcount = 1;
  tls->tls_flags = 0;

  *tl_out = &tls->tl;

  return 0;

 fail:
  zf_stack_free_tcp_listen_state(st, tls);
  return rc;
}


int zftl_accept(struct zftl* tl, struct zft** ts_out)
{
  struct zf_tcp_listen_state* tls = ZF_CONTAINER(struct zf_tcp_listen_state,
                                                 tl, tl);

  if( tls->acceptq_head == ZF_ZOCKET_ID_INVALID )
    return -EAGAIN;

  /* Retrieve the TCP state at the front of the queue. */
  struct zf_stack* stack = zf_stack_from_zocket(tl);
  struct zf_tcp* tcp = &stack->tcp[tls->acceptq_head];

  /* Remove it from the queue. */
  tls->acceptq_head = tcp->pcb.acceptq_next;
  if( tls->acceptq_head == ZF_ZOCKET_ID_INVALID )
    zf_muxer_mark_waitable_not_ready(&tls->w, EPOLLIN);
  /* The acceptq's reference is now owned by the application */

  *ts_out = &tcp->ts;
  return 0;
}


struct zf_waitable* zftl_to_waitable(struct zftl* tl)
{
  struct zf_tcp_listen_state* tls = ZF_CONTAINER(struct zf_tcp_listen_state,
                                                 tl, tl);
  return &tls->w;
}


/* This frees the listener even if there are outstanding references.  See also
 * zftl_free() and zftl_release(). */
static void __zftl_free(struct zf_stack* stack,
                        struct zf_tcp_listen_state* tls)
{
  /* The last reference has gone, meaning that no-one is using the filter any
   * more.  This also frees the backing socket. */
  int rc;
  rc = zfrr_remove(stack,
                   zf_stack_get_rx_table(stack, ZF_STACK_RX_TABLE_TCP_LISTEN),
                   0 /* nic */, &tls->laddr, NULL);
  zf_assert_ge(rc, 0);
  zf_stack_free_tcp_listen_state(stack, tls);
}


void zftl_release(struct zf_stack* stack, struct zf_tcp_listen_state* tls)
{
  zf_log_tcp_conn_trace(tls, "%s: refcount=%d\n", __func__, tls->refcount);
  zf_assert_gt(tls->refcount, 0);
  if( --tls->refcount == 0 )
    __zftl_free(stack, tls);
}


/* This is a public API function.  After calling this, the caller is no longer
 * entitled to use [tl], although we don't guarantee that we actually free it
 * immediately. */
int zftl_free(struct zftl* tl)
{
  struct zf_tcp_listen_state* tls = ZF_CONTAINER(struct zf_tcp_listen_state,
                                                 tl, tl);
  struct zf_stack* stack = zf_stack_from_zocket(tl);
  int rc = tcp_shutdown_listen(stack, tls);
  zf_assume(rc == 0 || rc == -ENOTCONN);
  zf_muxer_del(&tls->w);
  zftl_release(stack, tls);
  return 0;
}

void
zftl_getname(struct zftl* tl, struct sockaddr* laddr_out, socklen_t *laddrlen)
{
  struct zf_tcp_listen_state* tls = ZF_CONTAINER(struct zf_tcp_listen_state,
                                                 tl, tl);
  memcpy(laddr_out, &tls->laddr, MIN(sizeof(tls->laddr), *laddrlen));
  *laddrlen = sizeof(tls->laddr);
}
