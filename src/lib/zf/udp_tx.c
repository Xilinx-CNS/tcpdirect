/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** UDP TX slow path and resource management */

#include <zf/zf.h>
#include <zf_internal/muxer.h>
#include <zf_internal/tx.h>
#include <zf_internal/tx_send.h>
#include <zf_internal/tx_warm.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/tx_res.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_state.h>
#include <zf_internal/cplane.h>
#include <zf_internal/private/reactor.h>
#include <zf_internal/checksum.h>
#include <etherfabric/checksum.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int zfut_alloc(struct zfut** us_out,
               struct zf_stack* st,
               const struct sockaddr* laddr_sa,
               socklen_t laddrlen,
               const struct sockaddr* raddr_sa,
               socklen_t raddrlen,
               int flags,
               const struct zf_attr* attr)
{

  /* Check first VI of stack. If it has no TX capability then fail */
  if ( ef_vi_transmit_capacity(zf_stack_nic_tx_vi(&st->nic[0])) == 0 ) {
    zf_log_stack_err(st, "Failed to allocate TX UDP zocket in a stack with no TX capability\n");
    return -EINVAL; 
  }

  struct zf_udp_tx* udp_tx;
  struct zf_tx* tx;

  ZF_CHECK_SOCKADDR_IN(laddr_sa, laddrlen);
  ZF_CHECK_SOCKADDR_IN(raddr_sa, raddrlen);

  const struct sockaddr_in *laddr = (const struct sockaddr_in*)laddr_sa;
  const struct sockaddr_in *raddr = (const struct sockaddr_in*)raddr_sa;

  if( (raddr->sin_addr.s_addr == INADDR_ANY) || (raddr->sin_port == 0) )
    return -EINVAL;

  /* It is up to the caller to choose a valid local port number. If
   * the caller wants us to choose a port for them then they should
   * use the zfur_* functions. */
  if( laddr->sin_port == 0 )
    return -EINVAL;

  int rc = zf_stack_alloc_udp_tx(st, &udp_tx);
  if( rc < 0 )
    return rc;

  tx = &udp_tx->tx;
  zf_init_tx_state(st, tx);

  zf_path_init(&tx->path, raddr->sin_addr.s_addr, laddr->sin_addr.s_addr);
  zf_cplane_get_path(st, &tx->path, true/*wait*/);
  if( tx->path.rc != ZF_PATH_OK ) {
    zf_stack_free_udp_tx(st, udp_tx);
    return -EHOSTUNREACH;
  }

  zf_init_tx_ethhdr(st, tx);

  iphdr* ip = zf_tx_iphdr(tx);
  if( laddr->sin_addr.s_addr == INADDR_ANY )
    ip->saddr = tx->path.src;
  else
    ip->saddr = laddr->sin_addr.s_addr;

  ip->daddr = raddr->sin_addr.s_addr;
  ip->protocol = IPPROTO_UDP;
  ip->version = IPVERSION;
  ip->ihl = 5;
  ip->ttl = 64;

  udphdr* udp = zf_tx_udphdr(tx);
  udp->source = laddr->sin_port;
  udp->dest = raddr->sin_port;

  zf_path_pin_zock(st, tx);

  /* We are always ready to send. */
  zf_waitable_init(zfut_to_waitable(&udp_tx->handle));
  zf_muxer_mark_waitable_ready(&udp_tx->w, EPOLLOUT);
  /* Or not always? */
  udp_tx->pollout_req.next = NULL;

  *us_out = &udp_tx->handle;
  return 0;
}


int zfut_free(struct zfut* us)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_stack* st = zf_stack_from_zocket(us);

  zf_muxer_del(&udp_tx->w);

  /* There is no state to clean up, so we can go ahead and free the buffer. */
  zf_stack_free_udp_tx(st, udp_tx);
  return 0;
}


void zfut_dump(SkewPointer<zf_stack> stack, SkewPointer<zf_udp_tx> udp_tx)
{
  iphdr* ip = zf_tx_iphdr(&udp_tx->tx);
  udphdr* udp = zf_tx_udphdr(&udp_tx->tx);
  ZF_INET_NTOP_DECLARE_BUF(lbuf);
  ZF_INET_NTOP_DECLARE_BUF(rbuf);

  zf_dump("UDP TX %." ZF_STRINGIFY(ZF_STACK_NAME_SIZE)
          "s:%u lcl=%s:%d rmt=%s:%u\n",
          stack->st_name, UDP_TX_ID(stack, udp_tx),
          ZF_INET_NTOP_CALL(ip->saddr, lbuf), ntohs(udp->source),
          ZF_INET_NTOP_CALL(ip->daddr, rbuf), ntohs(udp->dest));
  zf_waitable_dump(udp_tx.propagate_skew(&udp_tx->w));
  zf_tx_dump(&udp_tx->tx, IPPROTO_UDP);
}


static inline unsigned
zfut_mss(struct zf_tx* tx)
{
  /* IP fragment offset is calculated in byte octets.  This value is used
   * for both (a) limiting the single non-fragmented UDP datagram and (b)
   * for limiting an IP fragment.  This value must be divisible by
   * 8 because of (b).  */
  return (MIN(tx->path.mtu + sizeof(struct ethhdr),
              PKT_BUF_SIZE_USABLE) - UDP_HDR_SIZE) & ~0x7;
}


/* Ask muxer for EPOLLOUT when TX space becomes available */
static void
waitable_remove_epollout(struct zf_udp_tx* udp_tx)
{
  struct zf_stack* st = zf_stack_from_zocket(udp_tx);
  int nic = 0;

  if( udp_tx->w.readiness_mask & EPOLLOUT ) {
    zf_muxer_mark_waitable_not_ready(&udp_tx->w, EPOLLOUT);
    ci_sllist_push(&st->nic[nic].pollout_req_list, &udp_tx->pollout_req);
  }
}


ZF_HOT static void
udp_write_tx_report(struct zf_udp_tx* udp_tx, size_t bytes,
                    zf_tx_req_id* req_id, bool fragment)
{
  zf_stack* stack = zf_stack_from_zocket(udp_tx);

  /* req_id_out should only be set if the packet was really sent */
  zf_assume_impl(req_id, ~stack->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED);
  if( ! req_id || stack->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
    return;

  const unsigned zock_id = UDP_TX_ID(stack, udp_tx);
  zf_assume_equal(zock_id, zock_id &
                         (ZF_REQ_ID_ZOCK_ID_MASK >> ZF_REQ_ID_ZOCK_ID_SHIFT));
  *req_id |= (zock_id << ZF_REQ_ID_ZOCK_ID_SHIFT);

  if( fragment )
    *req_id |= ZF_REQ_ID_UDP_FRAGMENT;
  else if( stack->tx_reports.enabled() )
    zf_tx_reports::prepare(&stack->tx_reports, zock_id, false,
                           udp_tx->packet_count++, bytes, 0);
}


static bool
try_clean_tx_completions(struct zf_udp_tx* udp_tx)
{
  struct zf_stack* st = zf_stack_from_zocket(udp_tx);
  int nicno = udp_tx->tx.path.nicno;
  ef_vi* vi = zf_stack_nic_tx_vi(&st->nic[nicno]);
#ifndef NDEBUG
  int iterations = 0;
#endif

  if( vi->nic_type.arch != EF_VI_ARCH_EFCT )
    return false;
  for( ; ; ) {
    ef_event ev;
    int rc = efct_poll_tx(vi, &ev, 1);
    if( rc > 0 ) {
      st->pftf.event_occurred_carry |= zf_reactor_process_event(st, nicno, vi,
                                                                &ev);
      return true;
    }
#ifndef NDEBUG
    ++iterations;
    zf_assert_lt(iterations, 100000);
#endif
  }
}


ZF_HOT static int
send_single(zf_udp_tx* udp_tx, const void* buf, size_t buflen)
{
  struct zf_tx* tx = &udp_tx->tx;
  zf_assert_le(buflen, zfut_mss(tx));
  /* we pack it all into single cache line, so pio copy is efficient
   * and preventing ef_pio_memcopy to write to the same dword twice */
  zf_tx_udphdr(tx)->len = htons(buflen + sizeof(struct udphdr));
  zf_tx_iphdr(tx)->tot_len = htons(buflen + UDP_HDR_SIZE -
                                   sizeof(struct ethhdr));
  const bool has_vlan = zf_tx_do_vlan(tx);
  int rc;
  zf_tx_req_id* txq_req_id = NULL;
  /* Below if-clause to get generated two separate inlined send_with_hdr() clones
   * One optimized for non-vlan tagged packets, the other one for vlan-tagged */
  if(ZF_LIKELY( ! has_vlan )) {
    rc = send_with_hdr(tx, buf, buflen, (uint8_t*) zf_tx_ethhdr(tx),
                       UDP_HDR_SIZE, tx->udp_hdr_fill_size,
                       ZF_REQ_ID_NORMAL | ZF_REQ_ID_PROTO_UDP, &txq_req_id);
  }
  else {
     rc = send_with_hdr(tx, buf, buflen, (uint8_t*) zf_tx_ethhdr(tx),
                        UDP_HDR_SIZE + VLAN_HLEN,
                        tx->udp_vlanhdr_fill_size,
                        ZF_REQ_ID_NORMAL | ZF_REQ_ID_PROTO_UDP, &txq_req_id);
  }

  if(ZF_LIKELY( rc >= 0 ))
    udp_write_tx_report(udp_tx, rc, txq_req_id, false);
  else if( rc == -EAGAIN )
    waitable_remove_epollout(udp_tx);

  return rc;
}


ZF_HOT int
zfut_send_single(struct zfut *us, const void* buf, size_t buflen)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_tx* tx = &udp_tx->tx;
  zf_tx_iphdr(tx)->frag_off = htons(IP_DF);
  return send_single(udp_tx, buf, buflen);
}


ZF_HOT int
zfut_send_single_warm(struct zfut *us, const void* buf, size_t buflen)
{
  int rc;
  zf_tx_warm_state tx_warm_state;
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_tx* tx = &udp_tx->tx;
  struct zf_stack* st = zf_stack_from_zocket(tx);
  struct zf_stack_nic* st_nic = &st->nic[tx->path.nicno];
  size_t total_len = buflen + zfut_get_header_size(us);

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

  rc = enable_tx_warm(tx, &tx_warm_state);
  if( rc < 0 )
    return rc;
  rc = zfut_send_single(us, buf, buflen);
  disable_tx_warm(tx, &tx_warm_state);
  return rc;
}


int
zfut_get_mss(struct zfut *us)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_tx* tx = &udp_tx->tx;

  return zfut_mss(tx);
}


ZF_HOT int
zfut_send(struct zfut* restrict us,
          const struct iovec* restrict iov, int iov_cnt,
          int flags)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_tx* tx = &udp_tx->tx;
  int rc;
  size_t udp_payload = 0; /* set it just to suppress gcc6 warning */
  size_t mss = zfut_mss(tx);

  const bool has_vlan = zf_tx_do_vlan(tx);

  zf_tx_iphdr(tx)->frag_off = htons(flags & IP_DF);
  if( iov_cnt == 1 && iov[0].iov_len <= mss )
    return send_single(udp_tx, iov[0].iov_base, iov[0].iov_len);
  if( iov_cnt == 0 )
    return send_single(udp_tx, NULL, 0);

  /* Writable copy of iov: iovp */
  struct iovec iov1[iov_cnt];
  memcpy(iov1, iov, sizeof(*iov) * iov_cnt);
  struct iovec* iovp = iov1;
  int iov_cnt_orig = iov_cnt;

  /* iovec we are going to zf_send(): */
  struct iovec iov2[iov_cnt + 1];
  iov2[0].iov_base = zf_tx_ethhdr(tx);
  iov2[0].iov_len = UDP_HDR_SIZE + VLAN_HLEN * has_vlan;
  int fragment_num = 0;

  while( true ) {
    int payload = mss + (fragment_num == 0 ? 0 : sizeof(struct udphdr));
    size_t space = payload;
    int i = 1;

    while( space > 0 && iov_cnt > 0 ) {
      iov2[i] = *iovp;
      if( space < iovp->iov_len ) {
        iov2[i].iov_len = space;
        /* iovp->iov_base += space: */
        iovp->iov_base = (void*)((uintptr_t)iovp->iov_base + space);
        iovp->iov_len -= space;
      }
      else {
        iovp++;
        iov_cnt--;
      }
      space -= iov2[i++].iov_len;
    }

    /* Fix IP and UDP headers */
    payload -= space;
    if( fragment_num == 0 ) {
      /* iov_cnt is 0 if and only if iov2 contains all the user data, i.e.
       * iov_cnt==0 is equal to "non-IP-fragmented UDP packet". */
      if( (flags & IP_DF) && iov_cnt > 0 )
         return -EMSGSIZE;
      /* We should calculate the overall length of the UDP datagram */
      udp_payload = payload;
      for( int j = 0; j < iov_cnt; j++ )
        udp_payload += iovp[j].iov_len;
      if( udp_payload >= (1u << 16) - sizeof(struct iphdr) -
                        sizeof(struct udphdr) )
        return -EMSGSIZE;

      zf_tx_iphdr(tx)->tot_len = htons(payload + IP_HLEN + sizeof(struct udphdr));
      zf_tx_udphdr(tx)->len = htons(udp_payload + sizeof(struct udphdr));

      if( iov_cnt > 0 ) {
        zf_tx_iphdr(tx)->frag_off |= IP_MF;

        /* Fixme: improve IP id.
         * For now, I use "&tx & 0xff00" in hope to get different initial
         * values for ZF applications running one-after-another (socket
         * tester with ZF socket shim does it).
         * Note: do not call htons() because ipid values should be just
         * different; there is no need to keep them in order. */
        static uint16_t ipid = 0x432 ^
                               ((((uintptr_t)&tx) & 0xff000000) >> 16);
        zf_tx_iphdr(tx)->id = ipid++;
        zf_tx_udphdr(tx)->check = ef_udp_checksum(zf_tx_iphdr(tx),
                                                  zf_tx_udphdr(tx),
                                                  iov, iov_cnt_orig);
      }
    }
    else {
      if( iov_cnt == 0 )
        zf_tx_iphdr(tx)->frag_off &=~ IP_MF;
      zf_tx_iphdr(tx)->tot_len = htons(payload  + sizeof(struct iphdr));
    }

    zf_tx_iphdr(tx)->frag_off = htons(zf_tx_iphdr(tx)->frag_off);

    /* Note that tx_send.h can only cope with arbitrary iovec counts
     * like this if ZF_REQ_ID_NO_PIO is set. */
    zf_tx_req_id* txq_req_id = NULL;
  again:
    rc = zf_send(tx, iov2, i, payload  + iov2[0].iov_len,
                 ZF_REQ_ID_NO_PIO | ZF_REQ_ID_PROTO_UDP, &txq_req_id);

    if( ZF_UNLIKELY( rc != 0 ) ) {
      if( rc == -EAGAIN ) {
        /* X3 doesn't have enough txq FIFO space to be able to send an entire
         * 64KB packet (fragmented) without polling the card in the middle, so
         * we block in this function waiting for space. See ON-13861 for more
         * design discussion.
         *
         * "8" is a heuristic. Callers will generally expect this function to
         * be relatively quick, but if they're asking us to send a large
         * number of fragments then that expectation won't hold any longer. We
         * don't want them getting in to an infinite retry loop by giving up
         * too soon, but equally we don't want to block on requests that would
         * typically be expected to be quick */
        if( ZF_UNLIKELY(fragment_num >= 8) &&
            try_clean_tx_completions(udp_tx) )
          goto again;
        waitable_remove_epollout(udp_tx);
      }
      zf_log_udp_tx_trace(zf_stack_from_zocket(tx),
                          "%s: zf_send() failed: rc=%d\n", __func__, rc);
      return rc;
    }
    if( ZF_UNLIKELY( iov_cnt == 0 ) ) {
      udp_write_tx_report(udp_tx, udp_payload, txq_req_id, false);
      return udp_payload;
    }

    zf_tx_iphdr(tx)->frag_off = ntohs(zf_tx_iphdr(tx)->frag_off);
    udp_write_tx_report(udp_tx, payload, txq_req_id, true);

    if( fragment_num == 0 && iov_cnt > 0 ) {
      iov2[0].iov_len -= sizeof(struct udphdr);
      zf_tx_iphdr(tx)->frag_off += (payload + sizeof(struct udphdr)) >> 3;
    }
    else {
      zf_tx_iphdr(tx)->frag_off += payload >> 3;
    }
    ++fragment_num;
  }

  /* Unreachable */
  return 0;
}

int zfut_get_tx_timestamps(struct zfut* us,
                           struct zf_pkt_report* reports_out,
                           int* count_in_out)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_stack* stack = zf_stack_from_zocket(udp_tx);
  bool more;
  zf_tx_reports::get(&stack->tx_reports, UDP_TX_ID(stack, udp_tx), 0,
                     reports_out, count_in_out, &more);
  if( ! more )
    zf_muxer_mark_waitable_not_ready(&udp_tx->w, EPOLLERR);
  return 0;
}

struct zf_waitable* zfut_to_waitable(struct zfut* us)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  return &udp_tx->w;
}


unsigned zfut_get_header_size(struct zfut *us)
{
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, us);
  struct zf_tx* tx = &udp_tx->tx;
  const bool has_vlan = zf_tx_do_vlan(tx);
  return ETH_IP_HLEN + (VLAN_HLEN * has_vlan) + UDP_HLEN;
}
