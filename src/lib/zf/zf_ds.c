/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/tcp.h>
#include <zf_internal/tcp_tx.h>
#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>


static enum zf_delegated_send_rc
zf_delegated_send_copy_headers(const struct zf_tcp* tcp, struct zf_ds* ds)
{
  const struct tcp_pcb* pcb = &tcp->pcb;
  const struct zf_tx* tx = &tcp->tst;
  const bool has_vlan = zf_tx_do_vlan(tx);
  struct tcphdr* tcp_hdr;
  struct iphdr* ip_hdr;

  ds->headers_len = ETH_IP_HLEN + (VLAN_HLEN * has_vlan) + TCP_HLEN;
  if( ds->headers_size < ds->headers_len )
    return ZF_DELEGATED_SEND_RC_SMALL_HEADER;

  memcpy(ds->headers, zf_tx_ethhdr_c(tx), ds->headers_len);
  if( has_vlan ) {
    struct ethvlaniptcphdr* vlan_pkt = (struct ethvlaniptcphdr*) ds->headers;
    tcp_hdr = &vlan_pkt->tcp;
    ip_hdr = &vlan_pkt->ip;
  }
  else {
    struct ethiptcphdr* pkt = (struct ethiptcphdr*) ds->headers;
    tcp_hdr = &pkt->tcp;
    ip_hdr = &pkt->ip;
  }

  ip_hdr->tot_len = htons(IP_HLEN + TCP_HLEN + pcb->mss);
  ip_hdr->check = 0;
  tcp_output_populate_header(tcp_hdr, pcb->local_port, pcb->remote_port,
                             pcb->snd_lbb, pcb->rcv_nxt, pcb->rcv_ann_wnd);
  ds->tcp_seq_offset = (char*)(&tcp_hdr->seq) - (char*)ds->headers;
  ds->ip_len_offset = (char*)(&ip_hdr->tot_len) - (char*)ds->headers;
  ds->ip_tcp_hdr_len = IP_HLEN + TCP_HLEN;
  return ZF_DELEGATED_SEND_RC_OK;
}


enum zf_delegated_send_rc
zf_delegated_send_prepare(struct zft* ts, int max_delegated_wnd,
                          int cong_wnd_override, unsigned flags,
                          struct zf_ds* ds)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct tcp_pcb* pcb = &tcp->pcb;

  ds->mss = 0;
  ds->headers_len = 0;

  if( ZF_UNLIKELY(!(pcb->state & FAST_SEND_STATE_MASK)) )
    return ZF_DELEGATED_SEND_RC_BAD_SOCKET;
  if( ZF_UNLIKELY(tcp_has_unsent(&pcb->sendq)) )
    return ZF_DELEGATED_SEND_RC_SENDQ_BUSY;

  zf_assert_equal(pcb->snd_lbb, pcb->snd_nxt);

  enum zf_delegated_send_rc rc = zf_delegated_send_copy_headers(tcp, ds);
  if( rc != ZF_DELEGATED_SEND_RC_OK )
    return rc;

  ds->mss = pcb->mss;
  ds->send_wnd = TCP_SEQ_SUB(pcb->snd_right_edge, pcb->snd_lbb);
  ds->cong_wnd = TCP_SEQ_SUB(pcb->cwnd + pcb->lastack, pcb->snd_lbb);
  ds->cong_wnd = MAX(0, ds->cong_wnd);
  /* This will be non-zero if we're refreshing a previous prepare. */
  ds->delegated_wnd = pcb->snd_delegated;

  int cwnd = MAX(cong_wnd_override, ds->cong_wnd);
  if( cwnd < ds->mss )
    return ZF_DELEGATED_SEND_RC_NOCWIN;
  if( ds->send_wnd <= 0 )
    return ZF_DELEGATED_SEND_RC_NOWIN;

  /* Do not allow pcb->snd_delegated to shrink due to send_wnd or cong_wnd
   * shrinking, as we've promised the application it can send that much,
   * and it may be too late for it to stop.
   */
  int max_snd = MIN(ds->send_wnd, cwnd);
  max_snd = MAX(max_snd, pcb->snd_delegated);

  /* We need space in the sendq for this on completion */
  int snd_buf_space = MAX((uint32_t)0, tcp_snd_buf_avail(pcb, &pcb->sendq));
  max_snd = MIN(snd_buf_space, max_snd);
  if( max_snd == 0 )
    return ZF_DELEGATED_SEND_RC_SENDQ_BUSY;

  /* Avoid overflowing 32bit snd_delegated - expected to be so due to
   * using int types for max_snd and max_delegated_wnd
   */
  zf_assert_le(max_snd, 0x7fffffff);
  zf_assert_le(max_delegated_wnd, 0x7fffffff);

  pcb->snd_delegated = MIN(max_snd, max_delegated_wnd);
  ds->delegated_wnd = pcb->snd_delegated;

  /* Changing snd_delegated can alter the validity of doing fast
   * sends, so update that state to match
   */
  tcp_fix_fast_send_length(pcb);

  return ZF_DELEGATED_SEND_RC_OK;
}


int zf_delegated_send_complete(struct zft* ts, const struct iovec* iov,
                               int iovlen, int flags)
{
  int total_unsent = 0, total_sent = 0, i, rc = 0;
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct tcp_pcb* pcb = &tcp->pcb;

  for( i = 0; i < iovlen; ++i )
    total_unsent += iov[i].iov_len;

  if( total_unsent > pcb->snd_delegated )
    return -EMSGSIZE;

  int already_acked = TCP_SEQ_SUB(pcb->lastack, pcb->snd_lbb);

  /* (already_acked > 0) implies (pcb->lastack > pcb->snd_lbb)
   *   -> we've received ACKs for things not in the retrans queue
   *   -> some of this data is already acked
   * (already_acked == 0) implies (pcb->lastack == pcb->snd_lbb)
   *   -> data is not already acked, and nothing in the retrans queue
   * (already_acked < 0) implies (pcb->lastack < pcb->snd_lbb)
   *   -> data is not already acked, but something in the retrans queue
   */
  already_acked = MAX(0, already_acked);
  already_acked = MIN(already_acked, total_unsent);

  if( already_acked ) {
    zf_assert_le(already_acked, pcb->snd_delegated);
    pcb->snd_delegated -= already_acked;
    pcb->snd_lbb += already_acked;
    total_unsent -= already_acked;
    total_sent += already_acked;
    while( (unsigned)already_acked >= iov->iov_len ) {
      already_acked -= iov->iov_len;
      ++iov;
      --iovlen;
    }
  }

  if( total_unsent == 0 )
    goto out;

  zf_assert_gt(iovlen, 0);
  zf_assert_lt((unsigned) already_acked, iov->iov_len);

  struct iovec iov_temp;
  while( iovlen ) {
    iov_temp.iov_base = (char*)iov->iov_base + already_acked;
    iov_temp.iov_len = iov->iov_len - already_acked;

    /* After first time round the loop we should have dealt with all
     * "already_acked" bytes
     */
    already_acked = 0;

    /* Queue remaining packets on send queue */
    rc = tcp_queue_sent_segments(tcp, &pcb->sendq, &iov_temp, &pcb->snd_lbb);
    if( ZF_UNLIKELY(rc < 0) )
      goto out;
    tcp_output_timers_common(zf_stack_from_zocket(tcp), tcp, pcb->snd_lbb);

    unsigned snd_buf_consumed = pcb->mss * rc;
    if( snd_buf_consumed > pcb->snd_buf )
      pcb->snd_buf = 0;
    else
      pcb->snd_buf -= snd_buf_consumed;

    pcb->snd_delegated -= iov_temp.iov_len;
    total_unsent -= iov_temp.iov_len;
    total_sent += iov_temp.iov_len;

    ++iov;
    --iovlen;
  }
  tcp_seg_tcphdr(tcp_seg_last(&pcb->sendq))->psh = 1;

  /* Start retransmit timer */
  if ( ! zf_tcp_timers_timer_is_active(tcp, ZF_TCP_TIMER_RTO) )
    zf_tcp_timers_timer_start(tcp, ZF_TCP_TIMER_RTO,
                              zf_tcp_timers_rto_timeout(tcp));

  zf_assert_gt(total_sent, 0);
  zf_assert_equal(total_unsent, 0);

 out:

  pcb->snd_nxt = pcb->snd_lbb;
  /* If all the prepared bytes have been completed, then we may be
   * able to allow fast sends again
   */
  if( pcb->snd_delegated == 0 )
    tcp_fix_fast_send_length(pcb);

  if( total_sent != 0 )
    return total_sent;
  else
    return rc;
}


int zf_delegated_send_cancel(struct zft* ts)
{
  struct zf_tcp* tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
  struct tcp_pcb* pcb = &tcp->pcb;

  pcb->snd_delegated = 0;

  /* snd_delegated becoming zero means we can potentially enable fast sends */
  tcp_fix_fast_send_length(pcb);

  return 0;
}
