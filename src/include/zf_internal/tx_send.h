/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF tx send - tx fast path send */

#ifndef __ZF_TX_SEND_H__
#define __ZF_TX_SEND_H__

#include <zf_internal/tx.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/utils.h>
#include <etherfabric/pio.h>
#include <etherfabric/checksum.h>
extern "C" {
#include <etherfabric/internal/internal.h>
}


/* Normally, you want to pass following req_id to zf_send: */
static constexpr zf_tx_req_id ZF_REQ_ID_NORMAL =
  ZF_REQ_ID_PIO_FLAG | ZF_REQ_ID_PKT_ID_MASK;
/* or the same without PIO: */
static constexpr zf_tx_req_id ZF_REQ_ID_NO_PIO = ZF_REQ_ID_PKT_ID_MASK;


template <typename NIC_TYPE>
ZF_HOT static inline bool
pio_is_available(const NIC_TYPE* st_nic)
{
  return (st_nic->pio.busy != 3);
}


template <typename NIC_TYPE>
ZF_HOT static inline uint16_t
max_pio_len(const NIC_TYPE* st_nic)
{
  return (st_nic->pio.len / 2);
}


template <typename NIC_TYPE>
ZF_HOT static inline bool
ctpio_is_allowed(const NIC_TYPE* st_nic, size_t length)
{
  return ((zf_stack_nic_tx_vi(st_nic)->vi_flags & EF_VI_TX_CTPIO) &&
          (st_nic->ctpio_allowed >= length));
}

ZF_HOT static inline size_t
do_checksum(const iovec* iov, int iov_cnt)
{
    size_t frame_len;
    struct iphdr* ip = zf_ip_hdr((char *)iov[0].iov_base);
    ip->check = ef_ip_checksum(ip);
    if( ip->protocol == IPPROTO_TCP ) {
      struct tcphdr* tcp;
      size_t remaining;
      const char* payload;

      zf_assert_ge(iov[0].iov_len,
                   (sizeof(struct ethhdr) +
                    sizeof(struct iphdr) +
                    sizeof(struct tcphdr)));

      tcp = (struct tcphdr*) (ip + 1);
      payload = ((const char*)tcp) + 4 * tcp->doff;
      remaining = iov[0].iov_len - (payload - (const char*)iov[0].iov_base);

      struct iovec local_iov[iov_cnt];
      frame_len = iov[0].iov_len;
      for ( int i = 1; i < iov_cnt; i++ ) {
        local_iov[i] = iov[i];
        frame_len += iov[i].iov_len;
      }

      local_iov[0].iov_base = (void*)payload;
      local_iov[0].iov_len = remaining;

      tcp->check = ef_tcp_checksum(ip, tcp, local_iov, iov_cnt);
    }
    else if( ip->protocol == IPPROTO_UDP ) {
      struct udphdr* udp;
      size_t remaining;
      const char* payload;
      struct iovec local_iov[iov_cnt];
      frame_len = iov[0].iov_len;
      for ( int i = 1; i < iov_cnt; i++ ) {
        local_iov[i] = iov[i];
        frame_len += iov[i].iov_len;
      }
      if( ip->frag_off & ~htons(IP_DF) )
        /* Checksum was precalculated and placed beforehand in the first fragment
         * and further fragments have no udp header */
        return frame_len;

      zf_assert_ge(iov[0].iov_len,
                   (sizeof(struct ethhdr) +
                    sizeof(struct iphdr) +
                    sizeof(struct udphdr)));

      udp = (struct udphdr*) (ip + 1);
      payload = (const char*)(udp + 1);
      remaining = iov[0].iov_len - (payload - (const char*)iov[0].iov_base);

      local_iov[0].iov_base = (void*)payload;
      local_iov[0].iov_len = remaining;

      udp->check = ef_udp_checksum(ip, udp, local_iov, iov_cnt);
    }
    else
      return 0;
    return frame_len;
}

/* req_id is the desired TX request id.  Typically, it can be:
 * - Protocol field should be ZF_REQ_ID_PROTO_TCP_NEW if and only if
 *   req_id_out is non-null.  This flag means that TX complate should not
 *   just free the packet, but should run a specialized function.
 * - REQ_ID_PIO_FLAG means that caller allows to use PIO or CTPIO.
 * - non-fff ZF_REQ_ID_PKT_ID_MASK means that the caller's data are
 *   already in the packed buffer; this buffer can be used in case of DMA
 *   send.
 *
 * req_id_out is the real TX request id used by the function.  It must be
 * supplied if the protocol field is ZF_REQ_ID_PROTO_TCP_NEW; the caller is
 * responsible for the packet buffer used for TX (if any).
 * REQ_ID_PIO_FLAG will be set in req_id_out if the packet was sent
 * via "classic" PIO; if it was sent via CTPIO this flag will be
 * clear. The caller can use this to know whether an allocated packet
 * buffer is in flight for this packet.
 *
 * This function may modify the pointed-to packet data by filling in
 * the checksum fields.
 */
ZF_HOT static inline int
zf_send(struct zf_tx* restrict tx,
        struct iovec* restrict iov,
        size_t iov_cnt,
        size_t tot_len,
        zf_tx_req_id req_id,
        zf_tx_req_id** req_id_out)
{
  struct zf_stack* st = zf_stack_from_zocket(tx);
  struct zf_pool* pool = &st->pool;
  int nicno = tx->path.nicno;
  int rc;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  ef_vi* vi = zf_stack_nic_tx_vi(st_nic);
  auto store_req = [&]{
    uint16_t idx = (st_nic->tx_reqs_added++) & st_nic->tx_reqs_mask;
    st_nic->tx_reqs[idx] = req_id;
    if( req_id_out )
      *req_id_out = &st_nic->tx_reqs[idx];
  };


  zf_assume_impl(req_id_out == NULL,
                 (req_id & ZF_REQ_ID_PROTO_MASK) != ZF_REQ_ID_PROTO_TCP_KEEP &&
                 (req_id & ZF_REQ_ID_PROTO_MASK) != ZF_REQ_ID_PROTO_TCP_ALT);

#ifdef ZF_DEVEL
  if( st->flags & ZF_STACK_FLAG_DEVEL_NO_TX )
    /* simulate full txq */
    return -EAGAIN;
#endif

  if( *zf_stack_res_nic_flags(st, nicno) & ZF_RES_NIC_FLAG_CTPIO_ONLY ) {
    /* FIXME get X3 overhead sorted properly */
    if(ZF_UNLIKELY( ef_vi_transmit_space_bytes(vi) < (int)tot_len + 128 )) {
      if( st->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
        return 0;
      else
        return -EAGAIN;
    }
    size_t frame_len = do_checksum(iov, iov_cnt);
    zf_assert_gt(frame_len, 0);
    ef_vi_transmitv_ctpio(vi, frame_len, iov, iov_cnt,
                          st->config.ctpio_threshold);

    if( st->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
      return 0;

    /* On X3 ctpio does not come with fallback and is more akin semantically
     * (at least in regards to tcpdirect internals) to PIO due to lack of
     * fallback
     * UDP does not require storing a buffer.
     */
    if( ZF_LIKELY( req_id & ZF_REQ_ID_PIO_FLAG ) ||
        ZF_LIKELY( (req_id & ZF_REQ_ID_PROTO_MASK) == ZF_REQ_ID_PROTO_UDP ) )
    {
      req_id |= ZF_REQ_ID_PKT_ID_MASK | ZF_REQ_ID_CTPIO_FLAG;
      store_req();
      return 0;
    }
    zf_assert(false);
    /* caller will have problem coping with unexpected PIO */
    if( (req_id & ZF_REQ_ID_PKT_ID_MASK) != PKT_INVALID ) {
      /* pretend we have DMAed the buffer */
      req_id &=~ ZF_REQ_ID_PIO_FLAG;
      store_req();
      return 0;
    }
  }
  /* check if any of pio sections are free, each busy flag bit correspond to
   * respective half of the pio buffer, 3 means no free buffers */
  if( (req_id & ZF_REQ_ID_PIO_FLAG) &&
      !ctpio_is_allowed(st_nic, tot_len) &&
      pio_is_available(st_nic) &&
      tot_len <= max_pio_len(st_nic) && iov_cnt <= 2 ) {
    zf_assert(*zf_stack_res_nic_flags(st, nicno) & ZF_RES_NIC_FLAG_PIO);
    int pio_buf_no = st_nic->pio.busy & 1;
    int orig_pio_ofs = pio_buf_no ? max_pio_len(st_nic) : 0;
    rc = ef10_ef_vi_transmitv_copy_pio(vi, orig_pio_ofs, iov, iov_cnt, 1);
    if( ZF_UNLIKELY(rc < 0) ) {
      /* The only reason for failure that should ever occur is lack of TXQ
       * space. */
      zf_assume_equal(rc, -EAGAIN);

      /* Warming simulates a full TXQ so EAGAIN is expected. */
      if( st->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
        return 0;

      zf_log_stack_trace(st,
                         "%s: ef10_ef_vi_transmitv_copy_pio() failed: rc=%d\n",
                         __func__, rc);
      return rc;
    }
    req_id &= ~ZF_REQ_ID_PKT_ID_MASK;
    req_id |= pio_buf_no;
    st_nic->pio.busy |= 1u << pio_buf_no;
    store_req();
    return 0;
  }

  /* We're not doing PIO, so prepare for a DMA or CTPIO send with
   * following fallback. */
  pkt_id id = req_id & ZF_REQ_ID_PKT_ID_MASK;
  bool pio_allowed = (req_id & ZF_REQ_ID_PIO_FLAG) != 0;
  req_id &=~ ZF_REQ_ID_PIO_FLAG;

  bool reused = true;
  if( id == PKT_INVALID ) {
    zf_assume_nequal(req_id & ZF_REQ_ID_PROTO_MASK, ZF_REQ_ID_PROTO_TCP_ALT);
    if( (rc = zft_alloc_pkt(pool, &id)) != 0 )
      return rc;
    req_id &=~ ZF_REQ_ID_PKT_ID_MASK;
    req_id |= id;
    reused = false;
  }

  char* pktb = PKT_BUF_BY_ID(&st->pool, id);

  /* Are we doing CTPIO? */
  bool do_ctpio = pio_allowed && ctpio_is_allowed(st_nic, tot_len);
  if( do_ctpio ) {
    zf_assert_gt(iov_cnt, 0);
    zf_assert_le(iov_cnt, 2);
    size_t frame_len = do_checksum(iov, iov_cnt);
    if(ZF_UNLIKELY( ! frame_len )) {
      /* Unrecognised protocol. */
      zf_log_stack_err(st, "%s: can't calculate checksum for protocol %d\n",
                       __func__, zf_ip_hdr((char *)iov[0].iov_base)->protocol);
      if( ! reused )
        zf_pool_free_pkt(pool, id);
      return -EINVAL;
    }

    ef_vi_transmitv_ctpio_copy(vi, frame_len, iov, iov_cnt,
                               st->config.ctpio_threshold, pktb);

    req_id |= ZF_REQ_ID_CTPIO_FLAG;
  }
  else {
    /* We assume that in **reused** case the last chunk is already on place,
     * i.e. we are sending a data buffer with a header buffer(s), and data is
     * already in the packet. */
    for( size_t i = 0; i < iov_cnt; ++i ) {
      if( reused &&
          !(vi->vi_flags & EF_VI_TX_CTPIO) &&
          (i > 0) &&
          i == iov_cnt - 1 ) {
        zf_assume_equal(memcmp(pktb, iov->iov_base, iov->iov_len), 0);
        break;
      }
      memcpy(pktb, iov->iov_base, iov->iov_len);
      pktb += iov->iov_len;
      ++iov;
    }
  }
  zf_assert_nequal(vi->nic_type.arch, EF_VI_ARCH_EFCT);
  zf_assert_nequal(vi->nic_type.arch, EF_VI_ARCH_EF10CT);
  /* Strictly speaking, we should call ef_vi_transmit_ctpio_fallback()
   * to post a CTPIO fallback descriptor. However, that entry point is
   * actually identical to this one, and this code path is also used
   * for DMA-only sends.
   *
   * The only reason the ef_vi_transmit should fail is if the TXQ is full.
   * For CTPIO fallback we ensure this is not the case by disabling
   * CTPIO when TXQ is full. */
  rc = ef_vi_transmit(vi, PKT_EFADDR_BY_ID(pool, nicno, id),
                      tot_len, 1);
  if( ZF_UNLIKELY(rc < 0) ) {
    zf_assume_equal(rc, -EAGAIN);
    if( ! reused )
      zf_pool_free_pkt(pool, id);

    /* Warming simulates a full TXQ so EAGAIN is expected. */
    if( st->flags & ZF_STACK_FLAG_TRANSMIT_WARM_ENABLED )
      return 0;

    /* Not warming.  CTPIO fallback failure should be impossible. */
    zf_assert( ! do_ctpio );

    zf_log_stack_trace(st, "%s: out of TXQ space\n", __func__);
    return rc;
  }
  else if( ZF_UNLIKELY(! ef_vi_transmit_space(vi)) ) {
    /* Just used last TX ring slot, disallow CTPIO.
     * If apps poll reasonably frequently, they won't hit this. */
    st_nic->ctpio_allowed = 0;
  }

  store_req();
  return 0;
}


static inline int
send_with_hdr(zf_tx* tx, const void* buf, size_t buflen,
              uint8_t* hdr_buf, size_t hdr_size, size_t hdrfilllen,
              zf_tx_req_id req_id, zf_tx_req_id** req_id_out)
{
  int rc;

  zf_assume_le(buflen + hdr_size,
               MIN(tx->path.mtu + sizeof(struct ethhdr) +
                   zf_tx_do_vlan(tx) * VLAN_HLEN,
                   PKT_BUF_SIZE_USABLE));

  /* Note with PIO we can only copy continous blocks of 8 bytes
   * starting with alignment 8 (or cache line alignment - 64bytes)
   * no gaps allowed mid cache line */
  struct iovec iov2[2];

  hdrfilllen = MIN(hdrfilllen, buflen);
  memcpy(hdr_buf + hdr_size, buf, hdrfilllen);
  iov2[0].iov_base = hdr_buf;
  iov2[0].iov_len = hdr_size + hdrfilllen;

  int iov_len = buflen - hdrfilllen;
  int iov_cnt = 1;
  if( iov_len != 0 ) {
    iov2[1].iov_base = (char*) buf + hdrfilllen;
    iov2[1].iov_len = iov_len;
    ++iov_cnt;
  }
  rc = zf_send(tx, iov2, iov_cnt, buflen + hdr_size, req_id, req_id_out);
  if( rc == 0 ) {
    return buflen;
  }
  else {
    zf_log_stack_trace(zf_stack_from_zocket(tx),
                       "%s: zf_send() failed: rc=%d\n", __func__, rc);
    return rc;
  }
}

#endif /* __ZF_TX_SEND_H__ */
