/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/zf_pool_res.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/lazy_alloc.h>
#include <zf_internal/tx_res.h>
#include <zf_internal/tcp_opt.h>
#include <zf_internal/muxer.h>
#include <zf_internal/zf_tcp.h>
#include <zf_internal/zf_alts.h>

#include <zf_internal/private/zf_stack_rx.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <ci/efhw/mc_driver_pcol.h>
#include <ci/driver/efab/hardware/host_ef10_common.h>

#include <onload/driveraccess.h>

void udp_rx_flush(struct zf_stack* stack, struct zf_udp_rx* udp_rx)
{
  zf_rx* rx = &udp_rx->rx;
  zf_rx_ring* ring = &rx->ring;
  uint32_t unfreed_pkts = ring->begin_read - ring->begin_process;
  if( unfreed_pkts ) {
    zf_assume_le(unfreed_pkts, SW_RECVQ_MAX);
    /* clean up after previous read_done */
    zfr_zc_process_done(&stack->pool, rx, unfreed_pkts);
  }
}

/* Flush all pending TCP RX processing on the stack. */
void zf_stack_udp_rx_flush(struct zf_stack* stack)
{
  while( stack->udp_deferred_rx_bitmap != 0 ) {
    int index = zf_stack_udp_pop_deferred_rx(stack);
    udp_rx_flush(stack, &stack->udp_rx[index]);
  }

}


/* Flush all pending TCP RX processing on the stack. */
int zf_stack_tcp_rx_flush(struct zf_stack* stack)
{
  int event_occurred = 0;

  while( stack->tcp_deferred_rx_bitmap != 0 ) {
    int index = zf_stack_tcp_pop_deferred_rx(stack);
    event_occurred |= tcp_rx_flush(stack, &stack->tcp[index]);
  }

  return event_occurred;
}

ZF_HOT static inline void
zf_invalidate_timestamp(char* iov_base)
{
  /* Here we manufacture a (tsync_minor, pkt_minor) pair to always return
   * -EL2NSYNC when calling ef_vi for translation, regardless of timestamp
   * format. */
  *(uint32_t*)(iov_base + RX_PREFIX_TSYNC_MINOR_OFST) = 0;
  *(uint32_t*)(iov_base + ES_DZ_PS_RX_PREFIX_TSTAMP_OFST) = 0x7F000000;
}

/* Returns negative on error, zero if no user-visible events occurred, and
 * positive otherwise.  This function might be called with a packet from the
 * future, but we gurantee that its event has been processed by the time we
 * return. */
ZF_HOT int
zf_stack_handle_rx(struct zf_stack* st, int nic, const char* iov_base,
                   pkt_id id, uint16_t len)
{
  zf_log_event_trace(st, "%s: future_nic_id=%d future_packet_id=%x\n",
                     __FUNCTION__, st->future_nic_id, st->future_packet_id);

  unsigned rx_prefix_len = st->nic[nic].rx_prefix_len;
  zf_assume((rx_prefix_len == 0) || (rx_prefix_len == ES_DZ_RX_PREFIX_SIZE));

  if( rx_prefix_len ){
    ef_vi* vi = &(st->nic[nic].vi);

    if( vi->nic_type.arch != EF_VI_ARCH_EFCT &&
        vi->nic_type.arch != EF_VI_ARCH_EF10CT ) {
      ef_eventq_state* evqs = &(vi->ep_state->evq);

      /* To overcome the restrictions that come with using ef_vi's timestamping
       * API, as the packet comes in we store a snapshot of the eventq state's
       * timesync information in the prefix.
       *
       * -------------------------------------------------------
       * | tsync_minor | tsync_major | nicno   | MAC Timestamp |
       * -------------------------------------------------------
       * |   4 bytes   |   4 bytes   | 2 bytes |    4 bytes    |
       *
       * nicno currently has a maximum possible value of 3, so we could stuff
       * more into that field in the future if need be.
       */

      *(uint32_t*)(iov_base + RX_PREFIX_TSYNC_MINOR_OFST) =
        evqs->sync_timestamp_minor;

      *(uint32_t*)(iov_base + RX_PREFIX_TSYNC_MAJOR_OFST) =
        evqs->sync_timestamp_major;

      *(uint16_t*)(iov_base + RX_PREFIX_NICNO_OFST) = nic;

      /* If the eventq is out of sync, we must act on that information now */
      if(ZF_UNLIKELY( ! evqs->sync_timestamp_synchronised ))
        zf_invalidate_timestamp((char*)iov_base);
    }
  }

  st->pftf.payload += rx_prefix_len;
  const char* eth_hdr_base = iov_base + rx_prefix_len;
  const struct iphdr* ip = (iphdr*)(eth_hdr_base + sizeof(struct ethhdr));
  uint16_t h_protocol = *((uint16_t*)ip - 1);

//  dump_pkt(0, iov_base, MAX(len,64));

  if(ZF_LIKELY( h_protocol == zf_htons(ETH_P_IP) )) {
    if(ip->protocol == IPPROTO_UDP) {
      return zf_stack_handle_rx_udp(st, eth_hdr_base, ip, len);
    }
    else if(ip->protocol == IPPROTO_TCP) {
      return zf_stack_handle_rx_tcp(st, eth_hdr_base, ip, len);
    }
  }
  else {
    ip = zf_ip_hdr(eth_hdr_base);
    h_protocol = *((uint16_t*)ip - 1);
    if(ZF_LIKELY( h_protocol == zf_htons(ETH_P_IP) )) {
      if(ip->protocol == IPPROTO_UDP) {
        return zf_stack_handle_rx_udp(st, eth_hdr_base, ip, len);
      }
      else if(ip->protocol == IPPROTO_TCP) {
        return zf_stack_handle_rx_tcp(st, eth_hdr_base, ip, len);
      }
    }
  }

  /* We don't handle this packet, so we don't care whether we receive
   * it successfully, but we do need to wait for the event and handle
   * any other user-visible events we encounter. */
  int rc = zf_stack_sync_future_rx(st, len, len);

  zf_assert_equal(st->future_nic_id, zf_stack::FUTURE_NIC_INVALID);

  /* Just ditch the weird thing */
  zf_log_event_trace(st, "%s: Not TCP or UDP\n", __FUNCTION__);
  st->stats.non_tcpudp++;
#ifndef NDEBUG
  if( rc >= 0 )
    dump_pkt(st, iov_base, len);
#endif
  if( id != PKT_INVALID )
    zf_pool_free_pkt(&st->pool, id);

  return rc > 0;
}

/* Clone of zf_stack_handle_rx that is optimized for overlapped receives */
ZF_HOT int
zf_stack_handle_rx_pftf(struct zf_stack* st, int nic, const char* iov_base,
                        pkt_id id)
{
  return zf_stack_handle_rx(st, nic, iov_base, id, 0);
}
