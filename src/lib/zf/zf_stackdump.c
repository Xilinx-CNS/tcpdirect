/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_tcp.h>
#include <zf_internal/udp_rx.h>
#include <zf_internal/udp_tx.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/zf_stackdump.h>


template<typename Zocket, typename Resource, typename DumpZocket>
static void dump_zockets(SkewPointer<zf_stack> stack, Zocket* zockets,
                         int num_zockets,
                         void (*to_res)(struct zf_stack*, Zocket*, Resource**),
                         DumpZocket dump_zocket)
{
  for( Zocket* zocket = zockets; zocket < zockets + num_zockets; ++zocket ) {
    Resource* res;
    to_res(stack, zocket, &res);
    if( res->generic_res.res_flags & ZF_GENERIC_RES_ALLOCATED ) {
      dump_zocket(stack.propagate_skew(zocket));
      zf_dump("------------------------------------------------------------\n");
    }
  }
}

void dump_attributes(SkewPointer<zf_stack_impl> stimpl)
{
  zf_dump("---------------------attributes-------------------------------\n");
  
  if(stimpl->sti_tx_ring_max == -1)
    zf_dump("tx_ring_max=512\n");
  else
    zf_dump("tx_ring_max=%d\n", stimpl->sti_tx_ring_max);
  
  if(stimpl->sti_rx_ring_max == -1)
    zf_dump("rx_ring_max=512\n");
  else
    zf_dump("rx_ring_max=%d\n", stimpl->sti_rx_ring_max);

  zf_dump("tx_timestamping=%d\n", stimpl->sti_tx_timestamping);  
  zf_dump("rx_timestamping=%d\n", stimpl->sti_rx_timestamping);  
  zf_dump("ctpio=%d\n", stimpl->sti_ctpio);
  zf_dump("ctpio_mode=%s\n", stimpl->sti_ctpio_mode);
  zf_dump("rx_datapath=%s\n", (stimpl->sti_rx_datapath == ENTERPRISE_MODE
    ? "enterprise"
    : "express"));
  zf_dump("phys_address_mode=%d\n", stimpl->sti_phys_address_mode);
  zf_dump("shrub_controller=%d\n", stimpl->sti_shrub_controller);
  zf_dump("pio=%d\n", stimpl->sti_pio);
  zf_dump("reactor_spin_count=%d\n", stimpl->sti_reactor_spin_count);
  zf_dump("tcp_timewait_ms=%d\n", stimpl->sti_tcp_timewait_ms);  
  zf_dump("alt_buf_size=%d\n", stimpl->sti_alt_buf_size);  
  zf_dump("alt_count=%d\n", stimpl->sti_alt_count);  
  zf_dump("rx_ring_refill_batch_size=%d\n", stimpl->sti_rx_ring_refill_batch_size);
  zf_dump("tcp_alt_ack_rewind=%d\n", stimpl->sti_tcp_alt_ack_rewind);  
  zf_dump("tcp_delayed_ack=%d\n", stimpl->sti_tcp_delayed_ack);  
  zf_dump("tcp_finwait_ms=%d\n", stimpl->sti_tcp_finwait_ms);  
  zf_dump("tcp_wait_for_time_wait=%d\n", stimpl->sti_tcp_wait_for_time_wait);  
  zf_dump("ctpio_max_frame_len=%d\n", stimpl->sti_ctpio_max_frame_len);
  zf_dump("force_separate_tx_vi=%d\n", stimpl->sti_force_separate_tx_vi);
  zf_dump("rx_ring_refill_interval=%d\n", stimpl->sti_rx_ring_refill_interval);
  zf_dump("udp_ttl=%d\n", stimpl->sti_udp_ttl); 
  zf_dump("log_level=%X\n", stimpl->sti_log_level); 
}

void dump_zockets(SkewPointer<zf_stack_impl> sti)
{
  SkewPointer<zf_stack> stack = sti.propagate_skew(&sti->st);

  dump_zockets(stack, stack->tcp, sti->max_tcp_endpoints, zf_stack_tcp_to_res,
               [&stack] (SkewPointer<zf_tcp> tcp)
                { zf_tcp_dump(stack, tcp); });

  dump_zockets(stack, stack->tcp_listen, sti->max_tcp_listen_endpoints,
               zf_stack_tcp_listen_state_to_res,
               [&stack] (SkewPointer<zf_tcp_listen_state> listener)
                { zf_tcp_listen_dump(stack, listener); });

  dump_zockets(stack, stack->udp_rx, sti->max_udp_rx_endpoints,
               zf_stack_udp_rx_to_res,
               [&stack] (SkewPointer<zf_udp_rx> rx)
                { zfur_dump(stack, rx); });

  dump_zockets(stack, stack->udp_tx, sti->max_udp_tx_endpoints,
               zf_stack_udp_tx_to_res,
               [&stack] (SkewPointer<zf_udp_tx> tx)
                { zfut_dump(stack, tx); });
}


void dump_nic(SkewPointer<zf_stack_impl> stimpl, int index)
{
  SkewPointer<zf_stack> stack = stimpl.propagate_skew(&stimpl->st);
  struct zf_stack_nic* nic = &stack->nic[index];
  struct ef_vi* vi = &nic->vi;

  if( !vi->inited )
    return;

  zf_dump("nic%d: vi=%d vi_flags=%x nic_flags=%x intf=%s index=%d hw=%u%c%u\n",
          index, ef_vi_instance(vi), ef_vi_flags(vi), stimpl->nic[index].flags,
          stimpl->nic[index].if_name, stimpl->nic[index].ifindex,
          vi->nic_type.arch, vi->nic_type.variant, vi->nic_type.revision);
#if 0
  /* TODO: Share VI ep_state (and maybe also DMA queues) so that we can
   * re-enable these. */
  zf_dump("  evq: cap=%d current=%u is_ev=%d\n",
          ef_eventq_capacity(vi), ef_eventq_current(vi),
          /*ef_eventq_has_event(vi)*/0);
  zf_dump("  rxq: cap=%d space=%d level=%d\n",
          ef_vi_receive_capacity(vi), ef_vi_receive_space(vi),
          ef_vi_receive_fill_level(vi));
  zf_dump("  txq: cap=%d space=%d level=%d\n",
          ef_vi_transmit_capacity(vi), ef_vi_transmit_space(vi),
          ef_vi_transmit_fill_level(vi));
#endif
  zf_dump("  txq: pio_buf_size=%d added=%d removed=%d\n",
          nic->pio.len, nic->tx_reqs_added, nic->tx_reqs_removed);
}


void dump_stack(SkewPointer<zf_stack_impl> stimpl)
{
  SkewPointer<zf_stack> stack = stimpl.propagate_skew(&stimpl->st);
  zf_dump("onload version=%s\n", stimpl->sti_on_version);
  zf_dump("tcpdirect version=%s\n", stimpl->sti_zf_version);
  zf_dump("name=%." ZF_STRINGIFY(ZF_STACK_NAME_SIZE) "s interface=%s "
          "vlan_id=%u\n",
          stack->st_name, stimpl->sti_if_name, stimpl->sti_vlan_id);
  zf_dump("  pool: pkt_bufs_n=%d free=%d\n",
          stack->pool.pkt_bufs_n, NUM_FREE_PKTS(&stack->pool));
  zf_dump("  config: tcp_timewait_ticks=%d tcp_finwait_ticks=%d"
          " ctpio_threshold=%d\n",
          stack->config.tcp_timewait_ticks, stack->config.tcp_finwait_ticks,
          stack->config.ctpio_threshold);
  zf_dump("  config: tcp_initial_cwnd=%u ms_per_tcp_tick=%d\n",
          stack->tcp_initial_cwnd, TCP_TMR_INTERVAL);
  zf_dump("  alts: n_alts=%d\n",
          stimpl->n_alts);
  zf_dump("  stats: ring_refill_nomem=%d cplane_alien_ifindex=%u\n",
          stack->stats.ring_refill_nomem, stack->stats.cplane_alien_ifindex);
  zf_dump("         tcp_retransmits=%d\n", stack->stats.tcp_retransmits);
  zf_dump("  discards: discard_csum_bad=%u discard_mcast_mismatch=%u\n"
          "         discard_crc_bad=%u discard_trunc=%u discard_rights=%u\n"
          "         discard_ev_error=%u discard_other=%u discard_inner_csum_bad=%u\n"
          "         non_tcpudp=%d \n",
          stack->stats.discards[EF_EVENT_RX_DISCARD_CSUM_BAD],
          stack->stats.discards[EF_EVENT_RX_DISCARD_MCAST_MISMATCH],
          stack->stats.discards[EF_EVENT_RX_DISCARD_CRC_BAD],
          stack->stats.discards[EF_EVENT_RX_DISCARD_TRUNC],
          stack->stats.discards[EF_EVENT_RX_DISCARD_RIGHTS],
          stack->stats.discards[EF_EVENT_RX_DISCARD_EV_ERROR],
          stack->stats.discards[EF_EVENT_RX_DISCARD_OTHER],
          stack->stats.discards[EF_EVENT_RX_DISCARD_INNER_CSUM_BAD],
          stack->stats.non_tcpudp);
  zf_dump("]\n");

  for( int i = 0; i < stack->nics_n; i++ )
    dump_nic(stimpl, i);
}


void dump_alts(SkewPointer<zf_stack_impl> stimpl)
{
  if( stimpl->n_alts > 0 )
    zf_dump("============================================================\n");
  for( int i = 0; i < stimpl->n_alts; ++i )
    zf_alt_dump(stimpl, i);
}


void zf_stack_dump(struct zf_stack* stack)
{
  auto stimpl = SkewPointer<zf_stack_impl>(ZF_CONTAINER(struct zf_stack_impl,
                                                        st, stack));

  zf_dump("============================================================\n");
  dump_stack(stimpl);
  zf_dump("============================================================\n");
  dump_zockets(stimpl);
  dump_attributes(stimpl);

  dump_alts(stimpl);
};

void zf_stack_dump_attr(struct zf_stack* stack)
{
    auto stimpl = SkewPointer<zf_stack_impl>(ZF_CONTAINER(struct zf_stack_impl,
                                                        st, stack));

  zf_dump("============================================================\n");
  zf_stack_dump_summary(stack);
  dump_attributes(stimpl);
  
  dump_alts(stimpl);
}


void zf_stack_dump_summary(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, stack);
  zf_dump("%." ZF_STRINGIFY(ZF_STACK_NAME_SIZE) "s id=%-5d pid=%d\n",
          stack->st_name, sti->shm_id, sti->pid);
};


int zf_get_all_stack_shm_ids(int onload_dh, int* shm_ids, size_t count)
{
  return oo_dshm_list(onload_dh, OO_DSHM_CLASS_ZF_STACK, shm_ids, count);
}

/* N.B. The buffer whose address we return in [stack_out] is not a valid stack,
 * since it contains pointers into the stack's original mapping.  It can,
 * however, be passed to zf_stack_dump() and related functions. */
int zf_stack_map(int onload_dh, int stack_shm_id, struct zf_stack** stack_out)
{
  return oo_dshm_map(onload_dh, OO_DSHM_CLASS_ZF_STACK, stack_shm_id,
                     ZF_STACK_ALLOC_SIZE, (void**) stack_out);
}


/* This has to be implemented outside the body of the class because we need
 * access to zf_stack_impl. */

template<typename T>
SkewPointer<T>::SkewPointer(struct zf_stack_impl* sti) :
  SkewPointer(sti, sti->natural_sti_addr)
{
}
