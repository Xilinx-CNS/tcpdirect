/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  ZF stack non performance critical state and routines
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/


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
#include <zf_internal/bond.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <ci/efhw/mc_driver_pcol.h>

#include <onload/driveraccess.h>

#include <ci/driver/efab/hardware/host_ef10_common.h>

#include <ci/efch/op_types.h>
#include <zf_internal/zf_state.h>

#include <algorithm>

#define PIO_WARN_IF_NOT_AVAILABLE  2
#define PIO_MUST_USE               3

#define ZF_TICK_DURATION_US (TCP_TMR_INTERVAL * 1000)

#define CTPIO_MODE_SF 0
#define CTPIO_MODE_SF_NP -1
#define CTPIO_MODE_CT 64

/* Replace this with std::ciel2 when available (proposed for C++20) */
static unsigned ciel2(unsigned x) {
  zf_assert(x > 1);
  return 1 << (8 * sizeof(x) - __builtin_clz(x-1));
}


static int zf_stack_txring_alloc(zf_allocator* a, zf_stack* stack, int nicno)
{
  struct zf_stack_nic* nic = &stack->nic[nicno];
  unsigned len = ef_vi_transmit_capacity(zf_stack_nic_tx_vi(nic)) + 1;
  zf_assert(ciel2(len) == len); /* i.e. len is a power of 2 */

  void* p = zf_allocator_alloc(a, len * sizeof(zf_tx_req_id));
  if( ! p )
    return -ENOMEM;
  nic->tx_reqs = static_cast<zf_tx_req_id*>(p);
  nic->tx_reqs_mask = len - 1;
  std::fill_n(nic->tx_reqs, len, ZF_REQ_ID_INVALID);
  return 0;
}


static int zf_stack_check_attr(struct zf_stack* st, struct zf_attr* attr)
{
  /* If not an emu target, the interface must be specified */
  if( attr->emu == 0 && attr->interface == NULL ) {
    zf_log_stack_err(st, "Interface name must be specified\n");
    return -ENODEV;
  }
  if ( attr->rx_ring_max == 0 && attr->tx_ring_max == 0 ) {
    zf_log_stack_err(st, "Cannot create a stack with both RX and TX disabled.\n");
    return -EINVAL;
  }
  if( attr->tx_ring_max == 0 && attr->alt_count > 0 ) {
    zf_log_stack_err(st, "Cannot allocate TCP alternatives on a stack with TX disabled.\n");
    return -EINVAL;
  }
  if( attr->rx_ring_max == 0 && attr->rx_timestamping ) {
    zf_log_stack_err(st, "Cannot add timestamps to received packets on a stack with RX disabled.\n");
    return -EINVAL;
  }
  if( attr->tx_ring_max == 0 && attr->tx_timestamping ) {
    zf_log_stack_err(st, "Cannot report timestamps to transmitted packets on a stack with TX disabled.\n");
    return -EINVAL;
  }
  if( attr->max_udp_rx_endpoints <= 0 || attr->max_udp_tx_endpoints <= 0 ||
      attr->max_tcp_endpoints <= 0 || attr->max_tcp_listen_endpoints <= 0 ) {
    zf_log_stack_err(st, "Maximum numbers of endpoints must be positive.\n");
    return -EINVAL;
  }
  if( attr->max_udp_rx_endpoints - 1 > ZF_ZOCKET_ID_MAX ||
      attr->max_udp_tx_endpoints - 1 > ZF_ZOCKET_ID_MAX ||
      attr->max_tcp_endpoints - 1 > ZF_ZOCKET_ID_MAX ||
      attr->max_tcp_listen_endpoints - 1 > ZF_ZOCKET_ID_MAX ) {
    zf_log_stack_err(st,
                     "No more than %d endpoints of any type may be created.\n",
                     ZF_ZOCKET_ID_MAX + 1);
    return -EINVAL;
  }
  if( ! (attr->rx_ring_refill_batch_size >= 8) ||
      ! (attr->rx_ring_refill_batch_size % 8 == 0) ) {
    zf_log_stack_err(st, "Refill batch size must be non-zero multiple of 8.\n");
    return -EINVAL;
  }
  if( ! (attr->rx_ring_refill_interval >= 1) ) {
    zf_log_stack_err(st, "Rx ring refill interval must be positive.\n");
    return -EINVAL;
  }
  if( ! (attr->reactor_spin_count >= 1) ) {
    zf_log_stack_err(st, "Reactor spin count must be positive.\n");
    return -EINVAL;
  }
  if( attr->max_tcp_syn_backlog <= 0 ) {
    zf_log_stack_err(st, "Maximum SYN backlog must be positive.\n");
    return -EINVAL;
  }
  if( attr->alt_count < 0) {
    zf_log_stack_err(st,
                     "Alternative count must be zero or positive.\n");
    return -EINVAL;
  } else if((attr->alt_count > 0) &&
            (attr->alt_buf_size <= 0)) {
    zf_log_stack_err(st,
                     "Alternative buffer size must be positive.\n");
    return -EINVAL;
  }
  if( strlen(attr->interface) > IF_NAMESIZE - 1 ) {
    zf_log_stack_err(st, "Interface name too long.\n");
    return -EINVAL;
  }

  return 0;
}


static int zf_stack_init_alts(struct zf_stack_impl* sti, struct zf_attr* attr,
                              int nicno)
{
  unsigned long available_alts;
  int available_buffering;
  zf_stack* st = &sti->st;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  struct zf_stack_res_nic* sti_nic = &sti->nic[nicno];
  ef_vi* vi = zf_stack_nic_tx_vi(st_nic);

  int rc = ef_pd_capabilities_get(sti_nic->dh,
                                  &sti_nic->pd, sti_nic->dh,
                                  EF_VI_CAP_TX_ALTERNATIVES_VFIFOS,
                                  &available_alts);
  if( rc != 0 ) {
    zf_log_stack_err(st, "Failed to query available alternatives (rc = %d)\n",
                     rc);
    if( !(sti_nic->flags & ZF_RES_NIC_FLAG_TX_LL) )
      zf_log_stack_err(st, "Interface %s is not in low latency mode\n",
                       sti->nic[nicno].if_name);
    return rc;
  }

  if( (unsigned)attr->alt_count > available_alts ) {
    zf_log_stack_err(st, "Requested number of alternatives (%d) exceeds "
                     "number supported by hardware (%d)\n",
                     attr->alt_count, available_alts);
    rc = -EBUSY;
    return rc;
  }

  available_buffering =
    ef_pd_transmit_alt_query_buffering(vi, sti_nic->dh,
                                       &sti_nic->pd, sti_nic->dh,
                                       attr->alt_count);

  if( available_buffering < 0 ) {
    rc = available_buffering;
    zf_log_stack_err(st, "Failed to query available buffers (rc = %d)\n",
                     rc);
    return rc;
  }

  if( attr->alt_buf_size > available_buffering ) {
    zf_log_stack_err(st, "Requested amount of buffering (%d) exceeds "
                     "amount supported by hardware (%d)\n",
                     attr->alt_buf_size, available_buffering);
    rc = -EBUSY;
    return rc;
  }

  rc = zf_altbm_init(&sti->alt_buf_model, sti, nicno, attr);
  if( rc != 0 ) {
    zf_log_stack_err(st, "Failed to initialize buffer model (rc = %d)\n",
                     rc);
    return rc;
  }

  rc = ef_vi_transmit_alt_alloc(vi, sti_nic->dh,
                                attr->alt_count, attr->alt_buf_size);
  if( rc != 0 ) {
    if( rc == -ENOMEM ) {
      zf_log_stack_err(st,
                     "Failed to allocate alternatives: out of buffers\n");
      rc = -EBUSY;
    }
    else if( rc == -EBUSY ) {
      zf_log_stack_err(st,
                     "Failed to allocate alternatives: too many VIs in use\n");
    }
    else {
      zf_log_stack_err(st, "Failed to allocate alternative queues (rc = %d)\n",
                       rc);
    }
    return rc;
  }

  sti->n_alts = attr->alt_count;

  for( int i = 0; i < sti->n_alts; i++ )
    sti->alt[i].handle = i;

  return 0;
}


static int zf_stack_init_pio(struct zf_stack_impl* sti, struct zf_attr* attr,
                             int nicno)
{
  zf_stack* st = &sti->st;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  struct zf_stack_res_nic* sti_nic = &sti->nic[nicno];
  ef_vi* vi = zf_stack_nic_tx_vi(st_nic);

  if( (st_nic->vi.nic_type.arch == EF_VI_ARCH_EFCT ||
       st_nic->vi.nic_type.arch == EF_VI_ARCH_EF10CT) &&
      attr->pio >= PIO_MUST_USE ) {
    zf_log_stack_warn(st,
                      "PIO not supported by efct interface but pio=%d. "
                      "Not attempting to allocate PIO buffer.\n",
                      attr->pio);
    st_nic->pio.busy = 3;
    return 0;
  }

  /* Try to allocate. If alloc fails and we are in-strict mode (2) then fail */
  int rc = ef_pio_alloc(&sti_nic->pio, sti_nic->dh, &sti_nic->pd,
                        -1, sti_nic->dh);
  if( rc < 0 && attr->pio >= PIO_MUST_USE ) {
    zf_log_stack_err(st, "Failed to allocate PIO buffer (rc = %d)\n", rc);
    return rc;
  }

  /* it's okay to fail because pio = (1,2) */
  else if( rc < 0 ) {
    st_nic->pio.busy = 3;
    if( attr->pio == PIO_WARN_IF_NOT_AVAILABLE )
      zf_log_stack_warn(st,"Failed to allocate PIO buffer (rc = %d), "
                           "continuing since pio=2\n", rc);
  }

  /* pio allocation worked - proceed with pio setup as usual */
  else {
    zf_assert_equal(rc, 0);

    rc = ef_pio_link_vi(&sti_nic->pio, sti_nic->dh, vi, sti_nic->dh);

    /* we shouldn't fail here */
    if( rc < 0 ) {
      zf_log_stack_err(st, "Failed to link PIO buffer to VI (rc = %d)\n", rc);
      ef_pio_free(&sti_nic->pio, sti_nic->dh);
      return rc;
    }

    st_nic->pio.len = ef_vi_get_pio_size(vi);
  }

  return 0;
}


static int zf_stack_init_ctpio_stack_config(struct zf_stack_impl* sti,
                                            struct zf_attr* attr,
                                            int* ctpio_mode)
{
  zf_stack* st = &sti->st;

  if( attr->ctpio_mode != NULL ) {
    char dummy;
    if( ! strcmp(attr->ctpio_mode, "sf") ) {
      *ctpio_mode = CTPIO_MODE_SF;
    }
    else if( ! strcmp(attr->ctpio_mode, "sf-np") ) {
      *ctpio_mode = CTPIO_MODE_SF_NP;
    }
    else if( ! strcmp(attr->ctpio_mode, "ct") ) {
      *ctpio_mode = CTPIO_MODE_CT;
    }
    else if( sscanf(attr->ctpio_mode, "ct%u%c", ctpio_mode, &dummy) == 1 ) {
    }
    else {
      zf_log_stack_err(st,
                       "Bad ctpio_mode attribute; must be one of: sf sf-np "
                       "ct\n");
      return -EINVAL;
    }
  }
  else {
    zf_log_stack_err(st,
                     "Bad ctpio_mode attribute; must be one of: sf sf-np ct\n");
    return -EINVAL;
  }

  if( *ctpio_mode > 0 )
    st->config.ctpio_threshold = *ctpio_mode;
  else
    st->config.ctpio_threshold = EF_VI_CTPIO_CT_THRESHOLD_SNF;

  return 0;
}


static int zf_stack_init_ctpio_nic_config(zf_stack_impl* sti,
                                          struct zf_attr* attr,
                                          int ctpio_mode, int nicno, 
                                          unsigned* vi_flags)
{
  zf_stack* st = &sti->st;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  struct zf_stack_res_nic* sti_nic = &sti->nic[nicno];
  unsigned long ctpio_available;

  st_nic->ctpio_allowed = 0;

  /* Check whether the NIC supports CTPIO mode. */
  int rc = ef_pd_capabilities_get(sti_nic->dh,
                                  &sti_nic->pd, sti_nic->dh,
                                  EF_VI_CAP_CTPIO,
                                  &ctpio_available);
  if( rc != 0 ) {
    if( rc == -EOPNOTSUPP ) {
      ctpio_available = 0;
    }
    else {
      zf_log_stack_err(st, "Failed to query CTPIO capability (rc = %d)\n", rc);
      return rc;
    }
  }

  if( ctpio_available && attr->ctpio ) {
    *vi_flags |= EF_VI_TX_CTPIO;
    if( ctpio_mode == CTPIO_MODE_SF_NP )
      *vi_flags |= EF_VI_TX_CTPIO_NO_POISON;

    if( attr->ctpio_max_frame_len > 0 )
      st->ctpio_max_frame_len = attr->ctpio_max_frame_len;
    else if( ctpio_mode == CTPIO_MODE_CT )
      st->ctpio_max_frame_len = 1518;
    else
      st->ctpio_max_frame_len = 500;

    st_nic->ctpio_allowed = st->ctpio_max_frame_len;
  }
  else {
    /* CTPIO was requested, but is not supported by this NIC. */
    if( attr->ctpio == PIO_WARN_IF_NOT_AVAILABLE ) {
      zf_log_stack_warn(st, "CTPIO not available, continuing since ctpio=2\n",
                        rc);
    }
    else if( attr->ctpio == PIO_MUST_USE ) {
      zf_log_stack_err(st, "CTPIO not available.\n");
      rc = -EOPNOTSUPP;
      return rc;
    }

    /* We either requested no CTPIO or don't care if it's unavailable. */
  }

  return 0;
}


static void zf_stack_init_zock_resource(zf_stack_impl* sti,
                                        struct zf_attr* attr)
{
  zf_stack* st = &sti->st;

  /* This template emits code fragments that initialise the allocators for each
   * type of zocket. */
#define ZOCKET_BUF_ALLOC_INIT(obj_type) \
  zf_lazy_alloc_init(&sti->obj_type.alloc_state,                              \
                     attr->max_##obj_type##_endpoints - 1,                    \
                     sti->obj_type.resources);

  ZOCKET_BUF_ALLOC_INIT(udp_rx);
  ZOCKET_BUF_ALLOC_INIT(udp_tx);
  ZOCKET_BUF_ALLOC_INIT(tcp);
  ZOCKET_BUF_ALLOC_INIT(tcp_listen);

  /* Allocate RX-lookup tables. */
#define RX_TABLE_ALLOC_TMPL(table_index) \
  zf_rx_table_alloc(&sti->alloc, ZF_RX_TABLE_MAX_ENTRIES, \
                    &sti->rx_table_res[table_index]);\
  st->rx_table[table_index] = zf_rx_table_get(sti->rx_table_res[table_index]);

  RX_TABLE_ALLOC_TMPL(ZF_STACK_RX_TABLE_UDP)
  RX_TABLE_ALLOC_TMPL(ZF_STACK_RX_TABLE_TCP)
  RX_TABLE_ALLOC_TMPL(ZF_STACK_RX_TABLE_TCP_LISTEN)
}


/* This function initialises all stack state that has no resource
 * dependencies.
 */
static void zf_stack_init_state(struct zf_stack_impl* sti,
                                struct zf_attr* attr)
{
  zf_stack* st = &sti->st;

  sti->alloc_len = ZF_STACK_ALLOC_SIZE;
  sti->natural_sti_addr = sti;
  sti->pid = getpid();
  
  strncpy(sti->sti_on_version, onload_version_short(), sizeof(sti->sti_on_version));
  strncpy(sti->sti_zf_version, zf_version_short(), sizeof(sti->sti_zf_version));

  sti->waitable_fd.epoll_fd = -1;
  sti->waitable_fd.timer_fd = -1;

  st->reactor_spin_count = attr->reactor_spin_count;
  st->rx_ring_refill_interval = attr->rx_ring_refill_interval;
  sti->max_udp_rx_endpoints     = attr->max_udp_rx_endpoints;
  sti->max_udp_tx_endpoints     = attr->max_udp_tx_endpoints;
  sti->max_tcp_endpoints        = attr->max_tcp_endpoints;
  sti->max_tcp_listen_endpoints = attr->max_tcp_listen_endpoints;

  sti->tcp_syn_retries          = attr->tcp_syn_retries;
  sti->tcp_synack_retries       = attr->tcp_synack_retries;
  sti->tcp_retries              = attr->tcp_retries;
  sti->arp_reply_timeout        = attr->arp_reply_timeout;

  /* Unlike the other attributes, these are needed on the datapath and
   * so are in zf_stack rather than in zf_stack_impl. */
  st->tcp_initial_cwnd          = attr->tcp_initial_cwnd;
  st->tcp_alt_ack_rewind        = attr->tcp_alt_ack_rewind;

  st->flags = 0;
  if( ! attr->tcp_delayed_ack )
    st->flags |= ZF_STACK_FLAG_TCP_NO_DELACK;
  if( attr->tcp_wait_for_time_wait )
    st->flags |= ZF_STACK_FLAG_TCP_WAIT_FOR_TIME_WAIT;

  st->config.tcp_timewait_ticks = attr->tcp_timewait_ms / TCP_TMR_INTERVAL;
  st->config.tcp_finwait_ticks = attr->tcp_finwait_ms / TCP_TMR_INTERVAL;

  if( attr->tcp_finwait_ms == 0 )
    st->flags |= ZF_STACK_FLAG_TCP_FIN_WAIT_TIMEOUT_DISABLED;

  zf_timer_wheel_init(&st->times.wheel, 1000);

  st->future_nic_id = zf_stack::FUTURE_NIC_INVALID;

  /* The stack is quiescent to begin with. */
  zf_waitable_init(&st->w);
  zf_muxer_mark_waitable_ready(&st->w, EPOLLSTACKHUP);
  st->busy_refcount = 0;

  zf_allocator_init(&sti->alloc,
                    ZF_STACK_ALLOC_SIZE - (sti->alloc.bytes - (char*)sti));

  /* Allocate zocket buffers. */
  zf_stack_init_zock_resource(sti, attr);

  zf_lazy_alloc_init(&sti->muxer.alloc_state, zf_stack::MAX_MUXER_COUNT - 1,
                     sti->muxer.resources);

  st->magic = zf_stack::MAGIC_VALUE;
}


static int zf_stack_init_nic_capabilities(struct zf_stack* st, int nicno)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  unsigned long vlan_filters;
  unsigned long variant;
  ef_driver_handle dh = sti->nic[nicno].dh;
  ef_pd* pd = &sti->nic[nicno].pd;
  int rc;

  sti->nic[nicno].flags = 0;

  rc = ef_pd_capabilities_get(dh, pd, dh, EF_VI_CAP_RX_FW_VARIANT, &variant);
  if( rc != 0 ) {
    zf_log_stack_err(st, "Failed to query RX mode for interface %s (rc %d)\n",
                         sti->nic[nicno].if_name, rc);
    return rc;
  }
  else if( variant != MC_CMD_GET_CAPABILITIES_OUT_RXDP_LOW_LATENCY &&
           variant != MC_CMD_GET_CAPABILITIES_OUT_RXDP ) {
    zf_log_stack_err(st, "Interface %s is not in supported mode for RX (%d).\n",
                     sti->nic[nicno].if_name, variant);
    return -EOPNOTSUPP;
  }
  if( variant == MC_CMD_GET_CAPABILITIES_OUT_RXDP_LOW_LATENCY )
    sti->nic[nicno].flags |= ZF_RES_NIC_FLAG_RX_LL;

  rc = ef_pd_capabilities_get(dh, pd, dh, EF_VI_CAP_TX_FW_VARIANT, &variant);
  if( rc != 0 ) {
    zf_log_stack_err(st, "Failed to query TX mode for interface %s (rc %d)\n",
                         sti->nic[nicno].if_name, rc);
    return rc;
  }
  else if( variant != MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY &&
           variant != MC_CMD_GET_CAPABILITIES_OUT_TXDP ) {
    zf_log_stack_err(st, "Interface %s is not in supported mode for TX (%d).\n",
                     sti->nic[nicno].if_name, variant);
    return -EOPNOTSUPP;
  }
  if( variant == MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY )
    sti->nic[nicno].flags |= ZF_RES_NIC_FLAG_TX_LL;

  rc = ef_pd_capabilities_get(dh, pd, dh, EF_VI_CAP_RX_FILTER_TYPE_IP_VLAN,
                              &vlan_filters);
  if( rc == 0 && vlan_filters != 0 )
    sti->nic[nicno].flags |= ZF_RES_NIC_FLAG_VLAN_FILTERS;

  return 0;
}


int zf_stack_init_nic_resources(struct zf_stack_impl* sti,
                                struct zf_attr* attr, int nicno,
                                int ifindex, zf_if_info* if_cplane_info,
                                unsigned vi_flags, int ctpio_mode)
{
  zf_stack* st = &sti->st;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  struct zf_stack_res_nic* sti_nic = &sti->nic[nicno];
  int rc;

  /* Open driver. */
  rc = ef_driver_open(&sti_nic->dh);
  if( rc < 0 ) {
    zf_log_stack_err(st,
                     "Failed to open ef_vi driver handle (rc = %d)\n", rc);
    return rc;
  }

  strncpy(sti_nic->if_name, if_cplane_info->name, IF_NAMESIZE - 1);

  sti_nic->ifindex = ifindex;
  sti_nic->ifindex_sfc = if_cplane_info->ifindex;

  memcpy(&st_nic->mac_addr, &if_cplane_info->mac_addr,
         sizeof(st_nic->mac_addr));

  rc = ef_pd_alloc(&sti_nic->pd, sti_nic->dh, sti_nic->ifindex_sfc, EF_PD_DEFAULT);
  if( rc < 0 ) {
    zf_log_stack_err(st, "Failed to allocate PD (rc = %d)\n", rc);
    goto fail0;
  }

  rc = zf_stack_init_nic_capabilities(st, nicno);
  if( rc < 0 )
    goto fail1;

  if( !(sti->nic[nicno].flags & ZF_RES_NIC_FLAG_RX_LL) ||
      !(sti->nic[nicno].flags & ZF_RES_NIC_FLAG_TX_LL) ) {
    zf_log_stack_warn(st, "Interface %s is not in low latency mode.\n",
                          sti->nic[nicno].if_name);
    zf_log_stack_warn(st, "Low latency mode is recommended for best "
                          "latency with TCPDirect.\n");
  }

  if ( attr->tx_ring_max != 0 ) {
    rc = zf_stack_init_ctpio_nic_config(sti, attr, ctpio_mode, nicno, &vi_flags);
    if( rc < 0 )
      goto fail1;
  }

  if( ! attr->force_separate_tx_vi || attr->rx_ring_max == 0 ) {
    rc = ef_vi_alloc_from_pd(&st_nic->vi, sti_nic->dh, &sti_nic->pd,
                            sti_nic->dh, -1,
                            attr->rx_ring_max, attr->tx_ring_max, NULL, -1,
                            (enum ef_vi_flags) vi_flags);
    if( rc < 0 ) {
      zf_log_stack_err(st, "Failed to allocate VI (rc = %d)\n", rc);
      if( rc == -EPERM )
        zf_log_stack_err(st, "EPERM: does adapter have the correct license?\n");
      goto fail1;
    }
  }
  else {
    rc = ef_vi_alloc_from_pd(&st_nic->vi, sti_nic->dh, &sti_nic->pd,
                             sti_nic->dh, -1,
                             attr->rx_ring_max, 0, NULL, -1,
                             (enum ef_vi_flags) vi_flags);
    if( rc < 0 ) {
      zf_log_stack_err(st, "Failed to allocate RX VI (rc = %d)\n", rc);
      if( rc == -EPERM )
        zf_log_stack_err(st, "EPERM: does adapter have the correct license?\n");
      goto fail1;
    }
    rc = ef_vi_alloc_from_pd(&st_nic->tx_vi, sti_nic->dh, &sti_nic->pd,
                             sti_nic->dh, -1,
                             0, attr->tx_ring_max, NULL, -1,
                             (enum ef_vi_flags) vi_flags);
    if( rc < 0 ) {
      zf_log_stack_err(st, "Failed to allocate TX VI (rc = %d)\n", rc);
      if( rc == -EPERM )
        zf_log_stack_err(st, "EPERM: does adapter have the correct license?\n");
      goto fail1;
    }
  }

  ef_vi_receive_set_discards(&st_nic->vi,
      EF_VI_DISCARD_RX_L4_CSUM_ERR |
      EF_VI_DISCARD_RX_L3_CSUM_ERR |
      EF_VI_DISCARD_RX_ETH_FCS_ERR |
      EF_VI_DISCARD_RX_ETH_LEN_ERR |
      EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR |
      EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR |
      EF_VI_DISCARD_RX_L2_CLASS_OTHER |
      EF_VI_DISCARD_RX_L3_CLASS_OTHER |
      EF_VI_DISCARD_RX_L4_CLASS_OTHER 
  );

  if ( attr->rx_ring_max != 0 ) {
    /* For EFCT, we store the timestamp in a fake prefix when copying from
     * the shared rx buffer into our own packet buffer. */
    if( st_nic->vi.nic_type.arch == EF_VI_ARCH_EFCT ||
        st_nic->vi.nic_type.arch == EF_VI_ARCH_EF10CT )
      st_nic->rx_prefix_len = ES_DZ_RX_PREFIX_SIZE;
    else
      st_nic->rx_prefix_len = ef_vi_receive_prefix_len(&st_nic->vi);

    zf_assume(st_nic->rx_prefix_len == 0 ||
              st_nic->rx_prefix_len == ES_DZ_RX_PREFIX_SIZE);

    ef_vi_receive_set_buffer_len(&st_nic->vi, PKT_BUF_SIZE_USABLE);
  }

  zf_log_stack_info(st,
                    "rxq_size=%d txq_size=%d evq_size=%d rx_prefix_len=%d\n",
                    ef_vi_receive_capacity(&st_nic->vi),
                    ef_vi_transmit_capacity(zf_stack_nic_tx_vi(st_nic)),
                    ef_eventq_capacity(&st_nic->vi), st_nic->rx_prefix_len);

  if( attr->tx_ring_max != 0 && attr->pio ) {
    rc = zf_stack_init_pio(sti, attr, nicno);
    if( rc < 0 )
      goto fail2;
  }

  if( attr->alt_count > 0 ) {
    rc = zf_stack_init_alts(sti, attr, nicno);
    if( rc < 0 )
      goto fail3;
  }

  if ( attr->tx_ring_max != 0 ) {
    rc = zf_stack_txring_alloc(&sti->alloc, st, nicno);
    if( rc < 0 )
      goto fail4;
  }

  rc = zf_state.cp.register_intf(zf_state.cp_handle, ifindex, &sti->nic[nicno], 0);
  if( rc < 0 ) {
    zf_log_stack_err(st, "Failed to register cplane intf %d (rc = %d)\n", ifindex, rc);
    goto fail4;
  }

  ci_sllist_init(&st_nic->pollout_req_list);

  st->nics_n++;

  return 0;

 fail4:
  if( sti->n_alts > 0 )
    ef_vi_transmit_alt_free(&st_nic->vi, sti_nic->dh);
 fail3:
  if( sti_nic->pio.pio_io ) {
    ef_pio_unlink_vi(&sti_nic->pio, sti_nic->dh, zf_stack_nic_tx_vi(st_nic), sti_nic->dh);
    ef_pio_free(&sti_nic->pio, sti_nic->dh);
  }
 fail2:
  ef_vi_free(&st_nic->vi, sti_nic->dh);
 fail1:
  ef_pd_free(&sti_nic->pd, sti_nic->dh);
 fail0:
  ef_driver_close(sti_nic->dh);
  return rc;
}

static int zf_stack_init_nic_pool(struct zf_stack_impl* sti,
                                  struct zf_attr* attr, int nicno)
{
  zf_stack* st = &sti->st;
  struct zf_stack_nic* st_nic = &st->nic[nicno];
  int rc;

  rc = zf_pool_map(st, &sti->pool_res, nicno);
  if( rc < 0 )
    return rc;

  if( attr->rx_ring_max != 0 ) {
    st_nic->rx_ring_refill_batch_size = attr->rx_ring_refill_batch_size;
    zf_stack_refill_rx_ring(st, nicno, ZF_STACK_REFILL_MAX);
  }

  return rc;
}


#ifndef ZF_DEVEL
static
#endif
int zf_stack_check_vi_compatibility(zf_stack* st, const zf_attr* attr,
                                    ef_vi* vi_a, ef_vi* vi_b)
{
  if( ef_vi_receive_prefix_len(vi_a) !=
      ef_vi_receive_prefix_len(vi_b) ) {
    zf_log_stack_err(st, "VI has mismatched prefix length\n");
    return -EDOM;
  }

  return 0;
}


int zf_stack_alloc(struct zf_attr* attr, struct zf_stack** stack_out)
{
  zf_stack* st = NO_STACK;

  /* Check there's nothing obviously wrong with the config. */
  int rc = zf_stack_check_attr(st, attr);
  if( rc < 0 )
    return rc;

  /* Allocate memory for the stack.  Unit tests hook here and assume that
   * we do this before querying the contol plane. */
  auto sti = (struct zf_stack_impl*) alloc_huge(ZF_STACK_ALLOC_SIZE);
  if( sti == NULL ) {
    zf_log_stack_err(st, "Failed to allocate huge page for stack, "
                         "are huge pages available?\n");
    return -ENOMEM;
  }

  memset(sti, 0, sizeof(*sti));
  zf_stack_init_state(sti, attr);
  strncpy(sti->sti_if_name, attr->interface, IF_NAMESIZE - 1);

  st = &sti->st;

  /* Determine where we want to create this stack. */
  int ifindex = zf_cplane_get_ifindex(attr->interface);
  if( ifindex < 0 )  {
    rc = ifindex;
    goto fail1;
  }

  sti->onload_dh = -1;
  rc = oo_fd_open(&sti->onload_dh);
  if( rc < 0 )
    goto fail1;

  /* Register the buffer so that stackdump can map it. dshm segments don't
   * need to be freed explicitly, so success here doesn't affect the later
   * cleanup path.
   */
  sti->shm_id = -1;
  rc = oo_dshm_register(sti->onload_dh, OO_DSHM_CLASS_ZF_STACK, sti,
                        ZF_STACK_ALLOC_SIZE);
  if( rc < 0 ) {
    zf_log_stack_err(st, "Failed to register stack shm (rc = %d)\n", rc);
    goto fail2;
  }
  sti->shm_id = rc;

  rc = zftl_listenq_init(&sti->alloc, &st->listenq, attr->max_tcp_syn_backlog);
  if( rc != 0 )
    goto fail2;

  if( (rc = zf_timekeeping_init(&st->times.time, ZF_TICK_DURATION_US)) != 0 )
    goto fail2;

  unsigned vi_flags;
  vi_flags = EF_VI_FLAGS_DEFAULT;

  if( attr->alt_count > 0 )
    vi_flags |= EF_VI_TX_ALT;

  if( attr->rx_timestamping )
    vi_flags |= EF_VI_RX_TIMESTAMPS;

  if( attr->tx_timestamping )
    vi_flags |= EF_VI_TX_TIMESTAMPS;

  int ctpio_mode;
  rc = zf_stack_init_ctpio_stack_config(sti, attr, &ctpio_mode);
  if( rc < 0 )
    goto fail2;

  /* Query the nominated interface for the stack. */
  zf_if_info if_cplane_info;
  rc = zf_cplane_get_iface_info(ifindex, &if_cplane_info);
  if( rc < 0 ) {
    zf_log_stack_err(st, "Failed to query interface (rc = %d)\n", rc);
    goto fail2;
  }

  st->encap_type = if_cplane_info.encap;
  sti->sti_ifindex = ifindex;
  sti->sti_ctpio = attr->ctpio;
  sti->sti_tx_ring_max = attr->tx_ring_max;
  sti->sti_alt_buf_size = attr->alt_buf_size;
  sti->sti_alt_count = attr->alt_count;
  sti->sti_rx_ring_max = attr->rx_ring_max;
  sti->sti_rx_ring_refill_batch_size = attr->rx_ring_refill_batch_size;
  sti->sti_rx_timestamping = attr->rx_timestamping;
  sti->sti_tcp_alt_ack_rewind = attr->tcp_alt_ack_rewind;
  sti->sti_tcp_delayed_ack = attr->tcp_delayed_ack;
  sti->sti_tcp_finwait_ms = attr->tcp_finwait_ms;
  sti->sti_tcp_timewait_ms = attr->tcp_timewait_ms;
  sti->sti_tcp_wait_for_time_wait = attr->tcp_wait_for_time_wait; 
  sti->sti_tx_timestamping = attr->tx_timestamping;
  sti->sti_ctpio_max_frame_len = attr->ctpio_max_frame_len;
  sti->sti_force_separate_tx_vi = attr->force_separate_tx_vi;
  sti->sti_pio = attr->pio;
  sti->sti_reactor_spin_count = attr->reactor_spin_count;
  sti->sti_rx_ring_refill_interval = attr->rx_ring_refill_interval;
  sti->sti_udp_ttl = attr->udp_ttl;
  sti->sti_log_level = attr->log_level;
  strncpy(sti->sti_ctpio_mode, attr->ctpio_mode, 8);
  if( st->encap_type & EF_CP_ENCAP_F_VLAN )
    sti->sti_vlan_id = if_cplane_info.vlan_id;
  else
    sti->sti_vlan_id = ZF_NO_VLAN;
  memcpy(sti->sti_src_mac, if_cplane_info.mac_addr, ETH_ALEN);

  /* Check whether the interface can be accelerated.  This includes non-SFC
   * interfaces, bonds with non-SFC slaves, and bonds with no slaves. */
  if( if_cplane_info.hw_ifindices_n == 0 ) {
    zf_log_stack_err(st, "Interface %s is not acceleratable.\n",
                     attr->interface);
    rc = -EIO;
    goto fail2;
  }

  if( st->encap_type & EF_CP_ENCAP_F_BOND ) {
    rc = zf_stack_init_bond_state(st, &if_cplane_info);
    if( rc < 0 ) {
      zf_log_stack_err(st, "Unable to query bond details: %s.\n", strerror(-rc));
      goto fail2;
    }
  }

  /* If we have more than one hwport, some features are disallowed as a matter
   * of policy. */
  if( if_cplane_info.hw_ifindices_n > 1 ) {
    /* We disallow alternatives because they are a limited resource and because
     * they would interact very awkwardly with bond failover. */
    if( attr->alt_count > 0 ) {
      zf_log_stack_err(st, "Alternatives are not supported on stacks with "
                           "multiple interfaces.\n");
      rc = -EINVAL;
      goto fail2;
    }
  }

  /* Resolve the hwports for the interface and create a VI on each. */
  for( int nicno = 0; nicno < if_cplane_info.hw_ifindices_n; ++nicno ) {
    zf_if_info hwport_cplane_info;
    int hwport_ifindex = if_cplane_info.hw_ifindices[nicno];

    rc = zf_cplane_get_iface_info(hwport_ifindex, &hwport_cplane_info);
    if( rc < 0 ) {
      zf_log_stack_err(st,
                       "Failed to query interface for ifindex %d (rc = %d)\n",
                       hwport_ifindex, rc);
      goto fail3;
    }

    rc = zf_stack_init_nic_resources(sti, attr, nicno, hwport_ifindex,
                                     &hwport_cplane_info, vi_flags,
                                     ctpio_mode);
    if( rc < 0 )
      goto fail3;
  }

  /* Now we have the VIs, can correctly size the buffer pool */
  rc = zf_pool_alloc(&sti->pool_res, &st->pool, st,
                     attr->n_bufs ? :
                     zf_stack_max_pkt_buf_usage(sti));
  if( rc < 0 ) {
    zf_log_stack_err(st,
                     "Failed to allocate packet-buffer pool (rc = %d)\n", rc);
    goto fail3;
  }

  /* And then map the buffers to each interface */
  for( int nicno = 0; nicno < st->nics_n; ++nicno ) {
    rc = zf_stack_init_nic_pool(sti, attr, nicno);
    if( rc != 0 ) {
      zf_log_stack_err(st, "failed to init pool for %s\n",
                       sti->nic[nicno].if_name);
      goto fail4;
    }
  }

  /* We mandate some uniformity properties across VIs.  Check that they're
   * satisfied. */
  for( int nicno = 1; nicno < st->nics_n; ++nicno ) {
    rc = zf_stack_check_vi_compatibility(st, attr, &st->nic[0].vi,
                                         &st->nic[nicno].vi);
    if( rc != 0 ) {
      zf_log_stack_err(st, "%s and %s are not compatible for bonding\n",
                       sti->nic[0].if_name, sti->nic[nicno].if_name);
      goto fail4;
    }
  }

  if( attr->tx_ring_max != 0 && attr->tx_timestamping ) {
    unsigned len = 0;
    for( int i = 0; i < st->nics_n; i++ )
      len += ef_vi_transmit_capacity(zf_stack_nic_tx_vi(st, i));
    rc = zf_tx_reports::alloc_queue(&st->tx_reports, &sti->alloc, len);
    if( rc < 0 )
      goto fail4;
  }
  if( attr->name )
    strncpy(st->st_name, attr->name, sizeof(st->st_name));
  else
    sprintf(st->st_name, "%s/%03x", attr->interface, st->nic[0].vi.vi_i);

  *stack_out = st;
  return 0;

 fail4:
  zf_pool_free(st, &sti->pool_res);
 fail3:
  for( int i = 0; i < st->nics_n; i++ )
    zf_stack_free_nic_resources(sti, i);
 fail2:
  oo_fd_close(sti->onload_dh);
 fail1:
  free_huge(sti, sti->alloc.max_ptr - (char*)sti);
  return rc;
}
