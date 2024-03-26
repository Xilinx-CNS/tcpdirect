/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF stack - non-critical path data and code/resource management */

#ifndef __ZF_STACK_IMPL_H__
#define __ZF_STACK_IMPL_H__

#include <zf_internal/zf_pool_res.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/tx.h>
#include <zf_internal/lazy_alloc.h>
#include <zf_internal/rx_table.h>

#include <zf_internal/zf_stack.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/tx_res.h>
#include <zf_internal/tcp.h>
#include <zf_internal/zf_alts.h>

#include <zf_internal/private/zf_stack_def.h>

#include <etherfabric/pd.h>
#include <etherfabric/pio.h>


extern ef_driver_handle
zf_stack_get_driver_handle(struct zf_stack* st, int nic);


extern int
zf_stack_get_onload_handle(struct zf_stack*);


extern struct ef_pd*
zf_stack_get_pd(struct zf_stack* st, int nic);


/* These functions are emitted by ENDPOINT_ALLOC_TMPL. */
extern ZF_COLD int
zf_stack_alloc_udp_rx(struct zf_stack* st, struct zf_udp_rx** rx);
extern ZF_COLD int
zf_stack_free_udp_rx(struct zf_stack* st, struct zf_udp_rx* rx);
extern ZF_COLD void
zf_stack_udp_rx_to_res(struct zf_stack* st, struct zf_udp_rx* rx,
                       struct zf_rx_res** rx_res);
extern ZF_COLD int
zf_stack_udp_rx_is_allocated(struct zf_stack* st, struct zf_udp_rx* rx);



/* These functions are emitted by ENDPOINT_ALLOC_TMPL. */
extern ZF_COLD int
zf_stack_alloc_udp_tx(struct zf_stack* st,
                      struct zf_udp_tx** tx);
extern ZF_COLD int
zf_stack_free_udp_tx(struct zf_stack* st, struct zf_udp_tx* tx);
extern ZF_COLD void
zf_stack_udp_tx_to_res(struct zf_stack* st, struct zf_udp_tx* tx,
                       struct zf_tx_res** tx_res);
extern ZF_COLD int
zf_stack_udp_tx_is_allocated(struct zf_stack* st, struct zf_udp_tx* tx);


/* These functions are emitted by ENDPOINT_ALLOC_TMPL. */
extern ZF_COLD void
zf_stack_tcp_to_res(struct zf_stack* st, struct zf_tcp* tcp,
                    struct zf_rx_res** tcp_res);
extern ZF_COLD int
zf_stack_alloc_tcp(struct zf_stack* st,
                   struct zf_tcp** tcp);
extern ZF_COLD int
zf_stack_free_tcp(struct zf_stack* st, struct zf_tcp* tcp);

extern ZF_COLD int
zf_stack_tcp_is_allocated(struct zf_stack* st, struct zf_tcp* tcp);


/* These functions are emitted by ENDPOINT_ALLOC_TMPL. */
extern ZF_COLD void
zf_stack_tcp_listen_state_to_res(struct zf_stack* st,
                                 struct zf_tcp_listen_state* tls,
                                 struct zf_rx_res** tcp_res);
extern ZF_COLD int
zf_stack_alloc_tcp_listen_state(struct zf_stack* st,
                                struct zf_tcp_listen_state** tls);
extern ZF_COLD int
zf_stack_free_tcp_listen_state(struct zf_stack* st,
                               struct zf_tcp_listen_state* tls);
extern ZF_COLD int
zf_stack_tcp_listen_state_is_allocated(struct zf_stack* st,
                                       struct zf_tcp_listen_state* tls);


/* These functions are emitted by ENDPOINT_ALLOC_TMPL. */
extern ZF_COLD int
zf_stack_alloc_muxer(struct zf_stack* st,
                     zf_muxer_set** muxer);
extern ZF_COLD int
zf_stack_free_muxer(struct zf_stack* st, zf_muxer_set* muxer);


extern ZF_COLD struct zf_rx_table_res*
zf_stack_get_rx_table(struct zf_stack* st, int rx_table_id);


enum zf_reactor_purge_status {
  ZF_REACTOR_PURGE_STATUS_IDLE = 0x0,
  ZF_REACTOR_PURGE_STATUS_RX = 0x1,
  ZF_REACTOR_PURGE_STATUS_TX = 0x2,
};

extern ZF_COLD int
zf_reactor_purge(struct zf_stack* st);

extern int
zf_reactor_process_timers(struct zf_stack* st);


#endif /* ZF_STACK_IMPL */
