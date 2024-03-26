/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**\file ZF rx - resource management and slow path */

#ifndef __ZF_RX_RES_H__
#define __ZF_RX_RES_H__

#include <zf_internal/utils.h>
#include <zf_internal/res.h>

#include <etherfabric/vi.h>

#include <netinet/in.h>

struct bind_state;
/* hw resources and slow state */
struct zf_rx_res {
  /* List of all filter state for this zocket.  The list is managed by the
   * RX-lookup table and its contents is opaque to this structure. */
  ci_dllist filter_list;

  struct zf_generic_res generic_res;

  /* This is used before filters are installed, where we don't have a table
   * to store it.  This is only needed for TCP as UDP installs filters
   * immediately upon bind.
   */
  struct bind_state* bs;
};


struct zf_rx;
ZF_COLD extern void
zfr_init(struct zf_rx* rx);

struct zf_rx_res;
ZF_COLD extern void
zfrr_init(struct zf_rx_res* rx_res);

struct zf_stack;
ZF_COLD extern int
zfrr_reserve_port(struct zf_stack* st, struct zf_rx_res* rx_res, int proto,
                  const struct sockaddr_in* laddr,
                  const struct sockaddr_in* raddr);
ZF_COLD extern int
zfrr_release_port(struct zf_stack* st, struct zf_rx_res* rx_res);

struct zf_rx_table_res;
struct zf_rx_table;

typedef uint32_t zfrr_nic_mask;
const zfrr_nic_mask ZFRR_ALL_NICS = (uint32_t) -1;

ZF_COLD extern int
zfrr_add(struct zf_stack* st, struct zf_rx_res* rx_res, uint16_t zocket_id,
         zfrr_nic_mask nics, int proto, struct zf_rx_table_res* rx_table_res,
         struct zf_rx_table* table, struct sockaddr_in* laddr,
         const struct sockaddr_in* raddr, int hw_filter);

ZF_COLD extern int
zfrr_remove(struct zf_stack* stack, struct zf_rx_table_res* rx_table_res,
            int nic, struct sockaddr_in* laddr, struct sockaddr_in* raddr);

ZF_COLD extern int
zfrr_remove_all(struct zf_stack* stack, struct zf_rx_table_res* rx_table_res,
                ci_dllist* list);

ZF_COLD extern int
zfr_drop_queue(zf_pool* pool, struct zf_rx* rx);

ZF_COLD extern void
zfr_queue_coalesce(struct zf_rx* rx, struct zf_stack* stack);

ZF_COLD extern void
zf_rx_dump(struct zf_rx* rx);

#endif /* __ZF_RX_RES_H__ */
