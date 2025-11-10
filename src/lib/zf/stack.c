/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF stack non performance critical state and routines */


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
#include <zf_internal/private/zf_license.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/mman.h>

#include <ci/efhw/mc_driver_pcol.h>

#include <onload/driveraccess.h>


#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif


void* __alloc_huge(size_t size)
{
  unsigned mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_HUGE_2MB;
  auto ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);
  if( ptr == MAP_FAILED )
    return NULL;
  zf_assert_equal((ptr - ((char*)NULL)) & (HUGE_PAGE_SIZE - 1), 0);
  return ptr;
}

void __free_huge(void* ptr, size_t size)
{
  int rc = munmap(ptr, size);
  zf_assert_equal(rc, 0);
}


unsigned zf_stack_max_pkt_buf_usage(zf_stack_impl* sti)
{
  auto st = &sti->st;
  unsigned n =
    sti->max_udp_rx_endpoints * zf_udp_rx_max_pkt_bufs_usage(st) +
    sti->max_udp_tx_endpoints * zf_udp_tx_max_pkt_bufs_usage(st) +
    sti->max_tcp_endpoints * zf_tcp_max_pkt_bufs_usage(st) +
    sti->max_tcp_listen_endpoints * zf_tcp_listen_max_pkt_bufs_usage(st) +
    sti->n_alts * zf_alternatives_max_pkt_bufs_usage(st) +
    2 /* allow this many pkt buffers being prepared to send and store
       * (separate copies) */;

  for( int nicno = 0; nicno < st->nics_n; ++nicno ) {
    struct zf_stack_nic* st_nic = &st->nic[nicno];
    n += ef_vi_receive_capacity(&st_nic->vi) +
      ef_vi_transmit_capacity(zf_stack_nic_tx_vi(st_nic));
  }

  return n;
}


template<typename Zocket, typename Resource, typename FreeZocket>
static void purge_zockets(struct zf_stack* stack, Zocket* zockets,
                          int num_zockets,
                          void (*to_res)(struct zf_stack*, Zocket*, Resource**),
                          FreeZocket free_zocket)
{
  for( Zocket* zocket = zockets; zocket < zockets + num_zockets; ++zocket ) {
    Resource* res;
    to_res(stack, zocket, &res);
    if( res->generic_res.res_flags & ZF_GENERIC_RES_ALLOCATED )
      free_zocket(zocket);
  }
}

#ifndef NDEBUG
template<typename Zocket, typename Resource>
static void
check_purged_zockets(struct zf_stack* stack, Zocket* zockets,
                     int num_zockets,
                     void (*to_res)(struct zf_stack*, Zocket*, Resource**))
{
  for( Zocket* zocket = zockets; zocket < zockets + num_zockets; ++zocket ) {
    Resource* res;
    to_res(stack, zocket, &res);
    zf_assert_nflags(res->generic_res.res_flags, ZF_GENERIC_RES_ALLOCATED);
  }
}
#endif


int zf_stack_free_nic_resources(struct zf_stack_impl* sti, int nicno)
{
  zf_stack* stack = &sti->st;
  struct zf_stack_nic* st_nic = &stack->nic[nicno];
  struct zf_stack_res_nic* sti_nic = &sti->nic[nicno];
  int rc = 0;
  int rc1;
  ef_vi* tx_vi = zf_stack_nic_tx_vi(st_nic);

  /* If anything fails, warn about the first failure only, and then try the
   * rest of the tear-down quietly.
   */
  if( sti->n_alts > 0 ) {
    rc1 = ef_vi_transmit_alt_free(tx_vi, sti_nic->dh);
    if( rc1 < 0 && rc == 0 ) {
      zf_log_stack_warn(stack,
                        "Failed to free alternatives for VI %03x (rc = %d)\n",
                        tx_vi->vi_i, rc1);
      rc = rc1;
    }
  }

  /* Check if pio was allocated before freeing/unlinking (see attribute pio) */
  if( sti_nic->pio.pio_io ) {
    rc1 = ef_pio_unlink_vi(&sti_nic->pio, sti_nic->dh,
                           tx_vi, sti_nic->dh);
    if( rc1 < 0 && rc == 0 ) {
      zf_log_stack_warn(stack,
                        "Failed to unlink PIO buffer from VI %03x (rc = %d)\n",
                        tx_vi->vi_i, rc1);
      rc = rc1;
    }
    rc1 = ef_pio_free(&sti_nic->pio, sti_nic->dh);
    if( rc1 < 0 && rc == 0 ) {
      zf_log_stack_warn(stack,
                        "Failed to free PIO buffer for VI %03x (rc = %d)\n",
                        tx_vi->vi_i, rc1);
      rc = rc1;
    }
  }

  rc1 = ef_vi_free(&st_nic->vi, sti_nic->dh);
  if( rc1 < 0 && rc == 0 ) {
    zf_log_stack_warn(stack, "Failed to free VI %03x (rc = %d)\n",
                      st_nic->vi.vi_i, rc1);
    rc = rc1;
  }

  rc1 = ef_pd_free(&sti_nic->pd, sti_nic->dh);
  if( rc1 < 0 && rc == 0 ) {
    zf_log_stack_warn(stack, "Failed to free PD (rc = %d)\n", rc1);
    rc = rc1;
  }

  /* This will clean up all of our hardware state. */
  rc1 = ef_driver_close(sti_nic->dh);
  if( rc1 < 0 && rc == 0 ) {
    zf_log_stack_warn(stack, "Failed to close VI file descriptor %d "
                      "(rc=%d)\n", rc1);
    rc = rc1;
  }

  return rc;
}


/* Frees a stack.  This is not safe on partially-initialised stacks. */
int zf_stack_free(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, stack);
  int rc = 0, rc1;

  zf_log_stack_info(stack, "%s()\n", __func__);
  /* Closing the Onload handle will unregister all dshm segments. */
  if( sti->onload_dh >= 0 ) {
    rc = oo_fd_close(sti->onload_dh);
    zf_assert_equal(rc, 0);
  }

  /* Free all zockets first.  This will cause filters and any other associated
   * resources to be freed.  Any connections associated with them will vanish
   * into thin air.
   *
   * Listening zockets should be freed berfore connected TCP zockets to ensure
   * that non-accepted connections are handled properly.
   */
  purge_zockets(stack, stack->tcp_listen, sti->max_tcp_listen_endpoints,
                zf_stack_tcp_listen_state_to_res,
                [stack] (struct zf_tcp_listen_state* listener)
                  { if( ! (listener->tls_flags & ZF_LISTEN_FLAGS_SHUTDOWN) )
                      zftl_free(&listener->tl); });

  purge_zockets(stack, stack->tcp, sti->max_tcp_endpoints, zf_stack_tcp_to_res,
                [stack] (struct zf_tcp* tcp)
                  { zf_tcp_on_stack_free(stack, tcp); });
#ifndef NDEBUG
  /* We expect that all references to the TCP zockets are released now */
  check_purged_zockets(stack, stack->tcp_listen,
                       sti->max_tcp_listen_endpoints,
                       zf_stack_tcp_listen_state_to_res);
  check_purged_zockets(stack, stack->tcp, sti->max_tcp_endpoints,
                       zf_stack_tcp_to_res);
#endif

  purge_zockets(stack, stack->udp_rx, sti->max_udp_rx_endpoints,
                zf_stack_udp_rx_to_res,
                [] (struct zf_udp_rx* rx) { zfur_free(&rx->handle); });

  purge_zockets(stack, stack->udp_tx, sti->max_udp_tx_endpoints,
                zf_stack_udp_tx_to_res,
                [] (struct zf_udp_tx* tx) { zfut_free(&tx->handle); });
#ifndef NDEBUG
  /* We expect that all references to the TCP zockets are released now */
  check_purged_zockets(stack, stack->udp_rx, sti->max_udp_rx_endpoints,
                       zf_stack_udp_rx_to_res);
  check_purged_zockets(stack, stack->udp_tx, sti->max_udp_tx_endpoints,
                       zf_stack_udp_tx_to_res);
#endif

  stack->magic = zf_stack::MAGIC_DESTROYED_VALUE;

  zftl_listenq_fini(&sti->alloc, &stack->listenq);

  zf_rx_table_free(&sti->alloc, sti->rx_table_res[ZF_STACK_RX_TABLE_TCP_LISTEN]);
  zf_rx_table_free(&sti->alloc, sti->rx_table_res[ZF_STACK_RX_TABLE_TCP]);
  zf_rx_table_free(&sti->alloc, sti->rx_table_res[ZF_STACK_RX_TABLE_UDP]);

  /* Check for packet leak */
#ifndef NDEBUG
  if( sti->n_alts == 0 && stack->nic[0].vi.inited ) {
    unsigned pkts_accounted = 0;
    for( int nicno = 0; nicno < stack->nics_n; ++nicno ) {
      /* PIO does not use packets, but it is accounted for in transmit fill
       * level. Set to zero if PIO was not allocated. */
      unsigned pkts_in_pio = sti->nic[nicno].pio.pio_io ?
        __builtin_popcount(stack->nic[nicno].pio.busy) : 0;
      unsigned tx_packets = ef_vi_transmit_fill_level(zf_stack_nic_tx_vi(stack, nicno)) - pkts_in_pio;
      unsigned rx_packets = ef_vi_receive_fill_level(&stack->nic[nicno].vi);

      /* For X3 ef_vi_transmit_fill_level and PIO states are bogus */
      if( zf_stack_nic_tx_vi(stack, nicno)->nic_type.arch != EF_VI_ARCH_EFCT &&
          zf_stack_nic_tx_vi(stack, nicno)->nic_type.arch != EF_VI_ARCH_EF10CT)
        pkts_accounted += tx_packets;

      if( stack->nic[nicno].vi.nic_type.arch != EF_VI_ARCH_EFCT &&
          stack->nic[nicno].vi.nic_type.arch != EF_VI_ARCH_EF10CT)
        pkts_accounted += rx_packets;

      zf_log_stack_trace(stack,
                         "%s: VI %d: busy pkts=%d vs %d: rx_hw=%d tx_hw=%d "
                         "pio=%d\n", __func__, nicno, stack->pool.first_free,
                         pkts_accounted,
                         rx_packets,
                         tx_packets,
                         pkts_in_pio);
    }
    zf_assert_equal(pkts_accounted, stack->pool.first_free);
  }
#endif

  zf_waitable_fd_free(stack);

  /* Free ef_vi resources.  It's not necessary as such to free the HW
   * resources, as the driver does this when the last reference to the handle
   * goes away, but there are two reasons why we need to do the cleanup anyway:
   * the first is that there is some host memory to be freed, and the second is
   * that there are mappings of the char device that need to be torn down,
   * which otherwise would keep a reference to the char device even after we've
   * closed its fd.
   */
  for( int i = 0; i < stack->nics_n; i++ ) {
    rc1 = zf_stack_free_nic_resources(sti, i);
    if( rc1 < 0 && rc == 0 ) {
      zf_log_stack_warn(stack, "Failed to free NIC %d VI %03x (rc = %d)\n",
                        i, stack->nic[i].vi.vi_i, rc1);
      rc = rc1;
    }
  }

  /* Free remaining state. */

  rc1 = zf_pool_free(stack, &sti->pool_res);
  if( rc1 < 0 && rc == 0 ) {
    zf_log_stack_warn(stack,
                      "Failed to free packet-buffer pool (rc = %d)\n", rc1);
    rc = rc1;
  }

  free_huge(sti, sti->alloc.max_ptr - (char*)sti);

  return rc;
}


ef_driver_handle
zf_stack_get_driver_handle(struct zf_stack* st, int nic)
{
  struct zf_stack_impl* sti = (struct zf_stack_impl*) st;
  return sti->nic[nic].dh;
}


int
zf_stack_get_onload_handle(struct zf_stack* st)
{
  struct zf_stack_impl* sti = (struct zf_stack_impl*) st;
  return sti->onload_dh;
}


struct ef_pd*
zf_stack_get_pd(struct zf_stack* st, int nic)
{
  struct zf_stack_impl* sti = (struct zf_stack_impl*) st;
  return &sti->nic[nic].pd;
}


#define RES_TYPE(alloc_name) \
  typeof(&((struct zf_stack_impl*) 0)->alloc_name.resources[0])
#define OBJ_TYPE(alloc_name) \
  typeof(&((struct zf_stack*) 0)->alloc_name[0])

/* This template emits boilerplate functions for allocating and freeing
 * zockets, and for retrieving the slow-path ("resource") data for a zocket
 * given its fast-path data. */
#define ENDPOINT_ALLOC_TMPL(obj_type, alloc_name) \
  void                                                                        \
  zf_stack_##obj_type##_to_res(struct zf_stack* st,                           \
                               OBJ_TYPE(alloc_name) obj,                      \
                               RES_TYPE(alloc_name)* res_out)                 \
  {                                                                           \
    struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);   \
    *res_out = &sti->alloc_name.resources[obj - st->alloc_name];              \
  }                                                                           \
                                                                              \
  int zf_stack_##obj_type##_is_allocated(struct zf_stack* st,                 \
                                         OBJ_TYPE(alloc_name) obj)            \
  {                                                                           \
    RES_TYPE(alloc_name) res;                                                 \
    zf_stack_##obj_type##_to_res(st, obj, &res);                              \
    return res->generic_res.res_flags & ZF_GENERIC_RES_ALLOCATED;             \
  }                                                                           \
                                                                              \
  int zf_stack_alloc_##obj_type(struct zf_stack* st,                          \
                                OBJ_TYPE(alloc_name)* obj_out)                \
  {                                                                           \
    struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);   \
    unsigned index;                                                           \
    int rc = zf_lazy_alloc(&sti->alloc_name.alloc_state, &index);             \
    if( rc != 0 )                                                             \
      return rc;                                                              \
    *obj_out = &st->alloc_name[index];                                        \
    typeof(&sti->alloc_name.resources[0]) res;                                \
    zf_stack_##obj_type##_to_res(st, *obj_out, &res);                         \
    memset(res, 0, sizeof(*res));                                             \
    res->generic_res.res_flags |= ZF_GENERIC_RES_ALLOCATED;                   \
    return 0;                                                                 \
  }                                                                           \
                                                                              \
  int                                                                         \
  zf_stack_free_##obj_type(struct zf_stack* st, OBJ_TYPE(alloc_name) obj)     \
  {                                                                           \
    struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);   \
    typeof(&sti->alloc_name.resources[0]) res;                                \
    zf_stack_##obj_type##_to_res(st, obj, &res);                              \
    zf_lazy_free(&sti->alloc_name.alloc_state, &res->generic_res.free_link);  \
    res->generic_res.res_flags &= ~ZF_GENERIC_RES_ALLOCATED;                  \
    return 0;                                                                 \
  }

ENDPOINT_ALLOC_TMPL(udp_rx, udp_rx)
ENDPOINT_ALLOC_TMPL(udp_tx, udp_tx)
ENDPOINT_ALLOC_TMPL(tcp, tcp)
ENDPOINT_ALLOC_TMPL(tcp_listen_state, tcp_listen)
ENDPOINT_ALLOC_TMPL(muxer, muxer)


struct zf_rx_table_res*
zf_stack_get_rx_table(struct zf_stack* st, int rx_table_id)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);

  if( rx_table_id < ZF_STACK_RX_TABLE_COUNT )
    return sti->rx_table_res[rx_table_id];

  zf_assert(0);
  return NULL;
}


void zf_init_tx_state(struct zf_stack* stack, struct zf_tx* tx)
{
  memset(&tx->pkt, 0, sizeof(tx->pkt));
  tx->path.mac = &zf_tx_ethhdr(tx)->h_dest[0];
}


void zf_init_tx_ethhdr(struct zf_stack* stack, struct zf_tx* tx)
{
  bool has_vlan = zf_tx_do_vlan(tx);
  zf_tx_ethhdr(tx)->h_proto = htons(has_vlan ? ETH_P_8021Q : ETH_P_IP);
  if( has_vlan ) {
    tx->pkt.tcp_vlanhdr.vlan_tag = htons(tx->path.vlan);
    tx->pkt.tcp_vlanhdr.ethproto = htons(ETH_P_IP);
  }
  /* The source MAC address is set when pinning the zocket, and the destination
   * MAC address is set when resolving the path. */
}


void
zf_tx_dump_hdrs(struct zf_tx* tx, int proto)
{
  unsigned const char* hdrs[4] = {
    (unsigned char*) zf_tx_ethhdr(tx),
    (unsigned char*) zf_tx_iphdr(tx),
    proto == IPPROTO_TCP ?
    (unsigned char*) zf_tx_tcphdr(tx) : (unsigned char*) zf_tx_udphdr(tx),
    proto == IPPROTO_TCP ?
    (unsigned char*) (zf_tx_tcphdr(tx) + 1):
    (unsigned char*) (zf_tx_udphdr(tx) + 1),
  };

  for(int i = 0; i < 3; i++) {
    unsigned const char* data = hdrs[i];
    char buf[128];
    char* e = buf + sizeof(buf) - 10;
    char* w = buf;
    w += sprintf(w, "   L%d: %2ld:", i + 2, hdrs[i+1] - data);
    for ( ; data < hdrs[i+1] && w < e; data++ ) {
      w += sprintf(w, " %02x", *data);
    }
    if( data != hdrs[i+1] )
      sprintf(w, "...");
    zf_dump("%s\n", buf);
  }
}

void zf_tx_dump(struct zf_tx* tx, int proto)
{
  zf_path_dump(&tx->path);
  zf_tx_dump_hdrs(tx, proto);
}


struct zf_waitable*
zf_stack_to_waitable(struct zf_stack* stack)
{
  return &stack->w;
}


int
zf_stack_is_quiescent(struct zf_stack* stack)
{
  return stack->busy_refcount == 0;
}

int
zf_stack_query_feature(struct zf_stack* stack, enum zf_stack_feature feature)
{
  switch( feature ) {
    case CTPIO: {
      return stack->ctpio_max_frame_len > 0;
    }
    case PIO: {
      /* The availiability of PIO is defined on a per nic basis, rather than
       * a per stack basis - Since the user is querying the stack for the 
       * feature (rather than each nic) this will return true if any of the
       * nics have PIO available */
      int pio_available = 0;
      for( int nicno = 0; nicno < stack->nics_n; ++nicno ) {
        struct zf_stack_nic* nic = &stack->nic[nicno];
        if( nic->pio.len > 0 ) {
          pio_available = 1;
          break;
        }
      }
      return pio_available;
    }
  }

  return -ENOENT;

}

int zf_set_reset_callback(struct zf_stack* st, void (*func)(void*), void* arg)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  sti->reset_callback = func;
  sti->reset_callback_arg = arg;
  return 0;
}
