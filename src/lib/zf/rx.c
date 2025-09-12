/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*! \file
 * 
 * \brief  ZF rx - resource management and slow path
 *
 * This is the slow path resource management.
 *
 * UDP:
 * zf_rx <-1-1-> zf_rx_res <-1-N filters-> zf_rx_table_res
 *
 * TCP:
 * zf_rx <-1-1-> zf_rx_res <-1-1 filter-> zf_rx_table_res
 */

#include <zf_internal/rx.h>
#include <zf_internal/rx_res.h>

#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/muxer.h>
#include <zf_internal/utils.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/timestamping.h>

#include <unistd.h>


/**
 * When adding an entry to the RX resource table we're allowed to associate
 * some opaque data.  We use this for:
 * - the filter cookies, so we can remove the HW filters later on
 * - a backing socket, for port reservation
 */
struct bind_state {
  struct zf_stack* stack;
  zfrr_nic_mask nics;
  ef_filter_cookie cookies[ZF_MAX_NICS];
  int backing_socket;
};


static const zf_logger zf_log_filter_err(ZF_LC_FILTER, ZF_LL_ERR);
#ifndef NDEBUG
static const zf_logger zf_log_filter_trace(ZF_LC_FILTER, ZF_LL_TRACE);
#else
#define zf_log_filter_trace(...) do{}while(0)
#endif

#ifndef NDEBUG
static const zf_logger zf_log_rx_trace(ZF_LC_RX, ZF_LL_TRACE);
#else
#define zf_log_rx_trace(...) do{}while(0)
#endif


/**
 * \brief Initialise the zf_rx_res
 *
 * This must be called before any filters can be installed.
 */
void
zfrr_init(struct zf_rx_res* rx_res)
{
  ci_dllist_init(&rx_res->filter_list);
}


static int
get_backing_socket(struct zf_stack* st, int proto, int ifindex,
                   const struct sockaddr_in* laddr,
                   const struct sockaddr_in* raddr)
{
  /* Sanity check protocol */
  zf_assert(proto == IPPROTO_UDP || proto == IPPROTO_TCP );

  int sock;
  int rc = 0;
  socklen_t addr_len = sizeof *laddr;

  if( laddr->sin_family != AF_INET )
    return -EAFNOSUPPORT;

  if( proto == IPPROTO_UDP )
    sock = zf_sys_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  else
    sock = zf_sys_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if( sock < 0 ) {
    rc = -errno;
    zf_log_filter_err(st,
                      "Failed to allocate socket for port reservation, rc %d\n",
                      rc);
    return rc;
  }

  /* Because we grab a backing socket for every filter we install we need to
   * set SO_REUSEADDR for UDP sockets, as it's quite reasonable for them to
   * have multiple filters with the same port.
   *
   * UDP sockets also may need multicast memberships.
   */
  if( proto == IPPROTO_UDP ) {
    int one = 1;
    if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ) {
      rc = -errno;
      zf_log_filter_err(st,
                        "Failed to set SO_REUSEADDR on backing socket, rc %d\n",
                        rc);
      goto fail;
    }

    if( is_multicast(laddr) ) {
      if( ! raddr || raddr->sin_addr.s_addr == INADDR_ANY ) {
        /* Install any-source multicast subscription */
        struct ip_mreqn mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr = laddr->sin_addr;
        mreq.imr_ifindex = ifindex;
        rc = setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if( rc < 0 ) {
          rc = -errno;
          zf_log_filter_err(st,
                            "Couldn't add membership on ifindex %d, rc %d\n",
                            mreq.imr_ifindex, rc);
          goto fail;
        }
      }
      else {
        /* Install source-specific multicast subscription */
        struct ip_mreq_source mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr  = laddr->sin_addr;
        mreq.imr_sourceaddr = raddr->sin_addr;

        /* Look up interface address from ifindex
         * IP_ADD_MEMBERSHIP doesn't require this lookup since ip_mreqn accepts
         * an ifindex directly */
        struct ifreq ifr;
        ifr.ifr_ifindex = ifindex;
        rc = ioctl(sock, SIOCGIFNAME, &ifr);
        if( rc == 0 )
          rc = ioctl(sock, SIOCGIFADDR, &ifr);
        if( rc < 0 ) {
          rc = -errno;
          zf_log_filter_err(st,
                  "Couldn't look up interface address for ifindex %d, rc %d\n",
                  ifindex, rc);
          goto fail;
        }
        mreq.imr_interface = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;

        rc = setsockopt(sock, SOL_IP, IP_ADD_SOURCE_MEMBERSHIP,
                        &mreq, sizeof(mreq));
        if( rc < 0 ) {
          rc = -errno;
          zf_log_filter_err(st, "Couldn't add source membership, rc %d\n", rc);
          goto fail;
        }
      }
    }
  }

  if( bind(sock, (const struct sockaddr*)laddr, sizeof(*laddr)) < 0 ) {
    rc = -errno;
    zf_log_filter_err(st, "Couldn't bind backing socket, rc %d\n", rc);
    goto fail;
  }

  if( getsockname(sock, (struct sockaddr *)laddr, &addr_len) < 0 ) {
    rc = -errno;
    zf_log_filter_err(st, "Couldn't get backing socket address, rc %d\n", rc);
    goto fail;
  }

  return sock;

fail:
  close(sock);
  return rc;
}


/**
 * \brief Reserves a local port for use by this zocket
 *
 * If the supplied port is 0 then a port will be selected and 'laddr'
 * will be updated with the chosen port.
 */
int
zfrr_reserve_port(struct zf_stack* st, struct zf_rx_res* rx_res, int proto,
                  const struct sockaddr_in* laddr,
                  const struct sockaddr_in* raddr)
{
  int sock;
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);

  /* Fail if already bound */
  if( rx_res->bs )
    return -EINVAL;

  /* Allocate somewhere to store stuff */
  rx_res->bs = (struct bind_state*)malloc(sizeof(struct bind_state));
  if( !rx_res->bs )
    return -ENOMEM;

  sock = get_backing_socket(st, proto, sti->sti_ifindex, laddr, raddr);
  if( sock < 0 ) {
    free(rx_res->bs);
    rx_res->bs = NULL;
    return sock;
  }

  rx_res->bs->backing_socket = sock;
  rx_res->bs->stack = st;
  return 0;
}


/**
 * \brief Releases a port that has been reserved for this zocket
 *
 * This is intended for the case where a port has been reserved, but filters
 * have not been installed.  Once filters have been installed then
 * zfrr_remove() can be used to release both the filter and backing socket.
 */
int
zfrr_release_port(struct zf_stack* st, struct zf_rx_res* rx_res )
{
  if( rx_res->bs ) {
    /* Sanity check */
    if( rx_res->bs->stack != st )
      return -EINVAL;

    close(rx_res->bs->backing_socket);
    free(rx_res->bs);
    rx_res->bs = NULL;
  }

  return 0;
}


/* Adds an entry to the RX table.  This maintains ownership of the bind_state
 * (passed as opaque data to the filtering code) until the table resource
 * is released.  At which point it returns ownership to the releaser.
 */
static int
zfrr_sw_filter_init(struct zf_stack* st, uint16_t zocket_id,
                    struct zf_rx_res* rx_res,
                    struct zf_rx_table_res* rx_table_res,
                    const struct sockaddr_in* laddr,
                    uint32_t raddr_be, uint16_t rport_be)
{
  int rc =  zf_rx_table_add(rx_table_res, laddr->sin_addr.s_addr, raddr_be,
                            laddr->sin_port, rport_be, zocket_id,
                            &rx_res->filter_list, rx_res->bs);

  /* Ownership of the bind_state resides in the rx table on success */
  if( rc == 0 )
    rx_res->bs = NULL;

  return rc;
}


static void
zfrr_hw_filter_init_vlan(struct zf_stack* st, int nicno, int proto,
                         const struct sockaddr_in* laddr, ef_filter_spec* spec)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);

  if( proto == IPPROTO_UDP && is_multicast(laddr) &&
      sti->nic[nicno].flags & ZF_RES_NIC_FLAG_VLAN_FILTERS &&
      sti->sti_vlan_id != ZF_NO_VLAN ) {
    ef_filter_spec_set_vlan(spec, sti->sti_vlan_id);
  }
}


static int
zfrr_hw_filter_init(struct zf_stack* st, zfrr_nic_mask nics, int proto,
                    const struct sockaddr_in* laddr,
                    const struct sockaddr_in* raddr,
                    ef_filter_cookie cookies[ZF_MAX_NICS])
{
  int rc;

  zf_assume(nics);

  int nic;
  enum ef_filter_flags flags = (enum ef_filter_flags) (st->x4_shared_mode ? EF_FILTER_FLAG_SHARED_RXQ : 0 );
  for( nic = 0; nic < st->nics_n; ++nic ) {
    if( (1ull << nic) & nics ) {
      ef_filter_spec spec;
      ef_filter_spec_init(&spec, flags);
      zfrr_hw_filter_init_vlan(st, nic, proto, laddr, &spec);

      if( raddr != NULL )
        rc = ef_filter_spec_set_ip4_full(&spec, proto, laddr->sin_addr.s_addr,
                                         laddr->sin_port,
                                         raddr->sin_addr.s_addr,
                                         raddr->sin_port);
      else
        rc = ef_filter_spec_set_ip4_local(&spec, proto,
                                          laddr->sin_addr.s_addr,
                                          laddr->sin_port);
      if( rc < 0 )
        goto fail;

      rc = ef_vi_filter_add(&st->nic[nic].vi,
                            zf_stack_get_driver_handle(st, nic),
                            &spec, &cookies[nic]);
      if( rc < 0 ) {
        zf_log_filter_trace(st, "%s: ef_vi_filter_add() failed for nic %d ",
                                "(rc = %d)\n", __FUNCTION__, nic, rc);
        goto fail;
      }
    }
  }

  return 0;

 fail:
  for( int del_nic = 0; del_nic < nic; ++del_nic )
    if( (1ull << del_nic) & nics )
      ef_vi_filter_del(&st->nic[del_nic].vi,
                       zf_stack_get_driver_handle(st, del_nic),
                       &cookies[del_nic]);
  return rc;
}


static int
zfrr_hw_filter_fini(struct zf_stack* st, zfrr_nic_mask nics,
                    ef_filter_cookie cookies[ZF_MAX_NICS])
{
  int rc = 0, rc1;

  /* Remove the filters using our stored cookies. */
  for( int nic = 0; nic < st->nics_n; ++nic ) {
    if( (1ull << nic) & nics ) {
      rc1 = ef_vi_filter_del(&st->nic[nic].vi,
                             zf_stack_get_driver_handle(st, nic),
                             &cookies[nic]);
      if( rc1 < 0 ) {
        zf_log_filter_trace(st, "%s: ef_vi_filter_del() failed for nic %d ",
                                "(rc = %d)\n", __FUNCTION__, nic, rc);
        if( rc == 0 )
          rc = rc1;
      }
    }
  }

  return rc;
}


/**
 * \brief Install filters for this zocket
 *
 * \param hw_filter Set if this zocket requires a hw filter for this addr
 *
 * If 'hw_filter' is true then the caller can use a port number of
 * zero to request that an unallocated port number should be chosen.
 * In this case, 'laddr' will be updated with the chosen port.
 */
int
zfrr_add(struct zf_stack* st, struct zf_rx_res* rx_res, uint16_t zocket_id,
         zfrr_nic_mask nics, int proto, struct zf_rx_table_res* rx_table_res,
         struct zf_rx_table* table, struct sockaddr_in* laddr,
         const struct sockaddr_in* raddr, int hw_filter)
{
  int rc;
  int already_bound = !!(rx_res->bs);

  uint32_t raddr_be = 0;
  uint16_t rport_be = 0;

  bool laddr_is_multicast = is_multicast(laddr);
  bool raddr_port_is_0 = raddr && raddr->sin_port == 0;
  bool needs_ssm_local_filter =  ( laddr_is_multicast && raddr_port_is_0 );

  zf_log_filter_trace(st, "%s: zocket_id = %u rx_res = %p bs = %p\n",
                      __FUNCTION__, zocket_id, rx_res, rx_res->bs);

  if( hw_filter ) {

    if( proto == IPPROTO_UDP ) {
      /* A bound TCP zocket may already have a backing socket, but
       * there's no separate bind stage for UDP, so there shouldn't
       * already be any bind_state.
       */
      zf_assert(!already_bound);
    }

    if( !already_bound ) {
      /* We did not explicitly reserve a port - do so now */
      rc = zfrr_reserve_port(st, rx_res, proto, laddr, raddr);
      if( rc < 0 )
        goto fail_bind;
    }

    /* We have now created and bound the backing socket so we must have some
     * bind_state to be storing it in.
     */
    zf_assert(rx_res->bs);
  
    if ( !needs_ssm_local_filter )
      rc = zfrr_hw_filter_init(st, nics, proto, laddr, raddr,
                              rx_res->bs->cookies);
    else
      rc = zfrr_hw_filter_init(st, nics, proto, laddr, NULL,
                              rx_res->bs->cookies);

    if( rc < 0 ) {
      if( rc == -EEXIST )
        rc = -EADDRINUSE;
      goto fail_hw_filt;
    }
    rx_res->bs->nics = nics;
  }
  else {
    /* There is no hardware filter or backing socket associated with an
     * accepted zocket.
     */
    zf_assert(!rx_res->bs);
  }

  /* By this point, we should have a port number. (The special
   * behaviour of port zero is not currently supported when not using
   * hardware filters.) */
  if( laddr->sin_port == 0 ) {
    rc = -EINVAL;
    goto fail_sw_filt;
  }

  if( !needs_ssm_local_filter ) {
    raddr_be = raddr != NULL ? raddr->sin_addr.s_addr : 0;
    rport_be = raddr != NULL ? raddr->sin_port : 0;
  }

  /* Adding a duplicate entry to rx_table is illegal, so we should drop
   * it here */
  uint16_t zocket_id_dummy;
  if ( zf_rx_table_lookup(table, laddr->sin_addr.s_addr, raddr_be,
                          laddr->sin_port, rport_be, &zocket_id_dummy) == 0 ) {
    rc = -EADDRINUSE;
    goto fail_sw_filt;
  }

  /* This initialises all of the state that's kept in [rx_res] now that we've
   * installed any necessary filter on the NIC.  N.B.: On success, this will
   * transfer ownership of [rx_res->bs] to the RX table and will set
   * [rx_res->bs] to NULL. */
  rc = zfrr_sw_filter_init(st, zocket_id, rx_res, rx_table_res, laddr,
                          raddr_be, rport_be);
  if( rc < 0 )
    goto fail_sw_filt;

  return rc;

fail_sw_filt:
  zf_log_filter_trace(st, "%s: fail_sw_filt\n", __FUNCTION__);
  if( hw_filter ) {
    zf_assert(rx_res->bs);
    /* This must succeed as we only just added it successfully */
    int rc1 = zfrr_hw_filter_fini(st, nics, rx_res->bs->cookies);
    zf_assert_ge(rc1, 0);
  }

fail_hw_filt:
  zf_log_filter_trace(st, "%s: fail_hw_filt\n", __FUNCTION__);
  if( !already_bound ) {
    /* We didn't have a backing socket when we came in here - leave things
     * in the same state.
     */
    close(rx_res->bs->backing_socket);
    free(rx_res->bs);
    rx_res->bs = NULL;
  }

fail_bind:
  return rc;
}


/* This function frees a bind_state and all resources associated with it.  It
 * is particularly useful as a callback to zf_rx_table_remove_list(). */
static int bind_state_cleanup_callback(void* opaque_bind_state)
{
  struct bind_state* bs = (struct bind_state*) opaque_bind_state;
  int rc = 0;

  if( bs != NULL ) {
    rc = zfrr_hw_filter_fini(bs->stack, bs->nics, bs->cookies);
    /* Closing the socket will drop any associated multicast membership.  We
     * need to do this even if the HW filter-removal failed, as we have already
     * taken ownership of the bind_state back from the RX-lookup table. */
    close(bs->backing_socket);
    free(bs);
  }

  return rc;
}


int
zfrr_remove(struct zf_stack* stack, struct zf_rx_table_res* rx_table_res,
            int nic, struct sockaddr_in* laddr, struct sockaddr_in* raddr)
{
  uint32_t laddr_be = laddr != NULL ? laddr->sin_addr.s_addr : 0;
  uint32_t lport_be = laddr != NULL ? laddr->sin_port : 0;


  uint32_t raddr_be = 0;
  uint32_t rport_be = 0;
  if ( raddr ) {
    bool ssm_filter_installed = is_multicast(laddr) && raddr->sin_port == 0;
    raddr_be = ssm_filter_installed ? 0 : raddr->sin_addr.s_addr;
    rport_be = ssm_filter_installed ? 0 : raddr->sin_port;
  }

  struct zf_rx_table* table = zf_rx_table_get(rx_table_res);
  struct bind_state* bs;
  uint16_t tmp;

  if( zf_rx_table_lookup( table, laddr_be, raddr_be, lport_be, rport_be,
                          &tmp) != 0 )
    return -ENOENT;

  /* TODO: bug65431: Return -EINVAL if we're not bound to the requested
   * address. */

  int rc = zf_rx_table_remove(rx_table_res, laddr_be, raddr_be, lport_be,
                              rport_be, (void**)&bs);
  if( rc != 0 )
    return rc;

  rc = bind_state_cleanup_callback(bs);
  zf_assume_equal(rc, 0);

  return 0;
}


int
zfrr_remove_all(struct zf_stack* stack, struct zf_rx_table_res* rx_table_res,
                ci_dllist* list)
{
  return zf_rx_table_remove_list(rx_table_res, list,
                                 bind_state_cleanup_callback);
}


/** \brief Initialises the zf_rx
 *
 * \param rx
 *
 * This initialises the fast path RX state for this zocket.  It is independent
 * of the local address and so should be called only once per zocket.  It must
 * be called before data can be received.
 */
void
zfr_init(struct zf_rx* rx)
{
  memset(rx, 0, sizeof(*rx));
}


/** \brief Free all packets on RX queue
 *
 * \param rx
 *
 * \return The number of packets freed.
 *
 * \note This function assumes that \p rx->begin_process is valid.  In general
 * this is not the case for UDP queues, so in such cases callers should first
 * call zfr_queue_mark_processed().
 */
int
zfr_drop_queue(zf_pool* pool, zf_rx* rx)
{
  int freed = 0;

  while( ! zfr_queue_all_packets_processed(rx) ) {
    struct iovec* pkts;
    int count = zfr_ring_peek_unprocessed(&rx->ring, &pkts);
    zfr_zc_process_done(pool, rx, count);
  }

  zf_assert(zfr_queue_all_packets_processed(rx));

  /* Keep pulling packets out of the ring until it's empty. */
  while( 1 ) {
    struct iovec* pkts;
    int count = zfr_ring_peek_all(&rx->ring, &pkts);
    if( count == 0 )
      break;

    freed += count;
    zfr_zc_read_done(pool, rx, count, 0);
  }

  return freed;
}


/** \brief Find the start of a TCP packet's possible payload start and end.
 *  to prevent overwriting the header.
 *
 * \param stack
 * \param pool The buffer pool containing the packet buffer.
 * \param ptr A pointer into the packet buffer.
 * \param payload_start address beyond headers where payload could go
 * \param payload_end address where no more payload should go
 *
 * \note payload_start address will differ per buffer due to staggering and
 *       header length differences. And capacity of each buffer will differ.
 */
static inline void
zfr_get_payload_space(struct zf_stack* stack, struct zf_pool* pool, char* ptr,
                      char**payload_start, char**payload_end)
{
  unsigned rx_prefix_len = stack->nic[0].rx_prefix_len;
  zf_assume(rx_prefix_len == 0 ||
            rx_prefix_len == ES_DZ_RX_PREFIX_SIZE);

  char* packet = zf_packet_buffer_start(pool, ptr);
  char* ethhdr = packet + rx_prefix_len;
  char* iphdr = (char*)zf_ip_hdr(ethhdr);
  char* tcphdr = iphdr + ((struct iphdr *)iphdr)->ihl * 4;
  /* We preserve the headers but in fact they are expendable apart from
   * timestamp and seg_no. */
  char* tcpdata = tcphdr + ((struct tcphdr *)tcphdr)->doff * 4;

  *payload_start = tcpdata;
  /* Actual start address of the next buffer not to be written beyond
   * Note that each pkt buffer capacities will differ. */
  *payload_end = (char*) ROUND_UP((ptrdiff_t)packet | 1, PKT_BUF_SIZE) -
                 PKT_BUF_TCP_RESERVE;
  zf_assert_le(*payload_start, *payload_end);
}

static inline int
zfr_timestamp_gt(struct zf_stack* stack, char* lhs, char* rhs)
{
  struct timespec ts_lhs;
  struct timespec ts_rhs;
  unsigned flags;

  if( __zfr_pkt_get_timestamp(stack, lhs, &ts_lhs, &flags) != 0 )
    return 0;
  if( __zfr_pkt_get_timestamp(stack, rhs, &ts_rhs, &flags) != 0 )
    return 0;

  return zf_timespec_compare(&ts_lhs, &ts_rhs) > 0;
}

/* Copies the timestamp from src into dst if and only if it is later */
static inline void
zfr_resolve_timestamps(struct zf_stack* stack, struct iovec* dst, struct iovec* src)
{
  /* We checked when creating the stack that all VIs have the same
   * prefix-length, so using NIC zero is valid here. */
  size_t rx_prefix_len = stack->nic[0].rx_prefix_len;

  char* src_pkt = zf_packet_buffer_start(&stack->pool, (char*)src->iov_base);
  char* dst_pkt = zf_packet_buffer_start(&stack->pool, (char*)dst->iov_base);

  if( zfr_timestamp_gt(stack, src_pkt, dst_pkt) )
    memcpy(dst_pkt, src_pkt, rx_prefix_len);
}

/** \brief Coalesces one entry into another.
 *
 * \param stack The stack which owns the specified packets.
 * \param pool Where to free emptied entries to.
 * \param current The target entry.
 * \param next    The entry to coalesce into current.
 * \param keep_base do not move data of the current segment
 *
 * Note that as segments have staggerred start addresses
 * segments will keep different amount of data.
 * Also max amount of data recvq currently can hold is
 * TCP_WND.
 *
 * \return 1 if there is more space in current
 *         0 otherwise
 */
static int
zfr_coalesce_entry(struct zf_stack* stack, struct zf_pool* pool,
                   struct iovec* current,
                   struct iovec* next,
                   int keep_base)
{
  char* cur_base = (char*) current->iov_base;
  char* space_start, *space_end;
  zfr_get_payload_space(stack, pool, cur_base, &space_start, &space_end);
  zf_assert_le(space_start, cur_base);
  zf_assert_le(cur_base + current->iov_len, space_end);
  unsigned free_space = space_end - (cur_base + current->iov_len);

  if( ! keep_base && space_start < cur_base ) {
    /* Data is not at the beginning of the segment,
     * perhaps it is partially consumed.
     * Let's realign the content to the begging before appending
     * more data */
    memmove(space_start, cur_base, current->iov_len);
    current->iov_base = space_start;
    free_space = space_end - (space_start + current->iov_len);
  }

  unsigned to_copy = MIN(free_space, next->iov_len);
  if( to_copy == 0 )
    return free_space > 0;

  /* If we have a prefix, we will make sure that each pkt buffer has the
   * prefix associated with the youngest byte it contains. */
  unsigned plen = stack->nic[0].rx_prefix_len;

  /* Copy what we can onto the end of our current entry. */
  memmove((char*)current->iov_base + current->iov_len, next->iov_base,
          to_copy);
  current->iov_len += to_copy;
  (char*&) next->iov_base += to_copy;
  next->iov_len -= to_copy;
  zf_assert_le((char*)current->iov_base + current->iov_len, space_end);
  if( plen > 0 )
    zfr_resolve_timestamps(stack, current, next);

  return free_space > to_copy;
}

/** \brief Coalesces packet data of entries on the RX ring.
 *
 * \param rx
 * \param stack
 *
 * This function will coalesce the RX ring.
 * There must be no deferred processing pending when this is called, and the ring
 * must contain at least one entry.
 * First segment might only be coalesced partially to avoid full-blown coalesce and
 * moving of all the data by few bytes following a small read.
 * Also if zerocopy read is pending, the segments the client got hold of
 * will not get coalesced.
 */
void
zfr_queue_coalesce(struct zf_rx* rx, struct zf_stack* stack)
{
  struct zf_rx_ring* ring = &rx->ring;
  struct zf_pool* pool = &stack->pool;
  bool more_space = 1;

  zf_log_rx_trace(stack, "%s: Coalescing %d entries on recv queue\n",
                  __func__, zfr_queue_packets_unread_n(rx));

  /* We assume that begin_process == end.  The caller should ensure this if
   * necessary.
   */
  zf_assert(zfr_queue_all_packets_processed(rx));

  /* The function is only permitted to be called with a non-empty RX ring. */
  zf_assert(zfr_queue_packets_unread_n(rx) > 0);

  /* current is the index of the packet that we will attempt to coalesce into.
   * We start at the first packet in the ring that is not currently owned by
   * the application as part of a ZC-receive, attempting to coalesce the
   * following packet into the first unread packet.
   */
  uint32_t current = ring->begin_read + rx->release_n;
  zf_assert_le(ring->end - current, SW_RECVQ_MAX);

  if( current == ring->end ) {
    zf_log_rx_trace(stack, "%s: In-progress ZC-receive prevented coalescing\n",
                    __func__);
    return;
  }

  /* Before coalescing we need to reestablish whether there is an EOF pkt
   * EOF pkt needs to be preserved. */
  bool has_EOF = ring->pkts[ring->end & SW_RECVQ_MASK].iov_len == 0;

  /* We walk each packet, updating our current index as we fill it */
  for( uint32_t next = current + 1; next != ring->end; next++) {
    zf_assert_nequal(current, ring->end);
    if( current == next )
      continue;

    /* for first segment we ask to keep payload at the current address
     * to avoid situation when reading few bytes causes subsequent coalescing
     * to move all the data by few bytes */
    more_space = zfr_coalesce_entry(stack, pool,
                                &ring->pkts[current & SW_RECVQ_MASK],
                                &ring->pkts[next & SW_RECVQ_MASK],
                                current == ring->begin_read);

    if( ! more_space  ) {
      current++;
      next--;
    }
  }

  if( ring->pkts[current & SW_RECVQ_MASK].iov_len )
    current++;

  if( has_EOF ) {
    /* We need to reinstate EOF marker, which is to be 0-len pkt.
     * The original marker was at the end. Current should be 0-len too
     * and just as good for this purpose. */
    zf_assert_equal(ring->pkts[current & SW_RECVQ_MASK].iov_len, 0);
    current++;
  }

  /* Release the buffers for the entries we've freed - those between our
   * current index and the original end of the ring.
   */
  for( uint32_t i = current; i != ring->end; i++ ) {
    zf_assert_equal(ring->pkts[i & SW_RECVQ_MASK].iov_len, 0);
    zf_pool_free_pkt(pool,
       PKT_BUF_ID_FROM_PTR(pool, ring->pkts[i & SW_RECVQ_MASK].iov_base));
#ifndef NDEBUG
    ring->pkts[i & SW_RECVQ_MASK] = iovec {};
#endif
  }

  ring->end = ring->begin_process = current;

  zf_log_rx_trace(stack, "%s: After coalesce %d entries on recv queue\n",
                  __func__, zfr_queue_packets_unread_n(rx));
}


void
zf_rx_dump(struct zf_rx* rx)
{
  zf_dump("  rx: unread=%u begin=%u process=%u end=%u\n",
          zfr_queue_packets_unread_n(rx),
          rx->ring.begin_read, rx->ring.begin_process, rx->ring.end);
}

