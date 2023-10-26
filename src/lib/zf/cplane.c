/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */

#include <zf_internal/zf_state.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>

#include <cplane/cplane.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <ci/net/arp.h>
#include <ci/net/ipv4.h>

static const zf_logger zf_log_cplane_err(ZF_LC_CPLANE,ZF_LL_ERR);
static const zf_logger zf_log_cplane_info(ZF_LC_CPLANE, ZF_LL_INFO);
#ifndef NDEBUG
static const zf_logger zf_log_cplane_trace(ZF_LC_CPLANE, ZF_LL_TRACE);
#else
#define zf_log_cplane_trace(...) do{}while(0)
#endif

ZF_COLD void zf_path_pin_zock(struct zf_stack* st, struct zf_tx* tx)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);

  if( st->encap_type & CICP_LLAP_TYPE_BOND ) {
    ef_cp_route_verinfo verinfo = EF_CP_ROUTE_VERINFO_INIT;
    ef_cp_fwd_meta meta = {
      .ifindex = sti->sti_ifindex,
      .iif_ifindex = -1,
    };
    iphdr* ip = zf_tx_iphdr(tx);
    size_t prefix_space = (char*)ip - (char*)&tx->pkt;
    int64_t rc = zf_state.cp.resolve(zf_state.cp_handle, ip, &prefix_space,
                            &meta, &verinfo,
                            EF_CP_RESOLVE_F_BIND_SRC | EF_CP_RESOLVE_F_NO_ARP);
    if( rc < 0 ) {
      /* Should only happen if something dramatic has happened, e.g. our NIC
       * has gone down */
      zf_log_cplane_err(st, "Socket pin failed to get a route: %s\n",
                        strerror(-rc));
      tx->path.nicno = 0;
      return;
    }

    tx->path.nicno = (zf_stack_res_nic*)meta.intf_cookie - &sti->nic[0];
  }
  else {
    /* Optimisation only: In non-bond modes we only support one nic currently,
     * so we can skip the resolve */
    memcpy(zf_tx_ethhdr(tx)->h_source, sti->sti_src_mac, ETH_ALEN);
    tx->path.nicno = 0;
  }
}

/** \brief Find destination MAC address for the given IP address.
 *
 * \param stack
 * \param path structure to fill in
 * \param wait wait until the MAC address is resolved?
 *
 * The function finds the details of the path to the specified IP address:
 * path MTU and destination MAC address.
 *
 * If MAC address is not known, we always send ARP request - but if
 * wait==false, then we do not wait for an answer.  In any case, OS will
 * handle the answer and control plane will store it for future use.
 *
 * If function returns ZF_PATH_NOMAC, content of path structure is partially
 * valid, notably vlan.
 *
 * Stale ARP entries are used as if they were valid.
 */
enum zf_path_status
__zf_cplane_get_path(struct zf_stack* st, struct zf_path* path,
                     bool wait)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  ef_cp_route_verinfo verinfo = EF_CP_ROUTE_VERINFO_INIT;
  int64_t rc;
  int64_t time_limit_us;
  int64_t time_used_us = 0;
  struct timespec start;
  size_t prefix_space;
  ethvlanipudphdr pkt = {
    .ip = {
      .ihl = sizeof(iphdr) / 4,
      .version = 4,
      .protocol = IPPROTO_UDP,   /* doesn't have to be correct */
      .saddr = !CI_IP_IS_MULTICAST(path->src) ? path->src : 0,
      .daddr = path->dst,
    },
  };
  ef_cp_fwd_meta meta = {
    .ifindex = sti->sti_ifindex,
    .iif_ifindex = -1,
  };

  zf_log_cplane_trace(st, "Get route: from " CI_IP_PRINTF_FORMAT
                      " to " CI_IP_PRINTF_FORMAT " iif %d\n",
                      CI_IP_PRINTF_ARGS(&pkt.ip.saddr),
                      CI_IP_PRINTF_ARGS(&pkt.ip.daddr),
                      meta.ifindex);

  time_limit_us = wait ? sti->arp_reply_timeout : 0;

  if( time_limit_us )
    clock_gettime(CLOCK_MONOTONIC, &start);

  do {
    prefix_space = offsetof(ethvlanipudphdr, ip);
    rc = zf_state.cp.resolve(zf_state.cp_handle, &pkt.ip, &prefix_space, &meta,
                             &verinfo, EF_CP_RESOLVE_F_BIND_SRC);
    if( rc == -EAGAIN ) {
      struct timespec now;

      if( time_limit_us == 0 )
        break;

      clock_gettime(CLOCK_MONOTONIC, &now);
      time_used_us = ((now.tv_sec - start.tv_sec) * 1000000) +
                     ((now.tv_nsec - start.tv_nsec) / 1000);

      if( time_used_us >= time_limit_us )
        break;

      usleep(1);
      continue;
    }
    /* It is no longer safe to require meta.ifindex == sti->sti_ifindex when
     * resolving routes. For example, sti->sti_ifindex could refer to a VLAN
     * interface (or really any non-physical interface), but meta.ifindex
     * will only ever return physical ifindices because we will only ever
     * register physical interfaces with the cplane API. */
    if( rc >= 0 && meta.ifindex > 0 )
      break;
    if( rc == -ETIMEDOUT ) {
      zf_log_cplane_err(st, "ARP failed for " CI_IP_PRINTF_FORMAT "\n",
                        CI_IP_PRINTF_ARGS(&path->dst));
      path->rc = ZF_PATH_NOROUTE;
      return path->rc;
    }
    if( rc == -EADDRNOTAVAIL ) {
      static int printed = 0;
      if( ! printed ) {
        zf_log_cplane_err(st, "Route goes via unknown interface ifindex=%d, "
                          "see cplane_alien_ifindex counter in zf_stackdump\n",
                          meta.ifindex);
        printed = 1;
      }
      st->stats.cplane_alien_ifindex++;
    }
    else
      zf_log_cplane_err(st, "Failed to resolve the route: %s\n",
                        strerror(-rc));
    path->rc = ZF_PATH_NOROUTE;
    return path->rc;

    /* In theory, we shoud break out if we see FLAG_ARP_FAILED popping up
     * in a non-first loop.  But if we see ARP_FAILED from the start, we
     * should give a chance to re-resolve.  For now we always loop. */
  } while( 1 );

  if( rc == -EAGAIN ) {
    if( time_limit_us ) {
      zf_log_cplane_err(st, "ARP timeout for " CI_IP_PRINTF_FORMAT "\n",
                        CI_IP_PRINTF_ARGS(&path->dst));
    }
    path->rc = ZF_PATH_NOROUTE;
    return path->rc;
  }

  ethhdr* eth = (ethhdr*)((char*)&pkt.ip - prefix_space);
  zf_log_cplane_trace(st, "Got route: from " CI_IP_PRINTF_FORMAT
                      " via " CI_MAC_PRINTF_FORMAT
                      " iif %d ethertype %x\n",
                      CI_IP_PRINTF_ARGS(&pkt.ip.saddr),
                      CI_MAC_PRINTF_ARGS(&eth->h_dest),
                      meta.ifindex, ntohs(eth->h_proto));

  if( time_limit_us ) {
    zf_log_cplane_info(st, "ARP for " CI_IP_PRINTF_FORMAT
                       " via ifindex %d took %dus\n",
                       CI_IP_PRINTF_ARGS(&path->dst),
                       meta.ifindex, time_used_us);
  }

  path->vlan = eth->h_proto == htons(ETH_P_8021Q) ?
               ntohs(pkt.vlan_tag) : ZF_NO_VLAN;
  path->mtu = meta.mtu;
  path->src = pkt.ip.saddr;
  memcpy(path->mac, (char*)&pkt.ip - prefix_space, ETH_ALEN);
  path->rc = ZF_PATH_OK;

  return path->rc;
}


int zf_cplane_get_iface_info(int ifindex, zf_if_info* info_out)
{
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc = 0;

  CP_VERLOCK_START(version, mib, &zf_state.cplane_handle);

  id = cp_llap_find_row(mib, ifindex);

  if( id != CICP_ROWID_BAD ) {
    const cicp_llap_row_t* row = &mib->llap[id];
    memcpy(&info_out->mac_addr, &row->mac, sizeof(info_out->mac_addr));
    if( (row->encap.type & (CICP_LLAP_TYPE_VLAN | CICP_LLAP_TYPE_MACVLAN)) )
      info_out->ifindex = row->encap.link_ifindex;
    else
      info_out->ifindex = ifindex;
    /* The [rx_hwports] member of the LLAP row specifies all hwports included
     * in the bond, and these are precisely the hwports on which we want to
     * create VIs for the ZF stack. */
    info_out->rx_hwports = row->rx_hwports;
    info_out->tx_hwports = row->tx_hwports;
    strncpy(info_out->name, row->name, sizeof(info_out->name));
    info_out->encap = row->encap;
  }
  else {
    rc = -ENOENT;
  }

  CP_VERLOCK_STOP(version, mib);

  return rc;
}


int zf_cplane_get_ifindex(const char* interface)
{
  ef_cp_intf intf;
  int rc = zf_state.cp.get_intf_by_name(zf_state.cp_handle, interface, &intf, 0);
  return rc < 0 ? rc : intf.ifindex;
}
