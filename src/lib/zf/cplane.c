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

static inline void zf_init_mcast_mac(uint32_t dst_be32, unsigned char* out_mac)
{
  uint32_t dst = ntohl(dst_be32);

  zf_assert(out_mac);

  out_mac[0] = 1;
  out_mac[1] = 0;
  out_mac[2] = 0x5e;
  out_mac[3] = (dst >> 16) & 0x7f;
  out_mac[4] = (dst >> 8) & 0xff;
  out_mac[5] = dst & 0xff;
}

static inline const cicp_llap_row_t* find_llap(struct cp_mibs* mib, int ifindex)
{
  cicp_rowid_t id = cp_llap_find_row(mib, ifindex);
  if( id == CICP_ROWID_BAD )
    return NULL;
  else
    return &mib->llap[id];
}

static inline const cicp_ipif_row_t* find_ipif(struct cp_mibs* mib, int ifindex)
{
  cicp_rowid_t id = cp_ipif_any_row_by_ifindex(mib, ifindex);
  if( id == CICP_ROWID_BAD )
    return NULL;
  else
    return &mib->ipif[id];
}

static inline uint16_t get_vlan(const cicp_encap_t* encap)
{
  if( encap->type & CICP_LLAP_TYPE_VLAN )
    return encap->vlan_id;
  else
    return ZF_NO_VLAN;
}

static void __zf_path_pin_zock_hash(struct zf_stack* st, struct zf_tx* tx)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  /* The ports fields of the UDP and TCP header structs coincide, so we're
   * OK to use ethipudphdr regardless */
  struct ethipudphdr* hdr = &tx->pkt.udp_novlanhdr;
  struct zf_path* path = &tx->path;
  cicp_hash_state hs = {0,};
  ci_hwport_id_t id;

  /* We rely on callers to handle the case where we have no tx_hwports
   * available.  This function will just select a nic amongst those that
   * we have.
   */
  zf_assert(st->bond_state.tx_hwports);

  if( tx->path.vlan != ZF_NO_VLAN ) {
    struct ethvlanipudphdr* vlan_hdr = &tx->pkt.udp_vlanhdr;
    hdr->eth = vlan_hdr->eth;
    hdr->ip = vlan_hdr->ip;
    hdr->udp = vlan_hdr->udp;
  }

  /* This is a declaration that the address is for a TCP/UDP flow, but this is
   * without prejudice to the hashing mode, which is selected by
   * [st->encap_type]. */
  hs.flags |= CICP_HASH_STATE_FLAGS_IS_IP;
  hs.flags |= CICP_HASH_STATE_FLAGS_IS_TCP_UDP;
  memcpy(&hs.dst_mac, hdr->eth.h_dest, ETH_ALEN);
  memcpy(&hs.src_mac, hdr->eth.h_source, ETH_ALEN);
  hs.src_addr_be32 = hdr->ip.saddr;
  hs.dst_addr_be32 = hdr->ip.daddr;
  hs.src_port_be16 = hdr->udp.source;
  hs.dst_port_be16 = hdr->udp.dest;

  id = oo_cp_hwport_bond_get(st->encap_type, st->bond_state.tx_hwports, &hs);
  path->nicno = sti->hwport_to_nicno[id];
}

ZF_COLD void zf_path_pin_zock(struct zf_stack* st, struct zf_tx* tx)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);

  memcpy(zf_tx_ethhdr(tx)->h_source, sti->sti_src_mac, ETH_ALEN);

  if( st->encap_type & CICP_LLAP_TYPE_BOND ) {
    if( st->encap_type & CICP_LLAP_TYPE_USES_HASH ) {
      __zf_path_pin_zock_hash(st, tx);
    }
    else {
      cicp_hwport_mask_t hwports = st->bond_state.tx_hwports;

      /* Not hashing -> should have exactly one tx hwport */
      zf_assert(CI_IS_POW2(hwports));
      tx->path.nicno = sti->hwport_to_nicno[cp_hwport_mask_first(hwports)];
    }
  }
  else {
    /* In non-bond modes we only support one nic currently */
    tx->path.nicno = 0;
  }
}

static zf_path_status
__zf_cplane_get_path_mcast(struct zf_stack* st, struct zf_path* path,
                           bool wait)
{
  struct cp_mibs* mib;
  cp_version_t version;
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  int stack_ifindex = sti->sti_ifindex;
  const cicp_llap_row_t* stack_if;
  const cicp_ipif_row_t* ipif;

  CP_VERLOCK_START(version, mib, &zf_state.cplane_handle);

  path->rc = ZF_PATH_NOROUTE;
  stack_if = find_llap(mib, stack_ifindex);
  /* Interface found - might have been not found during verlock change */
  if( stack_if ) {
    ipif = find_ipif(mib, stack_ifindex);
    /* Interface has address */
    if( ipif ) {
      path->mtu = stack_if->mtu;
      path->src = ipif->net_ip;
      path->vlan = get_vlan(&stack_if->encap);
      zf_init_mcast_mac(path->dst, path->mac);
      path->rc = ZF_PATH_OK;
    }
  }
  CP_VERLOCK_STOP(version, mib);

  return path->rc;
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
  struct cp_fwd_key key;
  struct cp_fwd_data data;
  cicp_verinfo_t verinfo;
  int rc;
  int iter;
  bool is_multi = CI_IP_IS_MULTICAST(path->dst);

  if( is_multi )
    return __zf_cplane_get_path_mcast(st, path, wait);

  oo_cp_verinfo_init(&verinfo);
  memset(&key, 0, sizeof(key));
  key.dst = CI_ADDR_SH_FROM_IP4(path->dst);
  key.ifindex = sti->sti_ifindex;
  key.iif_ifindex = CI_IFID_BAD;
  if( !CI_IP_IS_MULTICAST(path->src) )
    key.src = CI_ADDR_SH_FROM_IP4(path->src);
  else
    key.src = CI_ADDR_SH_FROM_IP4(INADDR_ANY);
  key.tos = 0;
  key.flag = CP_FWD_KEY_REQ_WAIT;

  zf_log_cplane_trace(st, "Get route: from " CI_IP_PRINTF_FORMAT
                      " to " CI_IP_PRINTF_FORMAT " iif %d\n",
                      CI_IP_PRINTF_ARGS(&key.src.ip4),
                      CI_IP_PRINTF_ARGS(&key.dst.ip4),
                      key.ifindex);

  iter = wait ? sti->arp_reply_timeout : 0;
  do {
    rc = oo_cp_route_resolve(&zf_state.cplane_handle,
                             &verinfo, &key, &data);
    if( rc < 0 || data.base.ifindex != sti->sti_ifindex ) {
      if( rc == 0 ) {
        static int printed = 0;
        if( ! printed ) {
          zf_log_cplane_err(st, "Route goes via unknown interface ifindex=%d, "
                            "see cplane_alien_ifindex counter in zf_stackdump\n",
                            data.base.ifindex);
          printed = 1;
        }
        st->stats.cplane_alien_ifindex++;
      }
      else
        zf_log_cplane_err(st, "Failed to resolve the route: %s\n",
                          strerror(-rc));
      path->rc = ZF_PATH_NOROUTE;
      return path->rc;
    }

    /* In theory, we shoud break out if we see FLAG_ARP_FAILED popping up
     * in a non-first loop.  But if we see ARP_FAILED from the start, we
     * should give a chance to re-resolve.  For now we always loop. */
    if( (data.flags & CICP_FWD_DATA_FLAG_ARP_VALID) || iter == 0 )
      break;

    iter--;
    usleep(1);
  } while( 1 );

  if( ! (data.flags & CICP_FWD_DATA_FLAG_ARP_VALID) ) {
    if( data.flags & CICP_FWD_DATA_FLAG_ARP_FAILED ) {
      zf_log_cplane_err(st, "ARP failed for " CI_IP_PRINTF_FORMAT "\n",
                        CI_IP_PRINTF_ARGS(&path->dst));
    }
    else if( wait ) {
      zf_log_cplane_err(st, "ARP timeout for " CI_IP_PRINTF_FORMAT "\n",
                        CI_IP_PRINTF_ARGS(&path->dst));
    }
    path->rc = ZF_PATH_NOROUTE;
    return path->rc;
  }

  zf_log_cplane_trace(st, "Got route: from " CI_IP_PRINTF_FORMAT
                      " via " CI_MAC_PRINTF_FORMAT
                      " iif %d encap %x\n",
                      CI_IP_PRINTF_ARGS(&data.base.src),
                      CI_MAC_PRINTF_ARGS(&data.dst_mac),
                      data.base.ifindex, data.encap.type);

  if( iter > 0 ) {
    zf_log_cplane_info(st, "ARP for " CI_IP_PRINTF_FORMAT
                       " via ifindex %d took %dus\n",
                       CI_IP_PRINTF_ARGS(&path->dst), data.base.ifindex, iter);
  }

  path->vlan = get_vlan(&data.encap);
  path->mtu = data.base.mtu;
  path->src = data.base.src.ip4;
  memcpy(path->mac, &data.dst_mac, ETH_ALEN);
  path->rc = ZF_PATH_OK;

  /* When we return ZF_PATH_OK here we are saying that it's safe to pin the
   * zocket to a nic, which relies on there being something to pin to.
   *
   * If we're returning ok them we think we've got a valid route over a ZF
   * interface, which implies we've got at least one tx_hwport available.
   */
  zf_assert(data.hwports);

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
  struct cp_mibs* mib;
  cicp_rowid_t id;
  cp_version_t version;
  int rc;

  CP_VERLOCK_START(version, mib, &zf_state.cplane_handle);

  id = cp_llap_by_ifname(mib, interface);
  if( id != CICP_ROWID_BAD )
    rc = mib->llap[id].ifindex;
  else
    rc = -ENODEV;

  CP_VERLOCK_STOP(version, mib);

  return rc;
}
