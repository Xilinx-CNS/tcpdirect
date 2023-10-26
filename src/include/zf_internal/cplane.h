/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_CPLANE_H__
#define __ZF_CPLANE_H__

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>  /* For IF_NAMESIZE */

#include <cplane/cplane.h>
#include <cplane/create.h>

#include <zf_internal/zf_log.h>
#include <zf_internal/utils.h>
#include <zf_internal/stack_params.h>

enum zf_path_status {
  ZF_PATH_OK=0,
  ZF_PATH_NOROUTE,
  ZF_PATH_NOIF,
  ZF_PATH_NOMAC,
};

static const uint16_t ZF_NO_VLAN = 0xFFFF;

struct zf_path {
  uint32_t            dst; /* destination IP */
  unsigned char*      mac; /* MAC address for this IP - located in the pkt */
  uint16_t            vlan; /* 802.1Q Vlan ID or NO_VLAN */
  uint16_t            mtu; /* IP-level maximum transfer unit for this IP */
  enum zf_path_status rc;  /* status */
  uint32_t            src; /* a suitable source IP for this path */
  uint8_t             nicno; /* The NIC to route over */
};

struct zf_stack;
enum zf_path_status
__zf_cplane_get_path(struct zf_stack* st, struct zf_path* path,
                     bool wait);


struct zf_if_info {
  int hw_ifindices[ZF_MAX_NICS];
  int hw_ifindices_n;
  /* If we're using a higher-order interface, this value is the ifindex of the
   * parent interface _in its own namespace_ (which might or might not be the
   * same as the namespace of the specified interface).  Otherwise, it's the
   * ifindex of the interface itself. */
  int ifindex;
  char name[IF_NAMESIZE];
  ci_uint8 mac_addr[6];
  cicp_encap_t encap;
};

extern int zf_cplane_get_iface_info(int ifindex, zf_if_info* info_out);
extern int zf_cplane_get_ifindex(const char* interface);
extern void zf_path_pin_zock(struct zf_stack* st, struct zf_tx* tx);


/* zf_hal.h MUST be included after __zf_cplane_get_* declarations. */
#include <zf_internal/private/zf_hal.h>

static inline void zf_path_init(struct zf_path* path, uint32_t dstaddr,
                                uint32_t srcaddr)
{
  path->dst = dstaddr;
  path->src = srcaddr;
  path->vlan = ZF_NO_VLAN;
  path->rc = ZF_PATH_NOROUTE;
  path->nicno = -1;
}


ZF_COLD
static inline ZF_NOINLINE void zf_path_dump(struct zf_path* path)
{
  ZF_INET_NTOP_DECLARE_BUF(dbuf);
  ZF_INET_NTOP_DECLARE_BUF(sbuf);
 
  zf_dump("  path: dst=%s src=%s nic=%d\n", ZF_INET_NTOP_CALL(path->dst, dbuf),
          ZF_INET_NTOP_CALL(path->src, sbuf), path->nicno);
#if 0
  /* TODO: The MAC addresses live inside packet buffers.  Handle the mappings
   * accordingly. */
  zf_dump("  path: mac=%02x:%02x:%02x:%02x:%02x:%02x vlan=%u mtu=%u rc=%u\n",
          path->mac[0], path->mac[1], path->mac[2], path->mac[3],
          path->mac[4], path->mac[5], path->vlan, path->mtu, path->rc);
#endif
}

#endif

