/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_TX_TYPES_H__
#define __ZF_TX_TYPES_H__

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/cplane.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/if_ether.h>

#define UDP_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                      sizeof(struct udphdr))
#define TCP_HDR_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
                      sizeof(struct tcphdr))
_Static_assert(sizeof(struct ethhdr) == 14, "Ethernet header struct error");
_Static_assert(sizeof(struct iphdr) == 20, "IP header struct error");
_Static_assert(sizeof(struct udphdr) == 8, "UDP header struct error");
_Static_assert(sizeof(struct tcphdr) == 20, "TCP header struct error");

#define UDP_TX_ID(st, tx)      (tx - (st)->udp_tx)

/**
 * \brief state needed by fast path to receive packets
 *
 * Covers sw filter and socket receive queue.
 */
struct ethipudphdr {
  /* for now only smallest fixed size supported */
  struct ethhdr eth;
  struct iphdr ip  __attribute__((packed));
  struct udphdr udp  __attribute__((packed));
  char fill[-UDP_HDR_SIZE & 7];
};
struct ethiptcphdr {
  /* for now only smallest fixed size supported */
  struct ethhdr eth;
  struct iphdr ip  __attribute__((packed));
  struct tcphdr tcp  __attribute__((packed));
  char fill[-TCP_HDR_SIZE & 7];
};

struct ethvlanipudphdr {
  /* for now only smallest fixed size supported */
  struct ethhdr eth;
  uint16_t vlan_tag __attribute__((packed));
  uint16_t ethproto __attribute__((packed));
  struct iphdr ip  __attribute__((packed));
  struct udphdr udp  __attribute__((packed));
  char fill[-(UDP_HDR_SIZE + 4) & 7];
};
struct ethvlaniptcphdr {
  /* for now only smallest fixed size supported */
  struct ethhdr eth;
  uint16_t vlan_tag __attribute__((packed));
  uint16_t ethproto __attribute__((packed));
  struct iphdr ip  __attribute__((packed));
  struct tcphdr tcp  __attribute__((packed));
  char fill[-(TCP_HDR_SIZE + 4) & 7];
};

struct zf_tx {

  /** This is prepared pkt header cache
   * currenty does not account for variability of ip/udp header lenght */
  struct {
    union {
      struct ethipudphdr udp_novlanhdr;
      struct ethiptcphdr tcp_novlanhdr;
      struct ethvlanipudphdr udp_vlanhdr;
      struct ethvlaniptcphdr tcp_vlanhdr;
    };
  } pkt alignas(8);
  static_assert((sizeof(pkt) & 7) == 0, "size rounded up to 8 for pio");

  /* space after the respective header for pio purposes and in-place sends */
  static constexpr int udp_hdr_fill_size = sizeof(pkt) - UDP_HDR_SIZE;
  static constexpr int tcp_hdr_fill_size = sizeof(pkt) - TCP_HDR_SIZE;
  static constexpr int udp_vlanhdr_fill_size = udp_hdr_fill_size - 4;
  static constexpr int tcp_vlanhdr_fill_size = tcp_hdr_fill_size - 4;

  /* Control plane data for the destination */
  struct zf_path path;

  /* TODO: cache of pkt buffers with headers */
  #define TX_HDR_PKT_BUF_CACHE_SIZE 4
  /* struct iovec pkt_buf_cache[TX_HDR_PKT_BUF_CACHE_SIZE]; */

};


#endif
