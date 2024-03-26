/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_CHECKSUM_H__
#define __ZF_INT_CHECKSUM_H__

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <etherfabric/checksum.h>

#ifdef ZF_DEVEL
/* This is not used in the ZF library, but in the unit tests only. */
static inline unsigned
zf_tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp,
                const void* payload)
{
  zf_assert(ip);
  zf_assert(tcp);

  zf_assert_ge(ntohs(ip->tot_len), (ip->ihl * 4) + (tcp->doff * 4));
  if( payload == NULL )
    zf_assert_equal(ntohs(ip->tot_len), (ip->ihl * 4) + (tcp->doff *4));

  size_t paylen = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
  struct iovec iov = {(void*)(tcp + 1), paylen};
  return ef_tcp_checksum(ip, tcp, &iov, 1);
}
#endif

#endif /* __ZF_INT_CHECKSUM_H__ */
