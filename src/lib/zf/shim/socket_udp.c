/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF: UDP.
 */

#include <zf/zf.h>
#include <zf_internal/shim/shim.h>

#include <arpa/inet.h>
#include <signal.h>


#define ZF_MAX_MCAST_ADDRS 64

struct zfss_udp_socket {
  struct zfss_socket sock;

  struct zfur* rx;
  /* We store a zfut only for connected sends.  Otherwise, we allocate them as
   * needed. */
  struct zfut* tx_connected;

  struct in_addr mcast_addrs[ZF_MAX_MCAST_ADDRS];
};



/* Check if already subscribed to this group and find an empty slot in
 * the socket's multicast address array.
 */
static int zfss_udp_mcast_add(struct zfss_udp_socket* udp_sock,
                              struct in_addr* maddr)
{
  for( int i = ZF_MAX_MCAST_ADDRS - 1; i >= 0; --i ) {
    struct in_addr* idx_addr = &udp_sock->mcast_addrs[i];
    if( idx_addr->s_addr == maddr->s_addr )
      return -EADDRINUSE;
    if( idx_addr->s_addr == INADDR_ANY ) {
      *idx_addr = *maddr;
      zf_log_ss_trace(stack, "%s[%d] %s\n", __func__, i, inet_ntoa(*maddr));
      return i;
    }
  }
  return -ENOSPC;
}

/* Join zfur to a multicast address. */
static int zfss_udp_mcast_join(struct zfss_udp_socket* udp_sock,
                               int idx)
{
  struct sockaddr_in addr;
  int rc;
  bool zero_port;

  addr.sin_family = AF_INET;
  addr.sin_addr = udp_sock->mcast_addrs[idx];
  addr.sin_port = udp_sock->sock.laddr.sin_port;
  zero_port = ( addr.sin_port == 0 );
  zf_log_ss_trace(stack, "%s[%d] %s:%d %s:%d\n", __func__, idx,
         inet_ntoa(addr.sin_addr), htons(addr.sin_port),
         inet_ntoa(udp_sock->sock.raddr.sin_addr),
         htons(udp_sock->sock.raddr.sin_port));

  rc = zfur_addr_bind(udp_sock->rx, (struct sockaddr*)&addr, sizeof(addr),
                      (struct sockaddr*)&udp_sock->sock.raddr,
                      sizeof(udp_sock->sock.raddr), 0);
  if( rc == 0 ) {
    if( zero_port )
      udp_sock->sock.laddr.sin_port = addr.sin_port;
    return 0;
  }
  udp_sock->mcast_addrs[idx].s_addr = INADDR_ANY;
  return rc;
}

static int zfss_udp_mcast_leave_idx(struct zfss_udp_socket* udp_sock,
                                    int idx)
{
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = udp_sock->mcast_addrs[idx].s_addr;
  addr.sin_port = udp_sock->sock.laddr.sin_port;
  zf_log_ss_trace(stack, "%s[%d] %s:%d %s:%d\n", __func__, idx,
                  inet_ntoa(addr.sin_addr), htons(addr.sin_port),
                  inet_ntoa(udp_sock->sock.raddr.sin_addr),
                  htons(udp_sock->sock.raddr.sin_port));

  return zfur_addr_unbind(udp_sock->rx, (struct sockaddr*)&addr, sizeof(addr),
                          (struct sockaddr*)&udp_sock->sock.raddr,
                          sizeof(udp_sock->sock.raddr), 0);
}

/* Leave a multicast group - remove a multicast filter. */
static int zfss_udp_mcast_leave(struct zfss_udp_socket* udp_sock,
                                struct in_addr* maddr)
{
  for( int i = 0; i < ZF_MAX_MCAST_ADDRS; ++i ) {
    struct in_addr* idx_addr = &udp_sock->mcast_addrs[i];
    if( idx_addr->s_addr == maddr->s_addr ) {
      int rc = 0;
      if( udp_sock->rx != NULL )
        rc = zfss_udp_mcast_leave_idx(udp_sock, i);
      idx_addr->s_addr = INADDR_ANY;
      return rc;
    }
  }
  /* Not subscribed to this address */
  return -EADDRNOTAVAIL;
}


static int
zfss_udp_bind(struct zfss_socket* sock, const struct sockaddr* addr,
              socklen_t addrlen)
{
  int rc = zfss_bind(sock, addr, addrlen);
  if( rc < 0 )
    return rc;

  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);
  if( udp_sock->rx != NULL )
    return -EINVAL;

  rc = zfur_alloc(&udp_sock->rx, stack, attr);
  if( rc < 0 )
    return rc;

  /* We do not insert the filter for multicast address, because user has to
   * join if he really wants to receive anything. */
  if( ! IN_MULTICAST(ntohl(sock->laddr.sin_addr.s_addr)) )
    rc = zfur_addr_bind(udp_sock->rx, (struct sockaddr*)&sock->laddr,
                        sizeof(sock->laddr), NULL, 0, 0);

  if( rc == 0 ) {
    /* Join requested multicast groups */
    for( int i = ZF_MAX_MCAST_ADDRS - 1; i >= 0; --i ) {
      if( udp_sock->mcast_addrs[i].s_addr != INADDR_ANY ) {
        rc = zfss_udp_mcast_join(udp_sock, i);
        if( rc < 0 )
          break;
      }
    }
  }

  if( rc < 0 ) {
    /* Clean up socket and zocket states if any bind operation failed */
    zfss_set_laddr(sock, &laddr_implict);
    sock->flags &= ~ZFSS_FLAG_BOUND;
    zfur_free(udp_sock->rx);
    udp_sock->rx = NULL;
  }

  return rc;
}

static int
zfss_udp_connect(struct zfss_socket* sock, const struct sockaddr* addr,
                 socklen_t addrlen)
{
  /* Fixme: error path in filter-related code here is completely wrong. */

  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);
  int rc;

  /* Remove all multicast filters */
  for( int i = ZF_MAX_MCAST_ADDRS - 1; i >= 0; --i ) {
    if( udp_sock->mcast_addrs[i].s_addr != INADDR_ANY ) {
      rc = zfss_udp_mcast_leave_idx(udp_sock, i);
      zf_assert_equal(rc, 0);
    }
  }

  if( ! (sock->flags & ZFSS_FLAG_BOUND) ) {
    rc = zfss_udp_bind(sock, (struct sockaddr *)&sock->laddr,
                       sizeof(sock->laddr)); 
    zf_assert_equal(rc, 0);
  }

  rc = zfss_set_raddr(sock, addr, addrlen);
  if( rc < 0 )
    return rc;

  /* Replace wild RX filter by full-match RX filter */
  if( ! IN_MULTICAST(ntohl(sock->laddr.sin_addr.s_addr)) ) {
    rc = zfur_addr_unbind(udp_sock->rx, (struct sockaddr*)&sock->laddr,
                          sizeof(sock->laddr), NULL, 0, 0);
    zf_assert_equal(rc, 0);
    rc = zfur_addr_bind(udp_sock->rx, (struct sockaddr*)&sock->laddr,
                        sizeof(sock->laddr), (struct sockaddr*)&sock->raddr,
                        sizeof(sock->raddr), 0);
    if( rc != 0 )
      return rc;
  }

  /* Reinstall all multicast filters */
  for( int i = ZF_MAX_MCAST_ADDRS - 1; i >= 0; --i ) {
    if( udp_sock->mcast_addrs[i].s_addr != INADDR_ANY ) {
      rc = zfss_udp_mcast_join(udp_sock, i);
      if( rc < 0 )
        break;
    }
  }

  rc = zfut_alloc(&udp_sock->tx_connected, stack,
                  (struct sockaddr*)&sock->laddr, sizeof(sock->laddr),
                  (struct sockaddr*)&sock->raddr, sizeof(sock->raddr),
                  0, attr);
  if( rc < 0 ) {
    struct sockaddr_in zero_addr = { 0 };
    zero_addr.sin_family = AF_INET;
    zfss_set_raddr(sock, (const struct sockaddr*)&zero_addr,
                   sizeof(zero_addr));
  }
  else if( sock->waitable != NULL ) {
    /* EPOLLOUT will be reported by tx_connected from now on */
    zf_waitable_set(sock->waitable, EPOLLOUT, false);
  }
  return rc;
}


int
zfss_udp_shutdown(struct zfss_socket* sock, int how)
{
  int rc = zfss_shutdown(sock, how);
  if( rc != 0 )
    return rc;

  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket,
                                                  sock, sock);
  if( udp_sock->rx != NULL && how != SHUT_WR ) {
    zfur_free(udp_sock->rx);
    udp_sock->rx = NULL;
  }
  if( udp_sock->tx_connected != NULL && how != SHUT_RD ) {
    zfut_free(udp_sock->tx_connected);
    udp_sock->tx_connected = NULL;
  }
  return 0;
}


static int zfss_udp_setsockopt_mcast(struct zfss_socket* sock,
                                     const void* optval, socklen_t optlen,
                                     bool join)
{
  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket,
                                                  sock, sock);
  struct ip_mreqn* mreq;

  if( optlen != sizeof(struct ip_mreqn) )
    return -EINVAL;

  mreq = (struct ip_mreqn*)optval;

  if( join ) {
    int idx = zfss_udp_mcast_add(udp_sock, &mreq->imr_multiaddr);
    if( idx < 0 )
      return idx;
    if( sock->flags & ZFSS_FLAG_BOUND )
      return zfss_udp_mcast_join(udp_sock, idx);
    else
      return 0;
  }
  else {
    return zfss_udp_mcast_leave(udp_sock, &mreq->imr_multiaddr);
  }
}

int zfss_udp_setsockopt(struct zfss_socket* sock, int level, int optname,
                        const void* optval, socklen_t optlen)
{
  if( level == SOL_IP ) {
    switch( optname ) {
    case IP_ADD_MEMBERSHIP:
    case IP_DROP_MEMBERSHIP:
      return zfss_udp_setsockopt_mcast(sock, optval, optlen,
                                       optname == IP_ADD_MEMBERSHIP);
    default:
      return -ENOSYS;
    }
  }

  return -ENOSYS;
}

static ssize_t
zfss_udp_recvmsg(struct zfss_socket* sock, struct msghdr* msg, int flags)
{
  /* Can't handle this. We can't fall back to the OS socket either, so we
   * don't return -ENOSYS. */
  if( (flags & ~SHIM_MSG_FLAGS) != 0 )
    return -EOPNOTSUPP;
  if( sock->flags & ZFSS_FLAG_SHUT_READ )
    return 0;

  int rc = 0;
  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);
  int dontwait = (flags & MSG_DONTWAIT) | (sock->flags & ZFSS_FLAG_NONBLOCK);

  while( 1 ) {
    struct {
      struct zfur_msg zcr;
      struct iovec iov[1];
    } rx_record;
    rx_record.zcr.iovcnt = 1;

    /* Grab up to one packet buffer from ZF. */
    zfur_zc_recv(udp_sock->rx, &rx_record.zcr, 0);

    /* Did anything arrive? */
    if( rx_record.zcr.iovcnt != 0 ) {
      zf_assert_equal(rx_record.zcr.iovcnt, 1);

      /* Copy as much as we can fit into the caller's buffer. */
      rc = zf_memcpy_flat2iov(&msg->msg_iov, &msg->msg_iovlen,
                              rx_record.iov[0].iov_base,
                              rx_record.iov[0].iov_len,
                              false/*update_iov*/);

      msg->msg_flags = 0;
      /* TODO: msg_control != NULL. */

      if( msg->msg_namelen >= sizeof(struct sockaddr_in) &&
          msg->msg_name != NULL ) {
        const struct iphdr* ip;
        const struct udphdr* udp;
        struct sockaddr_in* addr = (struct sockaddr_in*)msg->msg_name;

        zfur_pkt_get_header(udp_sock->rx, &rx_record.zcr, &ip, &udp, 0);

        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = ip->saddr;
        addr->sin_port = udp->source;
        msg->msg_namelen = sizeof(struct sockaddr_in);
      }
      /* else we do not care to fill in partial sockaddr_in */

      zfur_zc_recv_done(udp_sock->rx, &rx_record.zcr);

      return rc;
    }
    else if( dontwait ) {
      /* Make sure we have processed all events */
      if( zf_reactor_perform(stack) == 0 )
        return -EAGAIN;
    }
    else {
      /* Receive queue was empty, so wait for some activity on the stack and
       * then try again. */
      if( (rc = zfss_block_on_stack()) < 0 )
        return rc;
    }
  }

  /* Unreachable. */
}


static ssize_t
zfss_udp_sendmsg(struct zfss_socket* sock, const struct msghdr *msg,
                 int flags)
{
  if( (flags & ~SHIM_MSG_FLAGS) != 0 )
    return -EOPNOTSUPP;
  if( sock->flags & ZFSS_FLAG_SHUT_WRITE ) {
#if 0
    /* Linux does not send SIGPIPE in case of UDP. */
    raise(SIGPIPE);
#endif
    return -EPIPE;
  }

  /* For a non-bound socket we should bind and find out the port in use. */
  int rc;
  if( ! (sock->flags & ZFSS_FLAG_BOUND) ) {
    rc = zfss_udp_bind(sock, (struct sockaddr *)&sock->laddr,
                       sizeof(sock->laddr));
    if( rc != 0 )
      return rc;
  }

  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);
  struct zfut* tx;

  /* We do not handle MSG_DONTWAIT in UDP send */

  if( udp_sock->tx_connected != NULL ) {
    tx = udp_sock->tx_connected;
    goto do_send;
  }
  /* We only support sockaddr_in and unconnected sends. */
  if( msg->msg_namelen < sizeof(struct sockaddr_in) ||
      msg->msg_name == NULL )
    return -ENOSYS;

  rc = zfut_alloc(&tx, stack,
                  (struct sockaddr*)&sock->laddr, sizeof(sock->laddr),
                  (struct sockaddr*)msg->msg_name, msg->msg_namelen,
                  0, attr);
  if( rc < 0 )
    return rc;

 do_send:
  rc = zfut_send(tx, msg->msg_iov, msg->msg_iovlen, 0);
  if( rc == -EAGAIN ) {
    rc = zfss_block_on_stack();
    if( rc < 0 )
      return rc;
    goto do_send;
  }

  if( tx != udp_sock->tx_connected )
    zfut_free(tx);
  return rc;
}


static int
zfss_udp_close(struct zfss_socket* sock)
{
  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);

  if( udp_sock->tx_connected != NULL )
    zfut_free(udp_sock->tx_connected);
  udp_sock->tx_connected = NULL;

  if( udp_sock->rx != NULL )
    zfur_free(udp_sock->rx);
  udp_sock->rx = NULL;

  return 0;
}


static uint32_t zfss_udp_events(struct zfss_socket* sock)
{
  uint32_t events = zfss_events(sock);
  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);

  if( udp_sock->tx_connected == NULL )
    events |=  EPOLLOUT;
  return events;
}

static int
zfss_udp_waitables(struct zfss_socket* sock, struct zfss_waitable* wait)
{
  struct zfss_udp_socket* udp_sock = ZF_CONTAINER(struct zfss_udp_socket, sock,
                                                  sock);
  int ret = 1;

  wait[0].w = zfss_sock_waitable(sock);
  wait[0].ev = EPOLLIN | EPOLLOUT | EPOLLHUP;

  if( udp_sock->rx != NULL ) {
    wait[ret].w = zfur_to_waitable(udp_sock->rx);
    wait[ret].ev = EPOLLIN;
    ret++;
  }
  if( udp_sock->tx_connected != NULL ) {
    wait[ret].w = zfut_to_waitable(udp_sock->tx_connected);
    wait[ret].ev = EPOLLOUT;
    ret++;
  }
  return ret;
}


static const struct zfss_socket_ops udp_ops = {
  .close    = zfss_udp_close,
  .bind     = zfss_udp_bind,
  .connect  = zfss_udp_connect,
  .listen   = zfss_no_listen,
  .accept4  = zfss_no_accept4,
  .accept   = zfss_accept,
  .shutdown = zfss_udp_shutdown,
  .getsockname = zfss_getsockname,
  .getpeername = zfss_getpeername,
  .getsockopt  = zfss_getsockopt,
  .setsockopt  = zfss_udp_setsockopt,

  .recvmmsg = zfss_recvmmsg,
  .recvmsg  = zfss_udp_recvmsg,
  .recvfrom = zfss_recvfrom,
  .recv     = zfss_recv,
  .read     = zfss_read,
  .readv    = zfss_readv,

#if SHIM_SENDMMSG
  .sendmmsg = zfss_sendmmsg,
#endif
  .sendmsg  = zfss_udp_sendmsg,
  .sendto   = zfss_sendto,
  .send     = zfss_send,
  .write    = zfss_write,
  .writev   = zfss_writev,

  .events    = zfss_udp_events,
  .waitables = zfss_udp_waitables,
};


int zfss_create_udp(struct zfss_socket** sock_out)
{
  struct zfss_udp_socket* udp_sock = (struct zfss_udp_socket*)
                                     malloc(sizeof(struct zfss_udp_socket));
  if( udp_sock == NULL )
    return -ENOMEM;

  /* We don't allocate TX structures until we connect() or sendto(). */
  udp_sock->tx_connected = NULL;
  /* We don't allocate RX structures until we bind(). */
  udp_sock->rx = NULL;

  udp_sock->sock.ops = &udp_ops;
  memset(udp_sock->mcast_addrs, 0, sizeof(struct in_addr) * ZF_MAX_MCAST_ADDRS);
  *sock_out = &udp_sock->sock;
  return 0;
}


