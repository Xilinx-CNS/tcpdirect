/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF: TCP
 */

#include <zf/zf.h>
#include <zf_internal/shim/shim.h>
#include <zf/zf_ds.h>

/* Include TCP_MIN_MSS definition.
 * Fixme: do we need an official ZF API call to tell the user how much data
 * he can send via the given TCP connection? */
#include <zf_internal/tcp.h>

#include <netinet/tcp.h>
#include <signal.h>


enum zfss_tcp_state {
  ZFSS_TCP_CLOSED,
  ZFSS_TCP_CONNECTED,
  ZFSS_TCP_LISTENING,
};
struct zfss_tcp_socket {
  struct zfss_socket sock;

  enum zfss_tcp_state state;

  struct zft* conn;
  struct zftl* listen;

  /* Use with ZFSS_TCP_CONNECTED only: */
#define ZFSS_TCP_RX_IOV_CNT 5
  struct {
    /* Index in iov2 array to deliver to user. */
    int idx;

    /* zft_error() does not drop error when delivered to user;
     * Socket API does the opposite. */
    bool error_delivered;

    /* we have not returned OK from the connect() call yet. */
    bool not_connected;

    /* Writable copy of the zcr.iov below. */
    struct iovec iov2[ZFSS_TCP_RX_IOV_CNT];

    /* ZF zero-copy message and iov it uses.
     * This io vector is not writable by the shim.
     * The space for the iovec needs to be allocated at the end of this
     * struct. */
    struct zft_msg zcr;
  } rx_rec;
};

/* Call zf_reactor_perform() and relax if there is nothing useful;
 * re-check condition as soon as reactor returns new events. */
template <typename CondFunctor>
static int REACTOR_WHILE_CONDITION(CondFunctor cond)
{
  while( cond() ) {
    int rc = zfss_block_on_stack();
    if( rc < 0 )
      return rc;
  }

  return 0;
}

static void zfss_set_tcp_opts(struct zfss_socket* sock);


void
zfss_tcp_sys_unbind(struct zfss_socket* sock)
{
  zf_log_ss_trace(stack, "%s(%d)\n", __func__, sock->file.fd);
  int fd = zf_sys_socket(AF_INET, SOCK_STREAM, 0);
  dup2(fd, sock->file.fd);
  close(fd);
}


int
zfss_tcp_bind(struct zfss_socket* sock, const struct sockaddr* addr,
              socklen_t addrlen)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state != ZFSS_TCP_CLOSED )
    return -EINVAL;

  int rc = zfss_sys_bind(sock->file.fd, addr, addrlen);
  if( rc != 0 )
    return -errno;

  rc = zfss_bind(sock, addr, addrlen);
  if( rc != 0 )
    zfss_tcp_sys_unbind(sock);
  return rc;
}


static void
zfss_tcp_connected_init(struct zfss_tcp_socket* tcp_sock)
{
  tcp_sock->state = ZFSS_TCP_CONNECTED;
  tcp_sock->rx_rec.zcr.iovcnt = 0;
  tcp_sock->rx_rec.error_delivered = false;
  tcp_sock->rx_rec.not_connected = false;
}


static int
zfss_tcp_connect(struct zfss_socket* sock, const struct sockaddr* addr,
                 socklen_t addrlen)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state == ZFSS_TCP_CONNECTED ) {
    if( ! tcp_sock->rx_rec.not_connected )
      return -EALREADY;
    if( zft_state(tcp_sock->conn) == TCP_SYN_SENT )
      return -EINPROGRESS;
    tcp_sock->rx_rec.not_connected = false;
    return 0;
  }
  if( tcp_sock->state == ZFSS_TCP_LISTENING )
    return -EINVAL;

  int rc = zfss_set_raddr(sock, addr, addrlen);
  if( rc < 0 )
    return rc;

  if( sock->flags & ZFSS_FLAG_BOUND ) {
    zfss_tcp_sys_unbind(sock);
  }
  else {
    sockaddr any {AF_INET};
    rc = zfss_bind(sock, &any, sizeof(sockaddr_in));
    if( rc != 0 )
      return rc;
  }

  struct zft_handle* tcp_handle;
  rc = zft_alloc(stack, attr, &tcp_handle);
  if( rc != 0 )
    return rc;

  rc = zft_addr_bind(tcp_handle, (struct sockaddr*)&sock->laddr,
                     sizeof(sock->laddr), 0);
  if( rc != 0 ) {
    zft_handle_free(tcp_handle);
    return rc;
  }

  rc = zft_connect(tcp_handle, (struct sockaddr*)&sock->raddr,
                   sizeof(sock->raddr), &tcp_sock->conn);
  if( rc != 0 ) {
    zft_handle_free(tcp_handle);
    return rc;
  }

  zfss_tcp_connected_init(tcp_sock);
  socklen_t laddrlen = sizeof(sock->laddr);
  socklen_t raddrlen = sizeof(sock->raddr);
  zft_getname(tcp_sock->conn, (struct sockaddr*)&sock->laddr, &laddrlen,
              (struct sockaddr*)&sock->raddr, &raddrlen);

  if( sock->waitable != NULL ) {
    zf_waitable_set(sock->waitable, EPOLLIN, false);
  }

  if( sock->flags & ZFSS_FLAG_NONBLOCK ) {
    zfss_stack_poll();
    tcp_sock->rx_rec.not_connected = true;
    return -EINPROGRESS;
  }
  auto cond = [tcp_sock] { return zft_state(tcp_sock->conn) == TCP_SYN_SENT; };
  int rc1 = REACTOR_WHILE_CONDITION(cond);
  if( rc1 < 0 ) {
    tcp_sock->rx_rec.not_connected = true;
    return rc1;
  }
  int error = zft_error(tcp_sock->conn);
  if( error == 0 )
    return 0;

  tcp_sock->state = ZFSS_TCP_CLOSED;
  zft_free(tcp_sock->conn);
  tcp_sock->conn = NULL;
  return -error;
}


static int
zfss_tcp_listen(struct zfss_socket* sock, int backlog)
{
  if( sock->flags & ZFSS_FLAG_BOUND )
    zfss_tcp_sys_unbind(sock);

  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state != ZFSS_TCP_CLOSED )
    return -EINVAL;
  int rc = zftl_listen(stack, (struct sockaddr*)&sock->laddr,
                       sizeof(sock->laddr), attr, &tcp_sock->listen);
  if( rc < 0 )
    return rc;
  socklen_t laddrlen = sizeof(sock->laddr);
  zftl_getname(tcp_sock->listen, (struct sockaddr*)&sock->laddr, &laddrlen);
  tcp_sock->state = ZFSS_TCP_LISTENING;
  return 0;
}

static struct zfss_tcp_socket* zfss_alloc_tcp_socket(void)
{
  return (struct zfss_tcp_socket*)
    malloc(sizeof(struct zfss_tcp_socket) +
           sizeof(iovec) * ZFSS_TCP_RX_IOV_CNT);
}


static int
zfss_tcp_accept4(struct zfss_socket* sock,
                 struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);

  if( tcp_sock->state != ZFSS_TCP_LISTENING )
    return -EINVAL;

  struct zft* conn;

  /* Ensure we've handled all events */
  zfss_stack_poll();

  if( zftl_accept(tcp_sock->listen, &conn) < 0 ) {
    if( sock->flags & ZFSS_FLAG_NONBLOCK )
      return -EAGAIN;
    auto cond = [tcp_sock, &conn] () mutable {
      return zftl_accept(tcp_sock->listen, &conn) < 0;
    };
    int rc = REACTOR_WHILE_CONDITION(cond);
    if( rc < 0 )
      return rc;
  }

  zf_assert(conn);
  zf_assert_nequal(zft_state(conn), TCP_SYN_RECV);

  struct zfss_tcp_socket* acc_sock = zfss_alloc_tcp_socket();
  if( acc_sock == NULL ) {
    /* Fixme: we leak the conn, but malloc never fails :-) */
    return -ENOMEM;
  }
  zfss_tcp_connected_init(acc_sock);
  acc_sock->conn = conn;
  acc_sock->listen = NULL;

  struct zfss_socket* out_sock;
  out_sock = &acc_sock->sock;
  zfss_set_tcp_opts(out_sock);

  socklen_t laddrlen = sizeof(out_sock->laddr);
  socklen_t raddrlen = sizeof(out_sock->raddr);
  zft_getname(acc_sock->conn, (struct sockaddr*)&out_sock->laddr,
              &laddrlen, (struct sockaddr*)&out_sock->raddr, &raddrlen);
  if( addrlen != NULL )
    zfss_getpeername(out_sock, addr, addrlen);

  return zfss_create(AF_INET, SOCK_STREAM, IPPROTO_TCP | flags, &out_sock);
}


static int
zfss_tcp_shutdown(struct zfss_socket* sock, int how)
{
  int rc = zfss_shutdown(sock, how);
  if( rc != 0 )
    return rc;

  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state == ZFSS_TCP_CONNECTED && how != SHUT_RD ) {
    rc = zft_shutdown_tx(tcp_sock->conn);
    if( rc == -ENOTCONN ) {
      /* Linux returns 0 in the most cases here */
      int state = zft_state(tcp_sock->conn);
      if( state == TCP_TIME_WAIT || state == TCP_CLOSE )
        return rc;
      return 0;
    }
    /* If we get ENOMEM, we should supply more packet buffers. */
    zf_assert_nequal(rc, -ENOMEM);
    /* Fixme: handle -EAGAIN.  Is there any gracious way to handle it? */
    return rc;
  }

  if( tcp_sock->state == ZFSS_TCP_LISTENING && how != SHUT_WR ) {
    zftl_free(tcp_sock->listen);
    tcp_sock->listen = NULL;
    tcp_sock->state = ZFSS_TCP_CLOSED;
    return 0;
  }

  if( tcp_sock->state == ZFSS_TCP_CLOSED )
    return -ENOTCONN;

  return 0;
}


static int
zfss_tcp_getpeername(struct zfss_socket* sock, struct sockaddr *addr,
                 socklen_t *addrlen)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state != ZFSS_TCP_CONNECTED )
    return -ENOTCONN;
  return zfss_getpeername(sock, addr, addrlen);
}


static int
zfss_tcp_getsockopt(struct zfss_socket* sock, int level, int optname,
                    void *optval, socklen_t *optlen)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  int* int_val = (int*)optval;

  if( level == SOL_TCP && optname == TCP_INFO ) {
    memset(optval, 0, *optlen);
    struct tcp_info* tcp_info = (struct tcp_info*)optval;
    uint8_t *state = &tcp_info->tcpi_state;
    struct zft* ts;
    struct zf_tcp *tcp;
    zf_tick rto_ticks;
    switch( tcp_sock->state ) {
      case ZFSS_TCP_CONNECTED:
        ts = tcp_sock->conn;
        tcp = ZF_CONTAINER(struct zf_tcp, ts, ts);
        *state = zft_state(ts);
        rto_ticks = zf_tcp_timers_rto_timeout(tcp);
        tcp_info->tcpi_rto = rto_ticks * TCP_TMR_INTERVAL * 1000;
      break;
      case ZFSS_TCP_LISTENING:
        *state = TCP_LISTEN;
        break;
      case ZFSS_TCP_CLOSED:
        *state = TCP_CLOSE;
        break;
    }
    return 0;
  }
  else if( level == SOL_SOCKET) {
    switch(optname) {
      case SO_ACCEPTCONN:
        *int_val = (tcp_sock->state == ZFSS_TCP_LISTENING);
        return 0;
      case SO_ERROR:
        if( tcp_sock->state == ZFSS_TCP_CONNECTED ) {
          if( tcp_sock->rx_rec.error_delivered )
            *int_val = 0;
          else {
            *int_val = zft_error(tcp_sock->conn);
            tcp_sock->rx_rec.error_delivered = true;
          }
          return 0;
        }
        break;
    }
  }

  return zfss_sys_getsockopt(sock->file.fd, level, optname, optval, optlen);
}


int zfss_tcp_setsockopt(struct zfss_socket* sock, int level, int optname,
                        const void* optval, socklen_t optlen)
{
  return -ENOSYS;
}


static ssize_t
zfss_tcp_recv_done(struct zfss_tcp_socket* tcp_sock, ssize_t rc)
{
  int rc1 = zft_zc_recv_done(tcp_sock->conn, &tcp_sock->rx_rec.zcr);
  tcp_sock->rx_rec.zcr.iovcnt = 0;

  if( rc1 > 0 )
    return rc;

  /* We've got EOF, let's parse it and deliver to user. */
  zf_log_ss_trace(stack, "%s: zft_zc_recv_done() returned:\n\t%s\n"
                  "\terror_delivered=%d\n", __func__,
                  rc1 == 0 ? "0" : strerror(-rc1),
                  tcp_sock->rx_rec.error_delivered);

  /* We've got EOF, let's parse it and deliver to user. */
  if( rc1 == -EPIPE )
    rc1 = 0; /* recv() ignores EPIPE */

  /* Gracious shutdown && recv queue is empty: */
  if( rc1 == 0 && tcp_sock->rx_rec.zcr.pkts_left == 0 )
    zfss_shutdown(&tcp_sock->sock, SHUT_RD);

  /* Error happened and there is no data to deliver to user: */
  if( rc1 < 0 && rc == 0 ) {
    if( tcp_sock->rx_rec.error_delivered )
      return 0;
    tcp_sock->rx_rec.error_delivered = true;
    return rc1;
  }

  /* User wants the data - here it is! */
  return rc;
}

/* Copy data from the rx_rec structure to the user-supplied IO vector;
 * tell ZF that this data was proceeded; modify the return code.
 */
static ssize_t
zfss_tcp_recv_from_rec(struct zfss_tcp_socket* tcp_sock,
                       struct iovec** p_iov, size_t* p_iovcnt, ssize_t rc)
{
  while( tcp_sock->rx_rec.idx < tcp_sock->rx_rec.zcr.iovcnt ) {
    struct iovec* rxbuf = &tcp_sock->rx_rec.iov2[tcp_sock->rx_rec.idx];

    /* 0-length TCP packet which is not a pure ACK: it is FIN */
    if( rxbuf->iov_len == 0 ) {
      zfss_shutdown(&tcp_sock->sock, SHUT_RD);
      break;
    }
    size_t rc1 = zf_memcpy_flat2iov(p_iov, p_iovcnt,
                                    rxbuf->iov_base, rxbuf->iov_len,
                                    true/*update_iov*/);
    rc += rc1;
    if( rc1 < rxbuf->iov_len ) {
      rxbuf->iov_base = (void*)((uintptr_t)rxbuf->iov_base + rc1);
      rxbuf->iov_len -= rc1;
      return rc;
    }
    tcp_sock->rx_rec.idx++;
  }

  return zfss_tcp_recv_done(tcp_sock, rc);
}

static ssize_t
zfss_tcp_recvmsg(struct zfss_socket* sock, struct msghdr* msg, int flags)
{
  /* Can't handle this. We can't fall back to the OS socket either, so we
   * don't return -ENOSYS. */
  if( (flags & ~SHIM_MSG_FLAGS) != 0 )
    return -EOPNOTSUPP;

  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( tcp_sock->state != ZFSS_TCP_CONNECTED )
    return -ENOTCONN;
  zf_assert(tcp_sock->conn);
  if( sock->flags & ZFSS_FLAG_SHUT_READ ) {
    if( tcp_sock->rx_rec.error_delivered ) {
      msg->msg_flags = 0;
      return 0;
    }
    return -zft_error(tcp_sock->conn);
  }

  int dontwait = (flags & MSG_DONTWAIT) | (sock->flags & ZFSS_FLAG_NONBLOCK);
  int rc = 0;
  struct iovec local_iov[msg->msg_iovlen];
  size_t iovcnt = msg->msg_iovlen;
  struct iovec* iov = local_iov;
  bool fresh_recv = false;

  memcpy(iov, msg->msg_iov, msg->msg_iovlen * sizeof(struct iovec));

  while( true ) {

    /* there is some data - copy it to the user buffer */
    if( tcp_sock->rx_rec.zcr.iovcnt != 0 ) {
      rc = zfss_tcp_recv_from_rec(tcp_sock, &iov, &iovcnt, rc);
      msg->msg_flags = 0;

      /* User buffer is full: */
      if( iovcnt == 0 )
        return rc;
      /* No more packets in the queue: */
      if( fresh_recv && tcp_sock->rx_rec.zcr.pkts_left == 0 &&
          ~flags & MSG_WAITALL )
        return rc;
    }

    tcp_sock->rx_rec.zcr.iovcnt = ZFSS_TCP_RX_IOV_CNT;
    tcp_sock->rx_rec.idx = 0;
    zft_zc_recv(tcp_sock->conn, &tcp_sock->rx_rec.zcr, 0);
    if( tcp_sock->rx_rec.zcr.iovcnt == 1 &&
        tcp_sock->rx_rec.zcr.iov[0].iov_len == 0 ) {
      msg->msg_flags = 0;
      rc = zfss_tcp_recv_done(tcp_sock, rc);
      tcp_sock->rx_rec.zcr.iovcnt = 0;
      return rc;
    }

    fresh_recv = true;

    /* we've got some data - store the metadata to iov2
     * and go to zfss_tcp_recv_from_rec() */
    if( tcp_sock->rx_rec.zcr.iovcnt != 0 ) {
      zf_assert_le(tcp_sock->rx_rec.zcr.iovcnt, ZFSS_TCP_RX_IOV_CNT);
      memcpy(tcp_sock->rx_rec.iov2, tcp_sock->rx_rec.zcr.iov,
             sizeof(struct iovec) * tcp_sock->rx_rec.zcr.iovcnt);
      continue;
    }
    else if( rc > 0 && ~flags & MSG_WAITALL ) {
      /* No new data from the zocket, but we do have something from the receive
       * buffer to return to the caller. */
      return rc;
    }

    /* Unless the caller specified MSG_WAITALL, we should only get to this
     * point if we have read no data, either from the shim's receive buffer or
     * from the zocket itself. */
    if( ~flags & MSG_WAITALL ) {
      zf_assert_equal(rc, 0);
      zf_assert_equal(tcp_sock->rx_rec.zcr.iovcnt, 0);
    }

    /* no data - spin or exit */
    if( dontwait ) {
      /* Make sure we have processed all events */
      if( zfss_stack_poll() == 0 )
        return rc == 0 ? -EAGAIN : rc;
    }
    else {
      /* Receive queue was empty, so wait for some activity on the stack and
       * then try again. */
      int rc1 = zfss_block_on_stack();
      if( rc1 < 0 )
        return rc1;
      fresh_recv = false;
    }

    /* process all the events  */
    zfss_stack_poll();
  }

  /* Unreachable. */
}


static ssize_t
zfss_tcp_sendmsg(struct zfss_socket* sock, const struct msghdr *msg,
                 int flags)
{
  /* Can't handle this. We can't fall back to the OS socket either, so we
   * don't return -ENOSYS. */
  if( (flags & ~(SHIM_MSG_FLAGS | MSG_MORE)) != 0 )
    return -EOPNOTSUPP;

  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  if( sock->flags & ZFSS_FLAG_SHUT_WRITE ||
      tcp_sock->state != ZFSS_TCP_CONNECTED ) {
    raise(SIGPIPE);
    return -EPIPE;
  }

  size_t full_length = 0;
  for( unsigned i = 0; i < msg->msg_iovlen; i++ ) {
    full_length += msg->msg_iov[i].iov_len;
  }
  if( full_length == 0 ) {
    /* zft_send dislikes 0-length packets, but socket tester uses it to
     * find out the TCP state. */
    switch( zft_state(tcp_sock->conn) ) {
      case TCP_ESTABLISHED:
      case TCP_CLOSE_WAIT:
        return 0;
      default:
        raise(SIGPIPE);
        return -EPIPE;
    }
  }

  zf_assert(tcp_sock->conn);
  int dontwait = (flags & MSG_DONTWAIT) | (sock->flags & ZFSS_FLAG_NONBLOCK);

  size_t sent = 0;
  size_t iov_cnt = msg->msg_iovlen;
  struct iovec iov[iov_cnt];
  struct iovec* iov_p = iov;
  memcpy(iov, msg->msg_iov, sizeof(struct iovec) * iov_cnt);
  int rc;
 do_send:
  do {
    rc = zft_send(tcp_sock->conn, iov_p, iov_cnt, flags & MSG_MORE);
    zf_assume_nequal(rc, 0);
    if( rc > 0 ) {
      sent += rc;
      if( sent == full_length )
        return sent;

      /* Move iov_p & iov_cnt to the unsent data. */
      while( (unsigned)rc >= iov_p[0].iov_len ) {
        rc -= iov_p[0].iov_len;
        iov_p++;
        iov_cnt--;
        /* It was a partial send, so iov_cnt is always positive. */
        zf_assume_gt(iov_cnt, 0);
      }
      if( rc != 0 ) {
        iov_p[0].iov_base = (char*)iov_p[0].iov_base + rc;
        iov_p[0].iov_len -= rc;
      }
      break;
    }

    /* We've got an error.  Let's handle it. */
    if( rc == -EAGAIN )
      break;
    if( sent > 0 )
      return sent;

    if( rc == -ENOTCONN ) {
      rc = -zft_error(tcp_sock->conn);
      if( tcp_sock->rx_rec.error_delivered )
        rc = -EPIPE;
      else
        tcp_sock->rx_rec.error_delivered = true;
      zfss_shutdown(sock, SHUT_WR);
      if( rc == -EPIPE )
        raise(SIGPIPE);
      return rc;
    }
    if( rc != -EAGAIN ) {
      /* It can be -ENOMEM when out of buffers, or anything else which we do
       * not know how to handle. */
      zf_assert(0);
      return rc;
    }
  } while( 0 );

  /* Can't send more data: exit or spin. */
  if( dontwait ) {
    if( zfss_stack_poll() == 0 )
      return rc;
    else
      goto do_send;
  }
  rc = zfss_block_on_stack();
  if( rc < 0 )
    return rc;
  goto do_send;

  /* Unreachable */
}


static int
zfss_tcp_close(struct zfss_socket* sock)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);

  if( tcp_sock->conn != NULL ) {
    zft_free(tcp_sock->conn);
    zf_assert_equal(tcp_sock->state, ZFSS_TCP_CONNECTED);
    zf_assert_equal(tcp_sock->listen, NULL);
  }
  else if( tcp_sock->listen != NULL ) {
    zftl_free(tcp_sock->listen);
    zf_assert_equal(tcp_sock->state, ZFSS_TCP_LISTENING);
  }
  else {
    zf_assert_equal(tcp_sock->state, ZFSS_TCP_CLOSED);
  }
  return 0;
}


static uint32_t zfss_tcp_events(struct zfss_socket* sock)
{
  uint32_t events = zfss_events(sock);
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);

  if( tcp_sock->state == ZFSS_TCP_CLOSED )
    events |= EPOLLOUT | EPOLLHUP;
  return events;
}

int zfss_tcp_waitables(struct zfss_socket* sock, struct zfss_waitable* wait)
{
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  int ret = 1;

  wait[0].w = zfss_sock_waitable(sock);
  wait[0].ev = EPOLLIN | EPOLLHUP;

  switch( tcp_sock->state ) {
    case ZFSS_TCP_CLOSED:
      break;
    case ZFSS_TCP_LISTENING:
      wait[ret].w = zftl_to_waitable(tcp_sock->listen);
      wait[ret].ev = EPOLLIN;
      ret++;
      break;
    case ZFSS_TCP_CONNECTED:
      wait[ret].w =  zft_to_waitable(tcp_sock->conn);
      wait[ret].ev = EPOLLIN | EPOLLOUT | EPOLLHUP;
      ret++;
  }

  return ret;
}


static const struct zfss_socket_ops tcp_ops = {
  .close    = zfss_tcp_close,
  .bind     = zfss_tcp_bind,
  .connect  = zfss_tcp_connect,
  .listen   = zfss_tcp_listen,
  .accept4  = zfss_tcp_accept4,
  .accept   = zfss_accept,
  .shutdown = zfss_tcp_shutdown,
  .getsockname = zfss_getsockname,
  .getpeername = zfss_tcp_getpeername,
  .getsockopt  = zfss_tcp_getsockopt,
  .setsockopt  = zfss_tcp_setsockopt,

  .recvmmsg = zfss_recvmmsg,
  .recvmsg  = zfss_tcp_recvmsg,
  .recvfrom = zfss_recvfrom,
  .recv     = zfss_recv,
  .read     = zfss_read,
  .readv    = zfss_readv,

#if SHIM_SENDMMSG
  .sendmmsg = zfss_sendmmsg,
#endif
  .sendmsg  = zfss_tcp_sendmsg,
  .sendto   = zfss_sendto,
  .send     = zfss_send,
  .write    = zfss_write,
  .writev   = zfss_writev,

  .events    = zfss_tcp_events,
  .waitables = zfss_tcp_waitables,
};
static void zfss_set_tcp_opts(struct zfss_socket* sock)
{
  sock->ops = &tcp_ops;
}

int zfss_create_tcp(struct zfss_socket** sock_out)
{
  struct zfss_tcp_socket* tcp_sock = zfss_alloc_tcp_socket();

  if( tcp_sock == NULL )
    return -ENOMEM;

  
  tcp_sock->state = ZFSS_TCP_CLOSED;
  tcp_sock->conn = NULL;
  tcp_sock->listen = NULL;

  zfss_set_tcp_opts(&tcp_sock->sock);
  *sock_out = &tcp_sock->sock;
  return 0;
}

static inline enum onload_delegated_send_rc
zf_rc2od(enum zf_delegated_send_rc zf)
{
  enum onload_delegated_send_rc od;

#define ZF_RC2OD(_rc) \
  do {                                            \
    if ( zf == ZF_DELEGATED_SEND_RC_##_rc )       \
      od = ONLOAD_DELEGATED_SEND_RC_##_rc;        \
    } while (0)
    ZF_RC2OD(OK);
    ZF_RC2OD(BAD_SOCKET);
    ZF_RC2OD(SMALL_HEADER);
    ZF_RC2OD(SENDQ_BUSY);
    ZF_RC2OD(NOARP);
    ZF_RC2OD(NOWIN);
    ZF_RC2OD(NOCWIN);
#undef ZF_RC2OD

  return od;
}

static inline void
zf_ds2ods(struct zf_ds* zf, struct onload_delegated_send *od)
{
  od->headers = zf->headers;
  od->headers_len = zf->headers_len;
  od->mss = zf->mss;
  od->send_wnd = zf->send_wnd;
  od->cong_wnd = zf->cong_wnd;
  od->user_size = zf->delegated_wnd;
  od->tcp_seq_offset = zf->tcp_seq_offset;
  od->ip_len_offset = zf->ip_len_offset;
  od->ip_tcp_hdr_len = zf->ip_tcp_hdr_len;
}

static inline void
ods2zf_ds(struct onload_delegated_send *od, struct zf_ds* zf)
{
  zf->headers = od->headers;
  zf->headers_len = od->headers_len;
  zf->headers_size = od->headers_len;
  zf->mss = od->mss;
  zf->send_wnd = od->send_wnd;
  zf->cong_wnd = od->cong_wnd;
  zf->delegated_wnd = od->user_size;
  zf->tcp_seq_offset = od->tcp_seq_offset;
  zf->ip_len_offset = od->ip_len_offset;
  zf->ip_tcp_hdr_len = od->ip_tcp_hdr_len;
}

enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out)
{
  struct zft* ts;
  struct zf_ds ds;
  enum zf_delegated_send_rc zf_rc;
  enum onload_delegated_send_rc od_rc;
  struct zfss_socket* sock = zfss_fd_table_get_sock(fd);
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  zf_log_ss_info(stack, "::%s(%d, %d, %d, ...)\n", __func__, fd, size, flags);

  ts = tcp_sock->conn;

  memset(&ds, 0, sizeof(ds));
  ds.headers_size = out->headers_len;
  ds.headers = out->headers;

  zf_rc = zf_delegated_send_prepare(ts, size, 0, 0, &ds);
  out->user_size = size;

  zf_ds2ods(&ds, out);
  od_rc = zf_rc2od(zf_rc);

  zf_log_ss_info(stack, "::%s() -> %d\n", __func__, od_rc);
  return od_rc;
}

void onload_delegated_send_tcp_update(struct onload_delegated_send* ds,
                                      int bytes, int push)
{
  struct zf_ds zf_ds;

  zf_log_ss_info(stack, "::%s(%p, %d, %d)\n", __func__, ds, bytes, push);

  memset(&zf_ds, 0, sizeof(zf_ds));
  ods2zf_ds(ds, &zf_ds);

  zf_delegated_send_tcp_update(&zf_ds, bytes, push);
  zf_ds2ods(&zf_ds, ds);

  zf_log_ss_info(stack, "::%s() -> OK\n", __func__);
}

void onload_delegated_send_tcp_advance(struct onload_delegated_send* ds,
                                       int bytes)
{
  struct zf_ds zf_ds;

  zf_log_ss_info(stack, "::%s(%p, %d, %d)\n", __func__, ds, bytes);

  memset(&zf_ds, 0, sizeof(zf_ds));
  ods2zf_ds(ds, &zf_ds);

  zf_delegated_send_tcp_advance(&zf_ds, bytes);
  zf_ds2ods(&zf_ds, ds);

  zf_log_ss_info(stack, "::%s() -> OK\n", __func__);
}

int onload_delegated_send_complete(int fd, const struct iovec* iov,
                                   int iovlen, int flags)
{
  int rc;
  struct zft* ts;
  struct zfss_socket* sock = zfss_fd_table_get_sock(fd);
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);
  zf_log_ss_info(stack, "::%s(%d, %p, %d, %d, ...)\n", __func__,
                 fd, iov, iovlen, flags);

  ts = tcp_sock->conn;

  rc = zf_delegated_send_complete(ts, iov, iovlen, 0);
  zf_reactor_perform(stack);

  if( rc < 0 ) {
    errno = -rc;
    rc = -1;
  }

  zf_log_ss_info(stack, "::%s() -> %d\n", __func__, rc);
  return rc;
}

int onload_delegated_send_cancel(int fd)
{
  int rc;
  struct zft* ts;
  struct zfss_socket* sock = zfss_fd_table_get_sock(fd);
  struct zfss_tcp_socket* tcp_sock = ZF_CONTAINER(struct zfss_tcp_socket,
                                                  sock, sock);

  zf_log_ss_info(stack, "::%s(%d)\n", __func__, fd);

  ts = tcp_sock->conn;
  rc = zf_delegated_send_cancel(ts);

  zf_log_ss_info(stack, "::%s() -> %d\n", __func__, rc);
  return rc;
}
