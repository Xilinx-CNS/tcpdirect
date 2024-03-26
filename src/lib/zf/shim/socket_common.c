/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF - common helpers.
 */
#include <sys/socket.h>
#include <netinet/in.h>

#include <zf_internal/shim/shim.h>

void
zfss_set_laddr(struct zfss_socket* sock, const struct sockaddr_in* addr)
{
  zf_log_ss_trace(stack, "%s(%d, %p)\n", __func__, sock->file.fd, addr);
  /* Supply values for implicit hosts/ports. */
  struct sockaddr_in resultant_addr = *addr;
  resultant_addr.sin_family = AF_INET;
  if( resultant_addr.sin_addr.s_addr == INADDR_ANY )
    resultant_addr.sin_addr.s_addr = laddr_implict.sin_addr.s_addr;

  memcpy(&sock->laddr, &resultant_addr, sizeof(struct sockaddr_in));
}

int
zfss_bind(struct zfss_socket* sock, const struct sockaddr* addr,
          socklen_t addrlen)
{
  zf_log_ss_trace(stack, "%s(%d, %p)\n", __func__, sock->file.fd, addr);
  if( addrlen != sizeof(struct sockaddr_in) )
    return -ENOSYS;
  if( sock->flags & ZFSS_FLAG_BOUND )
    return -EALREADY;
  zfss_set_laddr(sock, (const struct sockaddr_in*)addr);
  sock->flags |= ZFSS_FLAG_BOUND;
  return 0;
}

int
zfss_set_raddr(struct zfss_socket* sock, const struct sockaddr* addr,
               socklen_t addrlen)
{
  zf_log_ss_trace(stack, "%s(%d, %p)\n", __func__, sock->file.fd, addr);
  if( addrlen != sizeof(struct sockaddr_in) )
    return -ENOSYS;
  memcpy(&sock->raddr, addr, sizeof(struct sockaddr_in));
  return 0;  
}


int
zfss_getsockname(struct zfss_socket* sock, struct sockaddr *addr,
                 socklen_t *addrlen)
{
  memcpy(addr, &sock->laddr, MIN(sizeof(sock->laddr), *addrlen));
  *addrlen = sizeof(sock->laddr);
  return 0;
}
int
zfss_getpeername(struct zfss_socket* sock, struct sockaddr *addr,
                 socklen_t *addrlen)
{
  memcpy(addr, &sock->raddr, MIN(sizeof(sock->laddr), *addrlen));
  *addrlen = sizeof(sock->laddr);
  return 0;
}


struct zf_waitable* zfss_sock_waitable(struct zfss_socket* sock)
{
  if( sock->waitable != NULL )
    return sock->waitable;

  sock->waitable = zf_waitable_alloc(stack);
  ZF_TEST(sock->waitable);
  zf_waitable_set(sock->waitable, sock->ops->events(sock), true);
  return sock->waitable;
}

uint32_t zfss_events(struct zfss_socket* sock)
{
  switch( sock->flags & (ZFSS_FLAG_SHUT_WRITE | ZFSS_FLAG_SHUT_READ) ) {
    case 0:
      return 0;
    case ZFSS_FLAG_SHUT_READ:
      return EPOLLIN;
    case ZFSS_FLAG_SHUT_WRITE:
      return EPOLLOUT;
    case ZFSS_FLAG_SHUT_WRITE | ZFSS_FLAG_SHUT_READ:
      return EPOLLIN | EPOLLOUT |EPOLLHUP;
  }
  /* Unreachable */
  return 0;
}

int
zfss_shutdown(struct zfss_socket* sock, int how)
{
  uint32_t events = 0;

  zf_log_ss_trace(stack, "%s(%d, %s)\n", __func__, sock->file.fd,
                  how == SHUT_RD ? "RD" : how == SHUT_WR ? "WR" : "RDWR");
  switch( how ) {
    case SHUT_RD:
      sock->flags |= ZFSS_FLAG_SHUT_READ;
      events = EPOLLIN;
      break;
    case SHUT_WR:
      sock->flags |= ZFSS_FLAG_SHUT_WRITE;
      events = EPOLLOUT;
      break;
    case SHUT_RDWR:
      sock->flags |= ZFSS_FLAG_SHUT_READ | ZFSS_FLAG_SHUT_WRITE;
      events = EPOLLIN | EPOLLOUT;
      break;
    default:
      return -EINVAL;
  }

  /* Set epoll events if someone is listening */
  if( sock->waitable != NULL ) {
    if( (sock->flags & (ZFSS_FLAG_SHUT_WRITE | ZFSS_FLAG_SHUT_READ)) ==
        (ZFSS_FLAG_SHUT_WRITE | ZFSS_FLAG_SHUT_READ) ) {
      events |= EPOLLHUP;
    }
    zf_waitable_set(sock->waitable, events, true); 
  }

  return 0;
}

void zfss_set_nonblock(struct zfss_socket* sock, bool set)
{
  zf_log_ss_trace(stack, "%s(%d, %s)\n", __func__, sock->file.fd,
                  set ? "set" : "unset");
  if( set )
    sock->flags |= ZFSS_FLAG_NONBLOCK;
  else
    sock->flags &=~ ZFSS_FLAG_NONBLOCK;
}

int
zfss_ioctl(struct zfss_socket* sock, unsigned long request, void* arg)
{
  int rc = -ENOTTY;
  switch( request ) {
    case FIONBIO:
    {
      int* parg = (int*)arg;
      zfss_set_nonblock(sock, !!(*parg));
      rc = 0;
      break;
    }
  }
  return rc;
}

int
zfss_getsockopt(struct zfss_socket* sock, int level, int optname,
                void *optval, socklen_t *optlen)
{
  return zfss_sys_getsockopt(sock->file.fd, level, optname, optval, optlen);
}

ssize_t
zfss_recvfrom(struct zfss_socket* sock, void* buf, size_t len, int flags,
              struct sockaddr *src_addr, socklen_t *addrlen)
{
  struct iovec iov = {
    .iov_base = buf,
    .iov_len  = len,
  };

  struct msghdr msg = {
    .msg_name        = src_addr,
    .msg_namelen     = addrlen != NULL ? *addrlen : 0,
    .msg_iov         = &iov,
    .msg_iovlen      = 1,
    .msg_control     = NULL,
    .msg_controllen  = 0,
    .msg_flags       = 0,
  };

  int rc = sock->ops->recvmsg(sock, &msg, flags);
  if( rc >= 0 && addrlen != NULL )
    *addrlen = msg.msg_namelen;

  return rc;
}
ssize_t
zfss_recv(struct zfss_socket* sock, void* buf, size_t len, int flags)
{
  return zfss_recvfrom(sock, buf, len, flags, NULL, NULL);
}
ssize_t
zfss_read(struct zfss_socket* sock, void* buf, size_t len)
{
  return zfss_recvfrom(sock, buf, len, 0, NULL, NULL);
}
ssize_t
zfss_readv(struct zfss_socket* sock, const struct iovec* iov, int iovcnt)
{
  struct msghdr msg = {
    .msg_name        = NULL,
    .msg_namelen     = 0,
    .msg_iov         = (struct iovec *)iov,
    .msg_iovlen      = (size_t)iovcnt,
    .msg_control     = NULL,
    .msg_controllen  = 0,
    .msg_flags       = 0,
  };
  
  return sock->ops->recvmsg(sock, &msg, 0);
}

int
zfss_recvmmsg(struct zfss_socket* sock, struct mmsghdr *msgvec,
              unsigned int vlen, int flags, recvmsg_timeout_t timeout)
{
  if( flags != 0 )
    return -ENOSYS;

  /* Can't handle these. We can't fall back to the OS socket either, so we
   * don't return -ENOSYS. */
  if( timeout != NULL || flags != 0 )
    return -EOPNOTSUPP;

  for( unsigned int msg_index = 0; msg_index < vlen; ++msg_index ) {
    struct msghdr* msg = &msgvec[msg_index].msg_hdr;

    int rc = sock->ops->recvmsg(sock, msg, flags);
    /* If we didn't handle that, let the OS try. */
    if( rc == -ENOSYS )
      rc = zfss_sys_recvmsg(sock->file.fd, msg, flags);
    if( rc < 0 )
      return rc;

    msgvec[msg_index].msg_len = rc;
  }

  /* Return value is number of messages returned, and at present we always wait
   * for the maximum number requested. */
  return (int) vlen;
}


#if SHIM_SENDMMSG
int
zfss_sendmmsg(struct zfss_socket* sock, struct mmsghdr *msgvec,
              unsigned int vlen, int flags)
{
  if( flags != 0 )
    return -ENOSYS;

  for( unsigned int msg_index = 0; msg_index < vlen; ++msg_index ) {
    struct msghdr* msg = &msgvec[msg_index].msg_hdr;

    int rc = sock->ops->sendmsg(sock, msg, flags);
    /* If we didn't handle that, let the OS try. */
    if( rc == -ENOSYS )
      rc = zfss_sys_sendmsg(sock->file.fd, msg, flags);
    if( rc < 0 )
      return rc;

    msgvec[msg_index].msg_len = rc;
  }

  return 0;
}
#endif


ssize_t
zfss_sendto(struct zfss_socket* sock, const void *buf, size_t len,
            int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
  struct iovec iov = { (void*) buf, len };

  struct msghdr msg = {
    .msg_name = (void*) dest_addr,
    .msg_namelen = addrlen,
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = NULL,
    .msg_controllen = 0,
  };

  return sock->ops->sendmsg(sock, &msg, flags);
}
ssize_t
zfss_send(struct zfss_socket* sock, const void *buf, size_t len,
          int flags)
{
  return zfss_sendto(sock, buf, len, flags, NULL, 0);
}
ssize_t
zfss_write(struct zfss_socket* sock, const void *buf, size_t len)
{
  return zfss_sendto(sock, buf, len, 0, NULL, 0);
}
ssize_t
zfss_writev(struct zfss_socket* sock, const struct iovec* iov, int iovcnt)
{
  struct msghdr msg = {
    .msg_name = NULL,
    .msg_namelen = 0,
    .msg_iov = (struct iovec*)iov,
    .msg_iovlen = (size_t)iovcnt,
    .msg_control = NULL,
    .msg_controllen = 0,
  };

  return sock->ops->sendmsg(sock, &msg, 0);
}


int
zfss_no_listen(struct zfss_socket* sock, int backlog)
{
  return -EOPNOTSUPP;
}
int
zfss_no_accept4(struct zfss_socket* sock,
                struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  return -EOPNOTSUPP;
}
int
zfss_accept(struct zfss_socket* sock,
            struct sockaddr *addr, socklen_t *addrlen)
{
  return sock->ops->accept4(sock, addr, addrlen, 0);
}
