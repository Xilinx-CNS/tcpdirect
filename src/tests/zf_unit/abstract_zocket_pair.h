/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
#ifndef __ABSTRACT_ZOCKET_PAIR_H_
#define __ABSTRACT_ZOCKET_PAIR_H_

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>

#include <arpa/inet.h>

#include "../tap/tap.h"


struct abstract_zocket_pair {
  void* opaque_rx;
  void* opaque_tx;

  /* Sends a single-byte message. */
  int (*send)(void* opaque_zocket, char msg);

  /* Streaming receive: multiple sent messages can be returned in a single
   * recv() call. */
  int (*recv)(void* opaque_zocket, char* buf, size_t len);

  /* Closes and frees both of the zockets */
  void (*close)(void *pair);

  static in_addr_t default_listen_addr;
};

in_addr_t abstract_zocket_pair::default_listen_addr = inet_addr("127.0.0.4");


static int zfut_opaque_send(void* opaque_tx, char msg)
{
  return zfut_send_single((struct zfut*) opaque_tx, &msg, sizeof(msg));
}


static void zfu_opaque_close(void *pair)
{
  zfur_free((struct zfur*)((struct abstract_zocket_pair*)pair)->opaque_rx);
  zfut_free((struct zfut*)((struct abstract_zocket_pair*)pair)->opaque_tx);
}


static int zft_opaque_send(void* opaque_tx, char msg)
{
  int rc = zft_send_single((struct zft*) opaque_tx, &msg, sizeof(msg), 0);
  return rc < 0 ? rc : 0;
}


static void zft_opaque_close(void *pair)
{
  zft_free((struct zft*)((struct abstract_zocket_pair*)pair)->opaque_rx);
  zft_free((struct zft*)((struct abstract_zocket_pair*)pair)->opaque_tx);
}


#define RECV_TEMPLATE(zocket_type)                                            \
  static int                                                                  \
  zocket_type##_opaque_recv(void* opaque_rx, char* buffer, size_t len)        \
  {                                                                           \
    struct zocket_type* rx = (struct zocket_type*) opaque_rx;                 \
    size_t len_written = 0;                                                      \
    /* We expect one-byte messages, so allocate enough iovecs. */             \
    struct {                                                                  \
      struct zocket_type##_msg header;                                        \
      struct iovec iov[64];                                                   \
    } msg;                                                                    \
                                                                              \
    do {                                                                      \
      msg.header.iovcnt = len;                                                \
                                                                              \
      zocket_type##_zc_recv(rx, &msg.header, 0);                              \
                                                                              \
      for( int i = 0; i < msg.header.iovcnt; ++i ) {                          \
        struct iovec* piov = &msg.iov[i];                                     \
        /* We should only ever see single-byte messages. */                   \
        zf_assert_equal(piov->iov_len, 1);                                    \
        memcpy(&buffer[len_written++], (char*) piov->iov_base, 1);            \
      }                                                                       \
                                                                              \
      if( msg.header.iovcnt > 0 )                                             \
        zocket_type##_zc_recv_done(rx, &msg.header);                          \
                                                                              \
      /* Loop until we've filled the caller's buffer or until there were no   \
       * more packets to receive. */                                          \
    } while( len > len_written && msg.header.iovcnt > 0 );                    \
                                                                              \
    return len_written;                                                       \
  }


RECV_TEMPLATE(zfur)
RECV_TEMPLATE(zft)


static inline void
alloc_udp_pair_sockaddr_in(struct zf_stack* rx_stack,
                           struct zf_stack* tx_stack, struct zf_attr* attr,
                           struct abstract_zocket_pair* zocket_pair,
                           struct sockaddr_in* rx_addr,
                           const struct sockaddr_in* tx_addr,
                           bool bind_remote_wild)
{
  struct zfur* rx;
  struct zfut* tx;
  ZF_TRY(zfur_alloc(&rx, rx_stack, attr));
  if( bind_remote_wild )
    ZF_TRY(zfur_addr_bind(rx, (struct sockaddr*)rx_addr, sizeof(*rx_addr),
                          NULL, 0, 0));
  else
    ZF_TRY(zfur_addr_bind(rx, (struct sockaddr*)rx_addr, sizeof(*rx_addr),
                          (struct sockaddr*)tx_addr, sizeof(*tx_addr), 0));
  /* The zfur_addr_bind() call will have updated [rx_addr] with the ephemeral
   * local port. */
  ZF_TRY(zfut_alloc(&tx, tx_stack, (struct sockaddr*)tx_addr, sizeof(*tx_addr),
                    (struct sockaddr*)rx_addr, sizeof(*rx_addr), 0, attr));

  ZF_INET_NTOP_DECLARE_BUF(lbuf);
  ZF_INET_NTOP_DECLARE_BUF(rbuf);
  diag("Allocated UDP pair %s:%u -> %s:%u",
       ZF_INET_NTOP_CALL(tx_addr->sin_addr.s_addr, lbuf),
       ntohs(tx_addr->sin_port),
       ZF_INET_NTOP_CALL(rx_addr->sin_addr.s_addr, rbuf),
       ntohs(rx_addr->sin_port));

  zocket_pair->opaque_rx = rx;
  zocket_pair->opaque_tx = tx;
  zocket_pair->send = zfut_opaque_send;
  zocket_pair->recv = zfur_opaque_recv;
  zocket_pair->close = zfu_opaque_close;
}


static inline void
alloc_udp_pair(struct zf_stack* rx_stack, struct zf_stack* tx_stack,
               struct zf_attr* attr, struct abstract_zocket_pair* zocket_pair)
{
  struct sockaddr_in rx_laddr = {
    AF_INET,
    /* For UDP RX, we request an ephemeral port. */
    0,
    { inet_addr("127.0.0.2") },
  };
  struct sockaddr_in tx_laddr = {
    AF_INET,
    /* For UDP TX, we can use any local port that we like. */
    htons(10000),
    { inet_addr("192.168.0.1") },
  };

  alloc_udp_pair_sockaddr_in(rx_stack, tx_stack, attr, zocket_pair, &rx_laddr,
                             &tx_laddr, 0);
}


/* Single-stack wrapper. */
static inline void alloc_udp_pair(struct zf_stack* stack, struct zf_attr* attr,
                                  struct abstract_zocket_pair* zocket_pair)
{
  alloc_udp_pair(stack, stack, attr, zocket_pair);
}


static inline void make_listen_addr(struct sockaddr_in* listen_addr)
{
  listen_addr->sin_family = AF_INET;
  /* Use an ephemeral port. */
  listen_addr->sin_port = 0;
  listen_addr->sin_addr.s_addr = abstract_zocket_pair::default_listen_addr;
}


template <typename T>
static void alloc_tcp_pair_t(struct zf_stack* tx_stack, struct zf_stack* stack,
                             struct zf_attr* attr,
                             struct abstract_zocket_pair* zocket_pair,
                             T post_connect, struct zftl* listener,
                             bool reverse = false)
{
  static int port_seq = 0;
  struct sockaddr_in listen_addr;
  struct sockaddr_in tx_laddr = {
    AF_INET, 0, { inet_addr("127.0.0.3") },
  };
  ++port_seq;

  socklen_t laddrlen = sizeof(listen_addr);
  zftl_getname(listener, (struct sockaddr*) &listen_addr, &laddrlen);

  struct zft_handle* tx_handle;
  ZF_TRY(zft_alloc(tx_stack, attr, &tx_handle));
  ZF_TRY(zft_addr_bind(tx_handle, (struct sockaddr*)&tx_laddr,
                       sizeof(tx_laddr), 0));

  /* Set up a connection via the listening zocket. */

  struct zft* tx;
  ZF_TRY(zft_connect(tx_handle, (struct sockaddr*)&listen_addr,
                     sizeof(listen_addr), &tx));

  socklen_t addrlen = sizeof(tx_laddr);
  zft_getname(tx, (struct sockaddr*) &tx_laddr, &addrlen, NULL, 0);
  ZF_INET_NTOP_DECLARE_BUF(lbuf);
  ZF_INET_NTOP_DECLARE_BUF(rbuf);
  diag("Allocated TCP pair %s:%u <-> %s:%u",
       ZF_INET_NTOP_CALL(tx_laddr.sin_addr.s_addr, lbuf),
       ntohs(tx_laddr.sin_port),
       ZF_INET_NTOP_CALL(listen_addr.sin_addr.s_addr, rbuf),
       ntohs(listen_addr.sin_port));

  post_connect();

  struct zft* rx;
  int rc;
  do {
    while( zf_reactor_perform(stack) == 0 ) {
      if( tx_stack != stack )
        zf_reactor_perform(tx_stack);
    }
  } while( (rc = zftl_accept(listener, &rx)) == -EAGAIN );
  ZF_TRY(rc);

  if( reverse ) {
    zocket_pair->opaque_rx = tx;
    zocket_pair->opaque_tx = rx;
  }
  else {
    zocket_pair->opaque_rx = rx;
    zocket_pair->opaque_tx = tx;
  }
  zocket_pair->send = zft_opaque_send;
  zocket_pair->recv = zft_opaque_recv;
  zocket_pair->close = zft_opaque_close;
}


static void
alloc_tcp_pair_listener(struct zf_stack* stack, struct zf_attr* attr,
                        struct zftl** listener_out)
{
  struct sockaddr_in listen_addr;
  make_listen_addr(&listen_addr);
  ZF_TRY(zftl_listen(stack, (struct sockaddr*)&listen_addr,
                     sizeof(listen_addr), attr, listener_out));
}


/* Template to avoid having to specify listener.  It caches one
 * statically, so is limited to cases where the first stack used is a
 * valid destination, and remains valid, for all the connecting pairs */

template <typename T>
static void alloc_tcp_pair_t(struct zf_stack* tx_stack, struct zf_stack* stack,
                             struct zf_attr* attr,
                             struct abstract_zocket_pair* zocket_pair,
                             T post_connect, bool reverse = false)
{
  static struct zftl* listener = NULL;
  if( listener == NULL ) {
    /* Set up a listening zocket the first time we come through here.  It will
     * be used to set up connected zocket-pairs.  It also has the additional
     * benefit of demonstrating that the presence of a listening zocket in the
     * stack does not break RX demultiplexing. */
    alloc_tcp_pair_listener(stack, attr, &listener);
  }

  alloc_tcp_pair_t(tx_stack, stack, attr, zocket_pair, post_connect, listener,
                   reverse);
}


/* Single-stack use-cases can use this function for allocating TCP pairs.  It
 * hides the management of the listening zocket and the reverse direction option */

static inline void
alloc_tcp_pair(struct zf_stack* stack, struct zf_attr* attr,
               struct abstract_zocket_pair* zocket_pair, bool reverse = false)
{
  auto nop = [] {}; /* lambda expression doing nothing */
  alloc_tcp_pair_t(stack, stack, attr, zocket_pair, nop, reverse);
}

#endif
