/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2018 Advanced Micro Devices, Inc. */

/*
 * This is a version of the TCP ping-pong benchmark modified to optionally sleep
 * between pings.
 */
#include <zf/zf.h>
#include "../zf_apps/zf_utils.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zftcppingpong_sleep [options] pong <this-host:port>\n");
  fprintf(f, "  zftcppingpong_sleep [options] ping <remote-host:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s tcp payload in bytes\n");
  fprintf(f, "  -i number of iterations\n");
  fprintf(f, "  -w warm send path during sleep\n");
  fprintf(f, "  -x warm stack before start (ping only)\n");
  fprintf(f, "  -z microseconds to sleep (ping only)\n");
  fprintf(f, "  -r output raw data (ping only)\n");
  fprintf(f, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


struct rx_msg {
  struct zft_msg msg;
  struct iovec iov[1];
};


struct cfg {
  int size;
  int itercount;
  useconds_t sleep_usecs;
  bool warm_send;
  bool warm_stack;
  bool ping;
  bool raw;
};


static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
  .sleep_usecs = 0,
  .raw = false,
  .warm_send = false,
  .warm_stack = false,
};


static inline useconds_t usecs_since(const struct timespec* last_ts)
{
  struct timespec now_ts;
  long us_since;
  clock_gettime(CLOCK_REALTIME, &now_ts);
  us_since = (now_ts.tv_sec - last_ts->tv_sec) * 1000000 +
                (now_ts.tv_nsec - last_ts->tv_nsec) / 1000;
  return us_since < 0 ? 0 : (useconds_t)us_since;
}


static int reactor_zft_warm(struct zf_stack* stack,
                            struct zft* zock, const void* buf, size_t buflen)
{
  int rc;
  if( (rc = zf_reactor_perform(stack)) == 0 )
    ZF_TEST( zft_send_single_warm(zock, buf, buflen) == buflen );
  return rc;
}


static void pinger(struct zf_stack* stack, struct zft* zock,
                   unsigned long* rtt_results)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int sends_left = cfg.itercount;
  bool zock_has_rx_data = false;
  struct timespec start_ts, end_ts;

  clock_gettime(CLOCK_REALTIME, &start_ts);
  if( cfg.warm_stack ) {
    /* First stack poll can take multiple microseconds.
     * Touching the stack event queue a few times before starting
     * helps this.  No work is expected. */
    int stack_warm_iter = 10;
    while( stack_warm_iter-- && ! zf_reactor_perform(stack) )
      ;
  }
  do {
    size_t bytes_left = cfg.size;
    if( cfg.sleep_usecs ) {
      /* Since there are TCP zockets in the stack, the reactor
       * should be polled when sleeping for a long time
       * to update timers. */
      if( cfg.warm_send )
        while( usecs_since(&start_ts) < cfg.sleep_usecs )
          reactor_zft_warm(stack, zock, send_buf, cfg.size);
      else
        while( usecs_since(&start_ts) < cfg.sleep_usecs )
          zf_reactor_perform(stack);
    }
    clock_gettime(CLOCK_REALTIME, &start_ts);
    ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
    do {
      if( ! zock_has_rx_data )
        /* Poll the stack until something happens. */
        while( zf_reactor_perform(stack) == 0 )
          ;
      msg.msg.iovcnt = max_iov;
      zft_zc_recv(zock, &msg.msg, 0);
      if( msg.msg.iovcnt == 0 )
        continue;

      ZF_TEST(msg.iov[0].iov_len <= bytes_left);
      bytes_left -= msg.iov[0].iov_len;
      if( bytes_left == 0 ) {
        /* Take timestamp */
        clock_gettime(CLOCK_REALTIME, &end_ts);
        rtt_results[cfg.itercount - sends_left] =
              (end_ts.tv_nsec - start_ts.tv_nsec)
              + (end_ts.tv_sec - start_ts.tv_sec) * 1000000000;
      }
      ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
      zock_has_rx_data = msg.msg.pkts_left != 0;
    } while( bytes_left );
  } while( --sends_left );
}


static void ponger(struct zf_stack* stack, struct zft* zock)
{
  char send_buf[cfg.size];
  struct rx_msg msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  int recvs_left = cfg.itercount;
  bool zock_has_rx_data = false;

  do {
    size_t bytes_left = cfg.size;
    do {
      if( ! zock_has_rx_data ) {
        /* Poll the stack until something happens. */
        if( cfg.warm_send )
          while( reactor_zft_warm(stack, zock, send_buf, cfg.size) == 0 )
            ;
        else
          while( zf_reactor_perform(stack) == 0 )
            ;
      }
      msg.msg.iovcnt = max_iov;
      zft_zc_recv(zock, &msg.msg, 0);
      if( msg.msg.iovcnt == 0 )
        continue;

      ZF_TEST(msg.iov[0].iov_len <= bytes_left);
      bytes_left -= msg.iov[0].iov_len;
      if( bytes_left == 0 ) {
        ZF_TEST(zft_send_single(zock, send_buf, cfg.size, 0) == cfg.size);
        --recvs_left;
      }
      ZF_TEST(zft_zc_recv_done(zock, &msg.msg) == 1);
      zock_has_rx_data = msg.msg.pkts_left != 0;
    } while( bytes_left );
  } while( recvs_left );
}


int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:wxz:r")) != -1 )
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 'w':
      cfg.warm_send = true;
      break;
    case 'x':
      cfg.warm_stack = true;
      break;
    case 'z':
      cfg.sleep_usecs = atoi(optarg);
      break;
    case 'r':
      cfg.raw = true;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;
  if( argc != 2 )
    usage_err();

  if( ! strcmp(argv[0], "ping") )
    cfg.ping = true;
  else if( ! strcmp(argv[0], "pong") ) {
    cfg.ping = false;
    if( cfg.warm_stack ) {
      fprintf(stderr, "ERROR: warm stack (-x) is only used on ping side\n");
      usage_err();
    }
    if( cfg.sleep_usecs ) {
      fprintf(stderr, "ERROR: sleep (-z) is only used on ping side\n");
      usage_err();
    }
    if( cfg.raw ) {
      fprintf(stderr, "ERROR: raw output (-r) is only used on ping side\n");
      usage_err();
    }
  }
  else
    usage_err();

  struct addrinfo* ai;
  if( getaddrinfo_hostport(argv[1], NULL, &ai) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    exit(2);
  }

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zft* zock;

  if( cfg.ping ) {
    /* In 'ping' mode, connect to the specified remote address. */
    struct zft_handle* tcp_handle;
    ZF_TRY(zft_alloc(stack, attr, &tcp_handle));
    printf("# Connecting to ponger\n");
    ZF_TRY(zft_connect(tcp_handle, ai->ai_addr, ai->ai_addrlen, &zock));
    /* The zft_connect() call is non-blocking, so the zocket is not yet
     * connected.  Wait until the connect completes or fails...
     */
    while( zft_state(zock) == TCP_SYN_SENT )
      zf_reactor_perform(stack);
    ZF_TEST( zft_state(zock) == TCP_ESTABLISHED );
  }
  else {
    /* In 'pong' mode, create a listening zocket and wait until we've
     * accepted a connection.
     */
    struct zftl* listener;
    int rc;
    ZF_TRY(zftl_listen(stack, ai->ai_addr, ai->ai_addrlen, attr, &listener));
    printf("# Waiting for incoming connection\n");
    do {
      while( zf_reactor_perform(stack) == 0 );
    } while( (rc = zftl_accept(listener, &zock)) == -EAGAIN );
    ZF_TRY(rc);
    ZF_TRY(zftl_free(listener));
  }
  printf("# Connection established\n");

  if( cfg.ping ) {
    unsigned long* rtt_results = calloc(cfg.itercount, sizeof(*rtt_results));
    int i;
    pinger(stack, zock, rtt_results);
    if( cfg.raw ) {
      for( i = 0; i < cfg.itercount; ++i )
        printf("%lu\n", rtt_results[i]);
    }
    else {
      uint64_t rtt_sum = 0;
      for( i = 0; i < cfg.itercount; ++i )
        rtt_sum += rtt_results[i];
      printf("mean round-trip time: %0.3f usec\n",
             (double)rtt_sum / ((uint64_t)cfg.itercount * 1000));
    }
    free(rtt_results);
  }
  else {
    ponger(stack, zock);
  }

  /* Do a clean shutdown and free all resources. */
  while( zft_shutdown_tx(zock) == -EAGAIN )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  ZF_TRY(zft_free(zock));
  ZF_TRY(zf_stack_free(stack));
  ZF_TRY(zf_deinit());
  return 0;
}
