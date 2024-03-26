/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2018 Advanced Micro Devices, Inc. */

/*
 * This is a version of the UDP ping-pong benchmark modified to optionally sleep
 * between pings.
 */
#include <zf/zf.h>
#include "../zf_apps/zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfudppingpong_sleep [options] pong <ponger:port> <pinger:port>\n");
  fprintf(f, "  zfudppingpong_sleep [options] ping <pinger:port> <ponger:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s udp payload in bytes\n");
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


struct cfg {
  int size;
  int itercount;
  useconds_t sleep_usecs;
  bool warm_send;
  bool warm_stack;
  int ping;
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


static int reactor_zfut_warm(struct zf_stack* stack,
                             struct zfut* ut, const void* buf, size_t buflen)
{
  int rc;
  if( (rc = zf_reactor_perform(stack)) == 0 )
    ZF_TEST( zfut_send_single_warm(ut, buf, buflen) == buflen );
  return rc;
}


static void pinger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut,
                   unsigned long* rtt_results)
{
  char send_buf[cfg.size];
  int sends_left = cfg.itercount;
  struct {
    struct zfur_msg msg;
    struct iovec iov[2];
  } msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
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
    if( cfg.sleep_usecs ) {
      if( cfg.warm_send )
        while( usecs_since(&start_ts) < cfg.sleep_usecs )
          ZF_TEST( zfut_send_single_warm(ut, send_buf, cfg.size) == cfg.size );
      else
        while( usecs_since(&start_ts) < cfg.sleep_usecs )
          ;
    }
    clock_gettime(CLOCK_REALTIME, &start_ts);
    ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);

    /* Poll the stack until response. */
    msg.msg.iovcnt = 0;
    while( msg.msg.iovcnt == 0 ) {
      while( zf_reactor_perform(stack) == 0 )
        ;
      msg.msg.iovcnt = max_iov;
      zfur_zc_recv(ur, &msg.msg, 0);
    }
    clock_gettime(CLOCK_REALTIME, &end_ts);
    rtt_results[cfg.itercount - sends_left] =
          (end_ts.tv_nsec - start_ts.tv_nsec)
          + (end_ts.tv_sec - start_ts.tv_sec) * 1000000000;
    /* The current implementation of TCPDirect always returns a single
     * buffer for each datagram.  Future implementations may return
     * multiple buffers for large (jumbo) or fragmented datagrams.
     */
    ZF_TEST(msg.msg.iovcnt == 1);
    /* As we're doing a ping-pong we shouldn't ever see any more datagrams
     * queued!
     */
    ZF_TEST(msg.msg.dgrams_left == 0);
    zfur_zc_recv_done(ur, &msg.msg);
  } while( --sends_left );
}


static void ponger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  char send_buf[cfg.size];
  int recvs_left = cfg.itercount;
  struct {
    struct zfur_msg msg;
    struct iovec iov[2];
  } msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);
  do {
    /* Poll the stack until something happens. */
    if( cfg.warm_send )
      while( reactor_zfut_warm(stack, ut, send_buf, cfg.size) == 0)
        ;
    else
      while( zf_reactor_perform(stack) == 0 )
        ;
    msg.msg.iovcnt = max_iov;
    zfur_zc_recv(ur, &msg.msg, 0);
    if( msg.msg.iovcnt == 0 )
      continue;

    ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);

    /* The current implementation of TCPDirect always returns a single
     * buffer for each datagram.  Future implementations may return
     * multiple buffers for large (jumbo) or fragmented datagrams.
     */
    ZF_TEST(msg.msg.iovcnt == 1);
    /* As we're doing a ping-pong we shouldn't ever see any more datagrams
     * queued!
     */
    ZF_TEST(msg.msg.dgrams_left == 0);
    zfur_zc_recv_done(ur, &msg.msg);
    --recvs_left;
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
  if( argc != 3 )
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

  struct addrinfo *ai_local, *ai_remote;
  if( getaddrinfo_hostport(argv[1], NULL, &ai_local) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    exit(2);
  }
  if( getaddrinfo_hostport(argv[2], NULL, &ai_remote) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[2]);
    exit(2);
  }

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  /* Allocate zockets and bind them to the given addresses.  TCPDirect has
   * separate objects for sending and receiving UDP datagrams.
   */
  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));
  ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                        ai_remote->ai_addr, ai_remote->ai_addrlen, 0));

  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, ai_local->ai_addr, ai_local->ai_addrlen,
                    ai_remote->ai_addr, ai_remote->ai_addrlen, 0, attr));

  if( cfg.ping ) {
    unsigned long* rtt_results = calloc(cfg.itercount, sizeof(*rtt_results));
    int i;
    pinger(stack, ur, ut, rtt_results);
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
    ponger(stack, ur, ut);
  }

  return 0;
}
