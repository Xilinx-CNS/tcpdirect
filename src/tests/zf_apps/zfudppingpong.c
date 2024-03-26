/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/*
 * TCPDirect sample application demonstrating low-latency UDP sends and
 * receives.
 */
#include <zf/zf.h>
#include "zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <stdlib.h>
#include "zf_stats.h"
#include "zf_timer.h"

static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfudppingpong [options] pong <ponger:port> <pinger:port>\n");
  fprintf(f, "  zfudppingpong [options] ping <pinger:port> <ponger:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s udp payload in bytes\n");
  fprintf(f, "  -i number of iterations\n");
  fprintf(f, "  -r number of warmup iterations\n");
  fprintf(f, "  -t print timestamps\n");
  fprintf(f, "  -p show pth percentile\n");
  fprintf(f, "  -f report full-round trip time stats\n");
  fprintf(f, "  -w write raw data to file\n");
  fprintf(f, "  -R read access all received data\n");
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
  int warmups;
  int ping;
  int timestamps;
  uint64_t* results;
  float percentile;
  const char* raw_filename;
  bool full_rtt;
  bool touch_rx;
};


static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
  .warmups = 1000,
  .full_rtt = false,
  .percentile = 99,
  .results = NULL,
  .raw_filename = NULL,
};

static struct zf_pkt_report *txr, *rxr;

static void ping_pongs(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  char send_buf[cfg.size];
  int sends_left = cfg.itercount;
  int recvs_left = cfg.itercount;
  int times_left = cfg.timestamps ? cfg.itercount : 0;

  struct {
    /* The iovec used by zfur_msg must be immediately afterwards. */
    struct zfur_msg msg;
    struct iovec iov[2];
  } msg;
  const int max_iov = sizeof(msg.iov) / sizeof(msg.iov[0]);

  int i = 0;
  uint64_t begin = 0, end = 0;

  if( cfg.timestamps ) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stderr, "TIME BEGIN %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
  }

  if( cfg.ping ) {
    begin = get_frc64_time();

    ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);
    --sends_left;
  }

  unsigned tx_report_num = 0, rx_report_num = 0;
  do {
    /* Poll the stack until something happens. */
    while( zf_reactor_perform(stack) == 0 )
      ;
    msg.msg.iovcnt = max_iov;
    zfur_zc_recv(ur, &msg.msg, 0);
    if( cfg.touch_rx )
      read_memory_lumps(msg.iov, msg.msg.iovcnt);
    if( cfg.ping ) {
      end = get_frc64_time();
      cfg.results[i] = end - begin;
      i++;
    }
    if( msg.msg.iovcnt ) {
      if( sends_left ) {
        if( cfg.ping ) {
          begin = get_frc64_time();
        }

        ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);
        --sends_left;
      }
      /* The current implementation of TCPDirect always returns a single
       * buffer for each datagram.  Future implementations may return
       * multiple buffers for large (jumbo) or fragmented datagrams.
       */
      ZF_TEST(msg.msg.iovcnt == 1);
      /* As we're doing a ping-pong we shouldn't ever see any more datagrams
       * queued!
       */
      ZF_TEST(msg.msg.dgrams_left == 0);
      if( cfg.timestamps ) {
        unsigned flag;
        ZF_TRY(zfur_pkt_get_timestamp(ur, &msg.msg,
                                &rxr[rx_report_num].timestamp, 0,
                                &flag));
        rxr[rx_report_num].flags = flag;
        ++rx_report_num;
      }
      zfur_zc_recv_done(ur, &msg.msg);
      --recvs_left;
    }
    if( times_left ) {
      int count = 1;
      ZF_TRY(zfut_get_tx_timestamps(ut, &txr[tx_report_num], &count));
      if( count ) {
        ZF_TEST(count == 1);
        ZF_TEST(txr[tx_report_num].start == tx_report_num);
        ZF_TEST(txr[tx_report_num].bytes == cfg.size);
        ++tx_report_num;
        --times_left;
      }
    }
  } while( recvs_left || times_left );
}


static void pinger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  init_tsc_frequency();
  /* Touch the values will inialising to minimse page faults. */
  int i;
  for( i = 0; i < cfg.itercount; i++)
     cfg.results[i] = 0;

  ping_pongs(stack, ur, ut);
  /* Convert frc to nsec for stats reporting */
  for(i = 0; i < cfg.itercount; i++)
    cfg.results[i] = frc_to_nsec(cfg.results[i]);
}


static void ponger(struct zf_stack* stack, struct zfur* ur, struct zfut* ut)
{
  ping_pongs(stack, ur, ut);
}



int main(int argc, char* argv[])
{
  int c;
  while( (c = getopt(argc, argv, "s:i:r:tfp:w:R")) != -1 )
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 'r':
      cfg.warmups = atoi(optarg);
      break;
    case 't':
      cfg.timestamps = 1;
      break;
    case 'f':
      cfg.full_rtt = true;
      break;
    case 'p':
      cfg.percentile = atof(optarg);
      break;
    case 'w':
      cfg.raw_filename = strdup(optarg);
      break;
    case 'R':
      cfg.touch_rx = true;
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

  cfg.itercount += cfg.warmups;
  if( ! strcmp(argv[0], "ping") )
    cfg.ping = true;
  else if( ! strcmp(argv[0], "pong") )
    cfg.ping = false;
  else
    usage_err();

  cfg.results = (uint64_t*) malloc(cfg.itercount * sizeof(uint64_t));

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

  if( cfg.timestamps ) {
    zf_attr_set_int(attr, "rx_timestamping", 1);
    zf_attr_set_int(attr, "tx_timestamping", 1);
  }

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

  if( cfg.timestamps ) {
    txr = malloc(sizeof(struct zf_pkt_report) * cfg.itercount);
    rxr = malloc(sizeof(struct zf_pkt_report) * cfg.itercount);
  }
  if( cfg.ping ) {
    pinger(stack, ur, ut);
  }
  else {
    ponger(stack, ur, ut);
  }

  if( cfg.timestamps ) {
    for( unsigned i = cfg.warmups; i < cfg.itercount; ++i) {
      if( cfg.ping) {
        fprintf(stderr, "TIME SENT  %ld.%09ld flags %x\n",
            txr[i].timestamp.tv_sec, txr[i].timestamp.tv_nsec, txr[i].flags);
        fprintf(stderr, "TIME RECV  %ld.%09ld flags %x\n",
            rxr[i].timestamp.tv_sec, rxr[i].timestamp.tv_nsec, rxr[i].flags);
      }
      else {
        fprintf(stderr, "TIME RECV  %ld.%09ld flags %x\n",
            rxr[i].timestamp.tv_sec, rxr[i].timestamp.tv_nsec, rxr[i].flags);
        fprintf(stderr, "TIME SENT  %ld.%09ld flags %x\n",
            txr[i].timestamp.tv_sec, txr[i].timestamp.tv_nsec, txr[i].flags);
      }
    }
    free(txr);
    free(rxr);
  }

  if( cfg.ping ) {
    if( cfg.raw_filename != NULL )
      write_raw_array(cfg.raw_filename, cfg.results + cfg.warmups,
                      cfg.itercount - cfg.warmups);

    struct stats s;
    get_stats(&s, (!cfg.full_rtt), cfg.results + cfg.warmups,
              cfg.itercount - cfg.warmups, cfg.percentile);

    if( cfg.raw_filename == NULL ) {
      printf("mean round-trip time: %0.3f usec\n", ((float)s.mean*2)/1000);
      printf("Reporting %s round-trip stats in nsec for %d iterations\n",
             ( (cfg.full_rtt)? "full" : "half"), cfg.itercount - cfg.warmups);
      printf("#\tsize\tmean\tmin\tmedian\tmax\t%%ile\tstddev\titer\n");
      printf("\t%d\t%ld\t%ld\t%ld\t%ld\t%0ld\t%ld\t%d\n", cfg.size,
             s.mean, s.min, s.median, s.max, s.percentile, s.stddev,
             cfg.itercount - cfg.warmups);
    }
  }
  free(cfg.results);

  return 0;
}
