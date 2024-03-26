/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  Daryl Lim
**  \brief  zfsend application
**   \date  2021/08/10
**    \cop  (c) Xilinx.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include "zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <stdarg.h>

struct cfg {
  int size;
  int itercount;
  bool timestamps;
  bool quiet;
  int usleep;
};

static struct zf_pkt_report *txr;
static struct cfg cfg = {
  .size = 12,
  .itercount = 1000000,
  .timestamps = false,
  .quiet = false,
  .usleep = 0
};

static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfsend [options] <local_host:port> <remote_host:port>\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -s       Size of the payload\n");
  fprintf(f, "  -i       Number of send iterations\n");
  fprintf(f, "  -t       Enable tx timestamping\n");
  fprintf(f, "  -q       Quiet -- do not emit progress messages\n");
  fprintf(f, "  -u       Sleep interval\n");
}

static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}

static void vlog(const char* fmt, ...)
{
  if( ! cfg.quiet ) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
  }
}

static void send_packets(struct zf_stack* stack, struct zfut* ut) {
  char send_buf[cfg.size];
  int sends_left = cfg.itercount;
  int times_left = cfg.timestamps ? cfg.itercount : 0;
  unsigned tx_report_num = 0;
  if ( cfg.timestamps ) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stderr, "TIME BEGIN %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
  }
  while( sends_left || times_left ) {
    if ( sends_left ) {
      vlog("Sending single packet...\n");
      ZF_TEST(zfut_send_single(ut, send_buf, cfg.size) == cfg.size);
      --sends_left;
    }

    vlog("Draining reactor...\n");
    while(zf_reactor_perform(stack) != 0)
      ;

    int count = 1;
    if ( cfg.timestamps ) {
      ZF_TRY(zfut_get_tx_timestamps(ut, &txr[tx_report_num], &count));
      if( count ) {
        ZF_TEST(count == 1);
        ZF_TEST(txr[tx_report_num].start == tx_report_num);
        ZF_TEST(txr[tx_report_num].bytes == cfg.size);
        ++tx_report_num;
        --times_left;
      }
    }

    if( cfg.usleep )
      usleep(cfg.usleep);
  }
}

int main(int argc, char* argv[])
{
  int c;

  while( (c = getopt(argc, argv, "hHs:i:tqu")) != -1 )
    switch( c ) {
    case 'h':
    case 'H':
      usage_err();
      break;
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 't':
      cfg.timestamps = 1;
      break;
    case 'q':
      cfg.quiet = 1;
      break;
    case 'u':
      cfg.usleep = 1;
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

  struct addrinfo *ai_local, *ai_remote;
  if( getaddrinfo_hostport(argv[0], NULL, &ai_local) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[0]);
    usage_err();
  }
  if( getaddrinfo_hostport(argv[1], NULL, &ai_remote) != 0 ) {
    fprintf(stderr, "ERROR: failed to lookup address '%s'\n", argv[1]);
    usage_err();
  }

  /* Initialise the TCPDirect library and allocate a stack. */
  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  if( cfg.timestamps )
    ZF_TRY(zf_attr_set_int(attr, "tx_timestamping", 1));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, ai_local->ai_addr, ai_local->ai_addrlen,
                    ai_remote->ai_addr, ai_remote->ai_addrlen, 0, attr));

  if( cfg.timestamps )
    txr = malloc(sizeof(struct zf_pkt_report) * cfg.itercount);

  vlog("Sending packets...\n");
  send_packets(stack, ut);

  if( cfg.timestamps ) {
    for( unsigned i = 0; i < cfg.itercount; ++i)
        fprintf(stderr, "TIME SENT  %ld.%09ld flags %x\n",
            txr[i].timestamp.tv_sec, txr[i].timestamp.tv_nsec, txr[i].flags);
    free(txr);
  }

  ZF_TRY(zfut_free(ut));
  ZF_TRY(zf_stack_free(stack));
  ZF_TRY(zf_deinit());
  return 0;
}
