/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  zfsink application
**   \date  2015/10/20
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <zf/zf.h>
#include "zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/time.h>


struct resources {
  /* statistics */
  volatile uint64_t n_rx_pkts;
  volatile uint64_t n_rx_bytes;
};


static bool cfg_quiet = false;
static bool cfg_rx_timestamping = false;
static struct resources res;

/* Mutex to protect printing from different threads */
static pthread_mutex_t printf_mutex;


static void usage_msg(FILE* f)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  zfsink <options> <local_host:port> [remote_host:port]\n");
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -h       Print this usage message\n");
  fprintf(f, "  -m       Use the zf multiplexer\n");
  fprintf(f, "  -w       Use the zf waitable fd\n");
  fprintf(f, "  -r       Enable rx timestamping\n");
  fprintf(f, "  -q       Quiet -- do not emit progress messages\n");
  fprintf(f, "  -p       Print zf attributes after stack startup\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


static void vlog(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  pthread_mutex_lock(&printf_mutex);
  vprintf(fmt, args);
  pthread_mutex_unlock(&printf_mutex);
  va_end(args);
}


static void try_recv(struct zfur* ur)
{
  struct {
    /* The iovec used by zfur_msg must be immediately afterwards */
    struct zfur_msg msg;
    struct iovec iov[1];
  } rd;

  do {
    rd.msg.iovcnt = sizeof(rd.iov) / sizeof(rd.iov[0]);
    zfur_zc_recv(ur, &rd.msg, 0);

    if( rd.msg.iovcnt == 0 )
      break;

    /* Do something useful with the datagram here! */

    /* In the case rx timestamping capabilities are enabled, we can retrieve
     * the time at which the packet was received.
     * */
    if( cfg_rx_timestamping ) {
      unsigned flags;
      struct timespec ts;
      int rc = zfur_pkt_get_timestamp(ur, &rd.msg, &ts, 0, &flags);

      if( rc == 0 )
        vlog("Hardware timestamp: %lld.%.9ld\n", ts.tv_sec, ts.tv_nsec);
      else
        vlog("Error retrieving timestamp! Return code: %d\n", rc);
    }

    zfur_zc_recv_done(ur, &rd.msg);

    res.n_rx_pkts += 1;
    res.n_rx_bytes += rd.iov[0].iov_len;
  } while( rd.msg.dgrams_left );
}


static void poll_muxer(struct zf_muxer_set* muxer, int timeout)
{
  struct epoll_event evs[8];
  const int max_evs = sizeof(evs) / sizeof(evs[0]);

  int n_ev = zf_muxer_wait(muxer, evs, max_evs, timeout);

  for( int i = 0; i < n_ev; ++i )
    try_recv(evs[i].data.ptr);
}


static void ev_loop_reactor(struct zf_stack* stack, struct zfur* ur)
{
  while( 1 ) {
    while( zf_reactor_perform(stack) == 0 )
      ;
    try_recv(ur);
  }
}


static void ev_loop_muxer(struct zf_muxer_set* muxer)
{
  while( 1 )
    poll_muxer(muxer, -1);
}


static void ev_loop_waitable_fd(struct zf_stack* stack,
                                struct zf_muxer_set* muxer)
{
  int waitable_fd;
  ZF_TRY(zf_waitable_fd_get(stack, &waitable_fd));
  ZF_TRY(zf_waitable_fd_prime(stack));

  int epollfd = epoll_create(10);
  struct epoll_event ev = { .events = EPOLLIN, .data.fd = waitable_fd };
  ZF_TRY(epoll_ctl(epollfd, EPOLL_CTL_ADD, waitable_fd, &ev));

  while( 1 ) {
    struct epoll_event evs[8];
    const int max_evs = sizeof(evs) / sizeof(evs[0]);

    int n_ev = epoll_wait(epollfd, evs, max_evs, -1);

    for( int i = 0; i < n_ev; ++i )
      if( evs[i].data.fd == waitable_fd ) {
        poll_muxer(muxer, 0);
        ZF_TRY(zf_waitable_fd_prime(stack));
      }
      else {
        /* Not possible in this sample code. */
      }
  }
}


/* return string containing the value of an attribute
 * allocates memory so must call free() after use */
static int attr_to_str(struct zf_attr* attr, const char* name, char ** str_out)
{
#define MAX_LEN 64
  int rc = 0;
  int n = 0;
  *str_out = NULL;
  const char** docs_out;
  int docs_len_out;
  rc = zf_attr_doc(name, &docs_out, &docs_len_out);
  if( rc < 0 )
    return rc;
  assert(docs_len_out >= 6);
  if( ! strcmp(docs_out[1], "int") ) {
    int64_t val;
    if( (rc = zf_attr_get_int(attr, name, &val)) == 0 ) {
      *str_out = malloc(MAX_LEN);
      assert( *str_out != NULL );
      n = snprintf(*str_out, MAX_LEN, "%"PRId64"", val);
    }
  }
  else if ( ! strcmp(docs_out[1], "str") ) {
    rc = zf_attr_get_str(attr, name, str_out);
    /* need explicit Null check */
    if ( (rc == 0) && ( *str_out == NULL ) ) {
      *str_out = malloc(MAX_LEN);
      n = snprintf(*str_out, MAX_LEN, "(null)");
    }
  }
  else if ( ! strcmp(docs_out[1], "bitmask") ) {
    uint64_t val;
    if( (rc = zf_attr_get_int(attr, name, (int64_t*) &val)) == 0 ) {
      *str_out = malloc(MAX_LEN);
      n = snprintf(*str_out, MAX_LEN, "0x%"PRIx64"", val);
    }
  }
  else {
    rc = -EINVAL;
  }
  free(docs_out);

  if( n >= MAX_LEN )
    rc = -EOVERFLOW;
  
  if( rc < 0 )
    free(*str_out);

  return rc;
  #undef MAX_LEN
}


void print_attrs(struct zf_attr* attr)
{
  const char** names_out;
  int names_len_out;

  /* return array of attribute names */
  ZF_TRY(zf_attr_doc(NULL, &names_out, &names_len_out));
  printf("%30s\t%s\n", "Attribute Name", "Value");

  for( int i=0; i < names_len_out; ++i) {
    char* value_str;
    ZF_TRY(attr_to_str(attr, names_out[i], &value_str));
    printf("%30s\t%s\n", names_out[i], value_str);
    free(value_str);
  }
  printf("\n\n");
  free(names_out);
}


static void monitor()
{
  uint64_t now_bytes, prev_bytes;
  struct timeval start, end;
  uint64_t prev_pkts, now_pkts;
  int ms, pkt_rate, mbps;

  vlog("#%9s %16s %16s", "pkt-rate", "bandwidth(Mbps)", "total-pkts\n");

  prev_pkts = res.n_rx_pkts;
  prev_bytes = res.n_rx_bytes;
  gettimeofday(&start, NULL);

  while( 1 ) {
    sleep(1);
    now_pkts = res.n_rx_pkts;
    now_bytes = res.n_rx_bytes;
    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
    pkt_rate = (int) ((now_pkts - prev_pkts) * 1000 / ms);
    mbps = (int) ((now_bytes - prev_bytes) * 8 / 1000 / ms);
    vlog("%10d %16d %16"PRIu64"\n", pkt_rate, mbps, now_pkts);
    fflush(stdout);
    prev_pkts = now_pkts;
    prev_bytes = now_bytes;
    start = end;
  }
}


static void* monitor_fn(void* arg)
{
  monitor();
  return NULL;
}


int main(int argc, char* argv[])
{
  pthread_t thread_id;
  int cfg_muxer = 0;
  int cfg_waitable_fd = 0;
  bool cfg_print_attrs = false;
  
  int c;
  while( (c = getopt(argc, argv, "hmrwqp")) != -1 )
    switch( c ) {
    case 'h':
      usage_msg(stdout);
      exit(0);
    case 'm':
      cfg_muxer = 1;
      break;
    case 'w':
      cfg_waitable_fd = 1;
      break;
    case 'r':
      cfg_rx_timestamping = 1;
      break;
    case 'q':
      cfg_quiet = true;
      break;
    case 'p':
      cfg_print_attrs = true;
      break;
    case '?':
      exit(1);
    default:
      ZF_TEST(0);
    }

  argc -= optind;
  argv += optind;

  struct addrinfo *ai_local = NULL, *ai_remote = NULL;
  switch( argc ) {
  case 2:
    ZF_TEST(getaddrinfo_hostport(argv[1], NULL, &ai_remote) == 0);
    /* fall through */
  case 1:
    ZF_TEST(getaddrinfo_hostport(argv[0], NULL, &ai_local) == 0);
    break;
  default:
    usage_err();
    break;
  }

  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  if( cfg_rx_timestamping )
    ZF_TRY(zf_attr_set_int(attr, "rx_timestamping", 1));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  if( cfg_print_attrs )
    print_attrs(attr);

  struct zfur* ur;
  ZF_TRY(zfur_alloc(&ur, stack, attr));

  if( ai_remote )
    ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                          ai_remote->ai_addr, ai_remote->ai_addrlen, 0));
  else
    ZF_TRY(zfur_addr_bind(ur, ai_local->ai_addr, ai_local->ai_addrlen,
                          NULL, 0, 0));

  /* If no local port was specified, report which one was assigned */
  if( ! strchr(argv[0], ':') ) {
    fprintf(stderr, "No port provided, listening on %s:%d\n", argv[0],
            ntohs(((struct sockaddr_in*)ai_local->ai_addr)->sin_port));
  }

  /* Initialise the multiplexer if we're going to use one. */
  struct epoll_event event = { .events = EPOLLIN, .data = { .ptr = ur } };
  struct zf_muxer_set* muxer;
  if( cfg_muxer || cfg_waitable_fd ) {
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    ZF_TRY(zf_muxer_add(muxer, zfur_to_waitable(ur), &event));
  }

  pthread_mutex_init(&printf_mutex, NULL);
  res.n_rx_bytes = 0;
  res.n_rx_pkts = 0;

  if( ! cfg_quiet )
    ZF_TRY(pthread_create(&thread_id, NULL, monitor_fn, NULL) == 0);

  if( cfg_waitable_fd )
    ev_loop_waitable_fd(stack, muxer);
  else if( cfg_muxer )
    ev_loop_muxer(muxer);
  else
    ev_loop_reactor(stack, ur);

  return 0;
}
