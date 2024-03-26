/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include "../zf_apps/zf_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>


#define BUFFER_SIZE 1500

static int shutdown_now;

static void handler(int sig)
{
  shutdown_now = 1;
}


struct zf_muxer_set *muxer;


__attribute__((unused)) static void hexdump(const void* pv, int len)
{
  const unsigned char* p = (const unsigned char*) pv;
  int i;
  for( i = 0; i < len; ++i ) {
    const char* eos;
    switch( i & 15 ) {
    case 0:
      printf("%08x  ", i);
      eos = "";
      break;
    case 1:
      eos = " ";
      break;
    case 15:
      eos = "\n";
      break;
    default:
      eos = (i & 1) ? " " : "";
      break;
    }
    printf("%02x%s", (unsigned) p[i], eos);
  }
  printf(((len & 15) == 0) ? "\n" : "\n\n");
}


static void usage(void)
{
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  zftcppingpong [<options>] {ping|pong} <local-ip:port>");
  fprintf(stderr, " [remote-ip:port]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "  -s tcp payload in bytes\n");
  fprintf(stderr, "  -i number of iterations\n");
  fprintf(stderr, "  -d pong arbitrary data (not latency test pingpong)\n");
  fprintf(stderr, "  -e echo data locally (in -d mode)\n");
  fprintf(stderr, "  -m use multiplexer\n");
  fprintf(stderr, "  -a use TCP alternatives : only for latency test\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "remote-host:port should be specified when and only when");
  fprintf(stderr, " run in 'pong' mode.\n");
  fprintf(stderr, "\n");
  exit(1);
}


void parse_addr(char* hostport, struct sockaddr_in* out)
{
  struct addrinfo* ai;
  struct addrinfo ai_hints;
  memset(&ai_hints, 0, sizeof(ai_hints));
  ai_hints.ai_family = AF_INET;

  char* port = strchr(hostport, ':');
  if( !port ) {
    fprintf(stderr, "Please specify host:port\n");
    usage();
  }

  *port = 0;
  ++port;

  int rc = getaddrinfo(hostport, port, &ai_hints, &ai);
  if( rc != 0 ) {
    fprintf(stderr, "Failed to determine IP and port from %s:%s (%s)\n",
            hostport, port, gai_strerror(rc));
    usage();
  }

  if( ai->ai_addrlen != sizeof(struct sockaddr_in) ) {
    fprintf(stderr, "Unexpected address size\n");
    freeaddrinfo(ai);
    usage();
  }

  memcpy(out, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
}


struct _cfg {
  int size;
  int itercount;
  int ping;
  int latency_test;
  int echo;
  int muxer;
  int use_alternatives;
  const char* laddr;
  const char* raddr;

} cfg;


int tst_queue_alternative(struct zf_stack* stack, struct zft* ts, 
                          zf_althandle althandle,
                          const struct iovec* iov, int iov_cnt,
                          int flags)
{
  int rc;

  for(;;) {
    rc = zft_alternatives_queue(ts, althandle, iov, iov_cnt, flags);
    if( (rc != -EAGAIN) &&
        (rc != -EBUSY) )
      break;
    zf_reactor_perform(stack);
  }

  return rc;
}


void ping(struct zf_stack* stack, struct zf_attr* attr,
          struct zft* tcp, double* rtt)
{
  unsigned char data[BUFFER_SIZE] = { 0 };
  struct iovec siov = { data, 1};
  struct { 
    struct zft_msg zcr;
    struct iovec iov[2]; 
  } rd;
  struct epoll_event event;
  int events;
  zf_althandle alt_handle[2];
  int ah = 0;
  uint64_t ping_last_word_value = 0x1122334455667788;

  unsigned char* ping_last_word = cfg.size >= 8 ? &data[cfg.size - 8] : 0;

  siov.iov_len = cfg.size;
  if( ping_last_word )
    memcpy(ping_last_word, &ping_last_word_value, sizeof(ping_last_word_value));

  if( cfg.use_alternatives ) {
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alt_handle[0]));
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alt_handle[1]));
  }

  if( cfg.muxer ) {
    /* Poll until ready to send */
    do {
      events = zf_muxer_wait(muxer, &event, 1, -1);
      ZF_TEST(events > 0);
    } while( ! (event.events & EPOLLOUT) );
    ZF_TEST(zft_send_single(tcp, siov.iov_base, siov.iov_len, 0) == cfg.size);
  }
  else {
    int rc;
    while( (rc = zft_send_single(tcp, siov.iov_base, siov.iov_len, 0)) < 0);
    ZF_TEST(rc == cfg.size);
  }

  if( cfg.use_alternatives ) {
    ZF_TRY(tst_queue_alternative(stack, tcp, alt_handle[ah], 
                                 &siov, 1, 0));
  }

  struct timeval start, end;
  gettimeofday(&start, NULL);

  for(int it = 0; it < cfg.itercount;) {
    if( cfg.muxer ) {
      /* Must poll at least once */
      do {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      } while( ! (event.events & EPOLLIN) );
    }
    else {
      while(zf_reactor_perform(stack) == 0);
    }

    rd.zcr.iovcnt = 2;
    zft_zc_recv(tcp, &rd.zcr, 0);

    if( rd.zcr.iovcnt == 0 )
      continue;

    if( ping_last_word ) {
      ++ping_last_word_value;
      memcpy(ping_last_word, &ping_last_word_value, sizeof(ping_last_word_value));
    }
    if( cfg.muxer )
      /* May already be ready to send after poll above */
      while( ! (event.events & EPOLLOUT) ) {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      }

    if( cfg.use_alternatives ) {

      /* Note that it is possible for this function to return EBUSY if
       * an alt rebuild is in progress. The "correct" way to handle
       * this is to process some events and retry. However we do not
       * do that here, because our fixed traffic pattern means that we
       * should never be trying to transmit while an alt is being
       * rebuilt, and if this ever happens it indicates that we are
       * not measuring the best-case latency. So, crash and burn if we
       * get an EBUSY return code. */
      ZF_TRY(zf_alternatives_send(stack, alt_handle[ah]));

      ah = (ah + 1) % 2;
      ZF_TRY(tst_queue_alternative(stack, tcp, alt_handle[ah], 
                                   &siov, 1, 0));
    }
    else {
      ZF_TEST(zft_send_single(tcp, siov.iov_base, siov.iov_len, 0) == cfg.size);
    }

    it += rd.zcr.iovcnt;
    ZF_TEST(zft_zc_recv_done(tcp, &rd.zcr) == 1);
  }

  gettimeofday(&end, NULL);

  int usec = (end.tv_sec - start.tv_sec) * 1000000;
  usec += end.tv_usec - start.tv_usec;
  *rtt = (double) usec / cfg.itercount;
}


void latency_pong(struct zf_stack* stack, struct zf_attr* attr,
                  struct zft* tcp)
{
  unsigned char data[BUFFER_SIZE] = { 0 };
  struct iovec siov = { data, (size_t) cfg.size };
  struct {
    struct zft_msg zcr;
    struct iovec iov[1];
  } rd;
  struct epoll_event event;
  int events;
  zf_althandle alt_handle[2];
  int ah = 0;

  if( cfg.use_alternatives ) {
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alt_handle[0]));
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alt_handle[1]));
    ZF_TRY(tst_queue_alternative(stack, tcp, alt_handle[ah], 
                                 &siov, 1, 0));
  }

  for(int it = 0; it < cfg.itercount; it++) {
    do {
      if( cfg.muxer ) {
        /* Poll until ready to receive */
        do {
          events = zf_muxer_wait(muxer, &event, 1, -1);
          ZF_TEST(events > 0);
        } while( ! (event.events & EPOLLIN) );
      }
      else {
        while(zf_reactor_perform(stack) == 0);
      }

      rd.zcr.iovcnt = 1;
      zft_zc_recv(tcp, &rd.zcr, 0);

    } while( rd.zcr.iovcnt == 0 );

    if( cfg.muxer )
      /* If not ready to send from earlier, poll until ready */
      while( ! (event.events & EPOLLOUT) ) {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      }
    if( cfg.use_alternatives ) {
      ZF_TRY(zf_alternatives_send(stack, alt_handle[ah]));
      ah = (ah + 1) % 2;
      ZF_TRY(tst_queue_alternative(stack, tcp, alt_handle[ah], 
                                   &siov, 1, 0));
    }
    else {
      ZF_TEST(zft_send_single(tcp, siov.iov_base, siov.iov_len, 0) == cfg.size);
    }
    ZF_TEST( zft_zc_recv_done(tcp, &rd.zcr) >= 0 );
  }
}


void data_pong(struct zf_stack* stack, struct zf_attr* attr,
               struct zft* tcp)
{
  struct iovec siov;
  size_t tot_seg_cnt = 0;
  size_t tot_payload = 0;
  struct {
    struct zft_msg zcr;
    struct iovec iov[2];
  } rd;
  zf_althandle alt_handle[1];

  if( cfg.use_alternatives ) {
    ZF_TRY(zf_alternatives_alloc(stack, attr, &alt_handle[0]));
  }

  while( 1 ) {
    struct epoll_event event;
    int events;

    if( cfg.muxer ) {
      /* Poll until ready to receive */
      do {
        events = zf_muxer_wait(muxer, &event, 1, -1);
        ZF_TEST(events > 0);
      } while( !(event.events & (EPOLLIN | EPOLLRDHUP)) && !shutdown_now );

      if( event.events & EPOLLRDHUP )
        shutdown_now = 1;
    }
    else {
      while(!zf_reactor_perform(stack) && !shutdown_now);
    }

    if( shutdown_now )
      return;

    rd.zcr.iovcnt = 2;
    zft_zc_recv(tcp, &rd.zcr, 0);

    /* Drain the receive queue */
    while( rd.zcr.iovcnt ) {
      for( int i = 0 ; i < rd.zcr.iovcnt; ++i ) {
        if( rd.iov[i].iov_len > 0 ) {
          int rc;
          ++tot_seg_cnt;
          tot_payload += rd.iov[i].iov_len;

          siov.iov_base = ((char*)rd.iov[i].iov_base);
          siov.iov_len = rd.iov[i].iov_len;

          if( cfg.muxer ) {
            while( 1 ) {
              /* If not ready to send from earlier, poll until ready */
              while( ! (event.events & EPOLLOUT) ) {
                events = zf_muxer_wait(muxer, &event, 1, -1);
                ZF_TEST(events > 0);
              }

              rc = zft_send_single(tcp, siov.iov_base, siov.iov_len, 0);
              if( rc == -EAGAIN ) {
                /* Although ready for EPOLLOUT, send buffer space could be
                 * too small for the outgoing packet; mark as not ready so
                 * that the muxer is polled to attempt to free some space
                 */
                event.events &= ~EPOLLOUT;
                continue;
              }
              else {
                ((char*&)siov.iov_base) += rc;
                siov.iov_len -= rc;
                if( siov.iov_len == 0 )
                  break;
                event.events &= ~EPOLLOUT;
                continue;
              }
            }
          }
          else {
            while(1) {
              if(cfg.use_alternatives) {
                unsigned int space;
                struct iovec aiov = siov;
                do {
                  space = zf_alternatives_free_space(stack, alt_handle[0]);
                  if(space == 0)
                    zf_reactor_perform(stack);
                } while(space == 0);
                if(space > aiov.iov_len)
                  space = aiov.iov_len;

                aiov.iov_len = space;

                ZF_TRY(tst_queue_alternative(stack, tcp, alt_handle[0], 
                                             &aiov, 1, 0));

                do {
                  rc = zf_alternatives_send(stack, alt_handle[0]);
                  if(rc == -EAGAIN)
                    zf_reactor_perform(stack);
                } while(rc == -EAGAIN);
                ZF_TEST(rc >= 0);

                rc = space;

              } else {
                rc = zft_send_single(tcp, siov.iov_base, siov.iov_len, 0);

                while( rc == -EAGAIN ) {
                  /* Poll to free up send buffer space and then retry send */
                  while( ! zf_reactor_perform(stack) );

                  rc = zft_send_single(tcp, siov.iov_base, siov.iov_len, 0);
                }
              }

              if( rc < 0 )
                break;
              ZF_TEST(rc <= (signed)siov.iov_len);
              ((char*&)siov.iov_base) += rc;
              siov.iov_len -= rc;
              if( siov.iov_len == 0 )
                break;
            }
          }
          ZF_TEST(rc > 0);

          if(cfg.echo) {
            fwrite(rd.iov[i].iov_base, sizeof(char),
                   rd.iov[i].iov_len, stdout);
            fwrite("\n", sizeof(char), strlen("\n"), stdout);
          }
        }
        else {
          printf("Got EOF after %lu segments, %lu bytes - doing shutdown\n",
                 tot_seg_cnt, tot_payload);
          ZF_TEST(rd.zcr.iovcnt == i + 1);
          zft_zc_recv_done(tcp, &rd.zcr);
          return;
        }
      }
      ZF_TEST(zft_zc_recv_done(tcp, &rd.zcr) >= 0);
      zft_zc_recv(tcp, &rd.zcr, 0);
    }
  }
}


int main(int argc, char* argv[])
{
  cfg.size = 12;
  cfg.itercount = 1000000;
  cfg.latency_test = 1;

  int c;
  while( (c = getopt(argc, argv, "s:i:dema")) != -1 ) {
    switch( c ) {
    case 's':
      cfg.size = atoi(optarg);
      break;
    case 'i':
      cfg.itercount = atoi(optarg);
      break;
    case 'd':
      cfg.latency_test = 0;
      break;
    case 'e':
      cfg.echo = 1;
      break;
    case 'm':
      cfg.muxer = 1;
      break;
    case 'a':
      cfg.use_alternatives = 1;
      break;
    case '?':
      usage();
      /* Fall through. */
    default:
      ZF_TEST(0);
    }
  }

  argc -= optind;
  argv += optind;

  /* Should always have <ping|pong> <local addr:port> */
  if( argc < 2 )
    usage();

  cfg.ping = strcmp(argv[0], "ping") == 0;
  if( !cfg.ping && (strcmp(argv[0], "pong") != 0) ) {
    fprintf(stderr, "Please specify ping or pong\n");
    usage();
  }


  if( (cfg.size <= 0) || (cfg.size > BUFFER_SIZE) ) {
    fprintf(stderr, "Payload size must be > 0 and <= %d\n", BUFFER_SIZE);
    usage();
  }


  if( cfg.ping && (argc != 2) )
    usage();
  else if( !cfg.ping && (argc != 3) )
    usage();

  cfg.laddr = argv[1];
  cfg.raddr = argv[2];

  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handler;
  ZF_TRY(sigaction(SIGUSR1, &sa, NULL));

  ZF_TRY(zf_init());

  struct zf_attr* attr;
  ZF_TRY(zf_attr_alloc(&attr));

  struct zf_stack* stack;
  ZF_TRY(zf_stack_alloc(attr, &stack));

  struct zft_handle* tcp_handle;
  ZF_TRY(zft_alloc(stack, attr, &tcp_handle));

  struct sockaddr_in laddr;
  parse_addr((char*)cfg.laddr, &laddr);
  struct zft* tcp;

  if( ! cfg.ping ) {
    /* In 'pong' mode, just connect to the specified remote address. */
    struct sockaddr_in raddr;
    parse_addr((char*)cfg.raddr, &raddr);
    ZF_TRY(zft_addr_bind(tcp_handle, (struct sockaddr*)&laddr, sizeof(laddr),
                         0));
    ZF_TRY(zft_connect(tcp_handle, (struct sockaddr*)&raddr, sizeof(raddr),
                       &tcp));
  }
  else {
    /* In 'ping' mode, create a listening zocket and wait until we've accepted
     * a connection from the 'ping' end. */
    struct zftl* listener;
    int rc;
    ZF_TRY(zftl_listen(stack, (struct sockaddr*)&laddr,
                       sizeof(laddr), attr, &listener));
    printf("Listening for incoming connection\n");
    do {
      while( zf_reactor_perform(stack) == 0 );
    } while( (rc = zftl_accept(listener, &tcp)) == -EAGAIN );
    ZF_TRY(rc);
    printf("Connection accepted\n");
    ZF_TRY(zftl_free(listener));
  }

  if( cfg.muxer ) {
    struct epoll_event event = { .events = EPOLLIN | EPOLLOUT | 
                                           EPOLLHUP | EPOLLRDHUP };
    ZF_TRY(zf_muxer_alloc(stack, &muxer));
    ZF_TRY(zf_muxer_add(muxer, zft_to_waitable(tcp), &event));
  }

  if(cfg.ping) {
    double rtt;
    ping(stack, attr, tcp, &rtt);
    printf("mean round-trip time: %0.3f usec\n", rtt);
  }
  else if(cfg.latency_test) {
    latency_pong(stack, attr, tcp);
  }
  else {
    data_pong(stack, attr, tcp);
  }

  while( zft_shutdown_tx(tcp) == -EAGAIN )
    zf_reactor_perform(stack);

  while( ! zf_stack_is_quiescent(stack) )
    zf_reactor_perform(stack);

  if( cfg.muxer ) {
    zf_muxer_del(zft_to_waitable(tcp));
    zf_muxer_free(muxer);
  }

  ZF_TRY(zft_free(tcp));

  return 0;
}
