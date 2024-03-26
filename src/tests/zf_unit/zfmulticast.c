/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "../tap/tap.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

  /* This test requires the loopback shim. */
  ZF_TEST((*attr_out)->emu == ZF_EMU_LOOPBACK);

  rc = zf_stack_alloc(*attr_out, stack_out);
  if( rc != 0 ) {
    zf_attr_free(*attr_out);
    return rc;
  }

  return 0;
}


static int fini(struct zf_stack* stack, struct zf_attr* attr)
{
  int rc;

  rc = zf_stack_free(stack);
  if( rc != 0 )
    return rc;
  zf_attr_free(attr);

  zf_deinit();

  return 0;
}

#define RX_IOVCNT 16

static bool recv(struct zfur* rx)
{
  struct {
    struct zfur_msg zcr;
    struct iovec iov[RX_IOVCNT];
  } rd = { { {}, 0, 0, RX_IOVCNT } };

  zfur_zc_recv(rx, &rd.zcr, 0);
  int iovcnt = rd.zcr.iovcnt;
  if( iovcnt )
    zfur_zc_recv_done(rx, &rd.zcr);

  return iovcnt;
}

static void send(struct zf_stack* stack, struct zf_attr* attr,
                 const char *src, unsigned short srcport,
                 const char *dest, unsigned short destport,
                 bool expect_recv)
{
  struct sockaddr_in laddr = { AF_INET, srcport,  { inet_addr(src)  } };
  struct sockaddr_in raddr = { AF_INET, destport, { inet_addr(dest) } };

  struct zfut* tx;
  ZF_TRY(zfut_alloc(&tx, stack, (const sockaddr*)&laddr, sizeof(laddr),
                    (const sockaddr*)&raddr, sizeof(raddr), 0, attr));
  const char *data = "test";
  zfut_send_single(tx, data, strlen(data));
  ZF_TRY(zfut_free(tx));

  if( expect_recv ) {
    while( zf_reactor_perform(stack) == 0 );
    while( zf_reactor_perform(stack) == 1 );
  }
  else {
    /* We really need to be able to synchronise with the emulator (ideally,
     * removing its thread and using a polling model instead) to test that
     * we won't receive unexpected packets. In the absence of synchronisation,
     * a short sleep reduces the likelihood of missing any packets. */
    usleep(1);
    zf_reactor_perform(stack);
  }
}

#define REMOTE_PORT 12345

static const char* remote_addrs[] = { "192.0.2.1", "192.0.2.2" };
static const char* mcast_addrs[]  = { "239.1.2.3", "239.5.6.7" };

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  plan(8);

  struct zfur* rx;

  struct sockaddr_in laddr = { AF_INET, 0, { inet_addr(mcast_addrs[0])  } };
  struct sockaddr_in raddr = { AF_INET, REMOTE_PORT,
                               { inet_addr(remote_addrs[0]) } };

  /* We don't test for multicast subscriptions here - zfbackingsock
   * covers it with netstat -g. */

  ZF_TRY(zfur_alloc(&rx, stack, attr));
  ZF_TRY(zfur_addr_bind(rx, (sockaddr*)&laddr, sizeof(laddr), NULL, 0, 0));

  printf("listening on %s:%d from any source\n",
         mcast_addrs[0], laddr.sin_port);
  send(stack, attr, remote_addrs[0], REMOTE_PORT,
       mcast_addrs[0], laddr.sin_port, true);
  cmp_ok(recv(rx), "==", 1, "receive packet destined for multicast address");
  send(stack, attr, remote_addrs[0], REMOTE_PORT,
       mcast_addrs[1], laddr.sin_port, false);
  cmp_ok(recv(rx), "==", 0, "no receive for packet for other address");
  send(stack, attr, remote_addrs[1], REMOTE_PORT,
       mcast_addrs[0], laddr.sin_port, true);
  cmp_ok(recv(rx), "==", 1, "received packet destined for multicast address");
  send(stack, attr, remote_addrs[1], REMOTE_PORT,
       mcast_addrs[1], laddr.sin_port, false);
  cmp_ok(recv(rx), "==", 0, "no receive for packet for other address");

  ZF_TRY(zfur_addr_unbind(rx, (const sockaddr*)&laddr, sizeof(laddr),
                          NULL, 0, 0));

  /* Test multicast with source filter */
  laddr.sin_port = 0;
  ZF_TRY(zfur_addr_bind(rx, (sockaddr*)&laddr, sizeof(laddr),
                        (const sockaddr*)&raddr, sizeof(raddr), 0));
  printf("listening on %s:%d from %s:%d\n", mcast_addrs[0], laddr.sin_port,
         remote_addrs[0], raddr.sin_port);
  send(stack, attr, remote_addrs[0], REMOTE_PORT,
       mcast_addrs[0], laddr.sin_port, true);
  cmp_ok(recv(rx), "==", 1, "receive packet from correct source");
  send(stack, attr, remote_addrs[0], REMOTE_PORT,
       mcast_addrs[1], laddr.sin_port, false);
  cmp_ok(recv(rx), "==", 0, "no receive for packet for other address");
  send(stack, attr, remote_addrs[1], REMOTE_PORT,
       mcast_addrs[0], laddr.sin_port, false);
  cmp_ok(recv(rx), "==", 0, "no receive for packet from other source");
  send(stack, attr, remote_addrs[1], REMOTE_PORT,
       mcast_addrs[1], laddr.sin_port, false);
  cmp_ok(recv(rx), "==", 0, "no receive for packet for other address");

  ZF_TRY(zfur_free(rx));

  done_testing();
}


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}

