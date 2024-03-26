/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2021 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "../tap/tap.h"


int fd;

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

static int nop(const struct sockaddr_in* laddr) { return 0; }

static int tcp_reserve_port(const struct sockaddr_in* laddr)
{
  ZF_TRY(fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  ZF_TRY(bind(fd, (const struct sockaddr*)laddr, sizeof(*laddr)));
  return 1;
}


static int tcp_close_port(const struct sockaddr_in* laddr)
{
  close(fd);
  return 0;
}


static int tcp_laddr_available(const struct sockaddr_in* laddr)
{
  int tcp_sock;
  ZF_TRY(tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  int rc = bind(tcp_sock, (const struct sockaddr*)laddr, sizeof(*laddr));
  close(tcp_sock);
 
  return rc < 0 ? 0 : 1;
}


static int test_bind_tcp(struct zf_stack* stack, struct zf_attr* attr,
                         int port, const char* laddr,
                         int(*pre_bind_action)(const struct sockaddr_in*),
                         int(*post_bind_action)(const struct sockaddr_in*))
{
  struct zft_handle* t_h;
  ZF_TRY(zft_alloc(stack, attr, &t_h));

  int ok = 1;

  struct sockaddr_in laddr_in = {
    AF_INET,
    htons(port),
    { inet_addr(laddr) },
  };

  /* Check this addr/port is free */
  ZF_TRY(pre_bind_action(&laddr_in));

  /* Do zf bind */
  if( zft_addr_bind(t_h, (struct sockaddr*)&laddr_in, sizeof(laddr_in),
                    0) < 0 ) {
    ok = 0;
    zft_handle_free(t_h);
    post_bind_action(&laddr_in);
  }
  else {
    /* Check port number is non-zero */
    struct sockaddr_in local_addr;
    socklen_t laddrlen = sizeof(local_addr);
    zft_handle_getname(t_h, (struct sockaddr*)&local_addr, &laddrlen);
    if(local_addr.sin_port == 0)
      ok = 0;

    /* Check port is no longer free */
    if( post_bind_action(&laddr_in) )
      ok = 0;

    zft_handle_free(t_h);
  }

  return ok;
}


static int test_bind_tcp_listen(struct zf_stack* stack, struct zf_attr* attr,
                         int port, const char* laddr,
                         int(*pre_bind_action)(const struct sockaddr_in*),
                         int(*post_bind_action)(const struct sockaddr_in*))
{
  int ok = 1;

  struct sockaddr_in laddr_in = {
    AF_INET,
    htons(port),
    { inet_addr(laddr) },
  };

  /* Check this addr/port is free */
  ZF_TRY(pre_bind_action(&laddr_in));

  /* Create listener */
  struct zftl* t;
  if( zftl_listen(stack, (struct sockaddr*)&laddr_in,
                  sizeof(struct sockaddr_in), attr, &t) < 0 ) {
    ok = 0;
    post_bind_action(&laddr_in);
  }
  else {
    /* Check port number is non-zero */
    struct sockaddr_in local_addr;
    socklen_t laddrlen = sizeof(local_addr);
    zftl_getname(t, (struct sockaddr*)&local_addr, &laddrlen);
    if(local_addr.sin_port == 0) {
      ok = 0;
    }

    /* Check port is no longer free */
    if( post_bind_action(&laddr_in) ) {
      ok = 0;
    }

    ZF_TRY(zftl_free(t));
  }

  return ok;
}


static int has_mcast_subscription(const char* addr, const char* intf)
{
  char cmd[100];
  snprintf(cmd, 100, "netstat -g | grep '%s' | grep -q '%s'", addr, intf);
  int rc;
  ZF_TRY(rc = system(cmd));

  return rc == 0 ? 1 : 0;
}


static int udp_reserve_port(const struct sockaddr_in* laddr)
{
  ZF_TRY(fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
  ZF_TRY(bind(fd, (const struct sockaddr*)laddr, sizeof(*laddr)));
  return 1;
}


static int udp_close_port(const struct sockaddr_in* laddr)
{
  close(fd);
  return 0;
}


static int udp_laddr_available(const struct sockaddr_in* laddr)
{
  int udp_sock;
  ZF_TRY(udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
  int rc = bind(udp_sock, (const struct sockaddr*)laddr, sizeof(*laddr));
  close(udp_sock);

  return rc < 0 ? 0 : 1;
}

static int test_bind_udp(struct zf_stack* stack, struct zf_attr* attr,
                         int base_port, const char** laddrs, int n_addrs,
                         const char* raddr, int r_port,
                         int(*pre_bind_action)(const struct sockaddr_in*),
                         int(*post_bind_action)(const struct sockaddr_in*))
{
  struct zfur* rx;
  ZF_TRY(zfur_alloc(&rx, stack, attr));
  int ok = 1;

  struct sockaddr_in raddr_in = {
    AF_INET,
    htons(r_port),
    { inet_addr(raddr) },
  };

  for(int i = 0; i < n_addrs; i++) {
    struct sockaddr_in laddr_in = {
      AF_INET,
      htons(base_port + i),
      { inet_addr(laddrs[i]) },
    };

    /* Check this addr/port is free or reserve it */
    ZF_TRY(pre_bind_action(&laddr_in));

    /* Do zf bind */
    if( zfur_addr_bind(rx, (struct sockaddr*)&laddr_in, sizeof(laddr_in),
                       (struct sockaddr*)&raddr_in, sizeof(raddr_in), 0) < 0 )
      ok = 0;

#if 0
    /* TODO: Check port is non-zero. First, though, we need a proper
     * interface for retrieving the chosen port number. */
    struct sockaddr_in local_addr;
    zfur_getname(rx, &local_addr, NULL);
    if(local_addr.sin_port == 0)
      ok = 0;
#endif

    /* Check port is no longer free or close it */
    if( post_bind_action(&laddr_in) )
      ok = 0;

    /* Check if we have a multicast subscription if this is an mcast addr */
    if( (ntohl(laddr_in.sin_addr.s_addr) & 0xf0000000) == 0xe0000000 )
      ok = has_mcast_subscription(laddrs[i], attr->interface);
  }

  ZF_TRY(zfur_free(rx));
  return ok;
}

static const char* local_addrs[] = { "127.0.0.1", "127.0.0.2", "127.0.0.3" };

/* This address is reserved and should not be assigned to any interfaces, and
 * so we are guaranteed that the address is not local. */
static const char* remote_addrs[] = { "192.0.2.1" };

static const char* mcast_addrs[] = { "230.1.2.3", "234.5.6.7" };

static const char* ssm_mcast_addrs[] = {"232.0.1.1"};

static const char* source_specific_raddr = "192.168.0.2";

static const char* inet_any = "0.0.0.0";

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  plan(22);
  int rc;

  int port = 20000;


  /* UDP - doesn't currently release RX resources, so need to increment port */
  rc = test_bind_udp(stack, attr, port, local_addrs, 1, source_specific_raddr, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP single local");

  port += 10;
  rc = test_bind_udp(stack, attr, port, local_addrs, 2, source_specific_raddr, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP two local");

  port += 10;
  rc = test_bind_udp(stack, attr, port, local_addrs, 3, source_specific_raddr, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP three local");

  port += 10;
  rc = test_bind_udp(stack, attr, port, remote_addrs, 1, source_specific_raddr, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 0, "UDP remote");

  port += 10;
  rc = test_bind_udp(stack, attr, port, mcast_addrs, 2, inet_any, 0,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP two mcast any source");
  
  /* In source specific multicast mode, laddr is in SSM, raddr is not inet_any and
   * rport can be 0. */
  port += 10;
  rc = test_bind_udp(stack, attr, port, ssm_mcast_addrs, 1, source_specific_raddr, 0,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP single multicast SSM");

  /* inet_any raddr is invalid with SSM binding. */
  port += 10;
  rc = test_bind_udp(stack, attr, port, ssm_mcast_addrs, 1, inet_any, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 0, "UDP single multicast SSM, inet_any raddr, 2000 rport");

  /* Tests that check we aren't binding when raddr xor rport are 0 without local SSM*/
  port += 10;
  rc = test_bind_udp(stack, attr, port, local_addrs, 1, inet_any, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 0, "UDP, single local with 0 raddr and 2000 rport");

  port += 10;
  rc = test_bind_udp(stack, attr, port, local_addrs, 1, source_specific_raddr, 0,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 0, "UDP, single local with valid raddr and 0 rport");

  port += 10;
  rc = test_bind_udp(stack, attr, port, mcast_addrs, 2, source_specific_raddr, 2000,
                     udp_laddr_available, udp_laddr_available);
  cmp_ok(rc, "==", 1, "UDP two mcast single source");

  /* Check we can't bind if the port is already in use by OS */
  rc = test_bind_udp(stack, attr, port, local_addrs, 1, source_specific_raddr, 2000,
                     udp_reserve_port, udp_close_port);
  cmp_ok(rc, "==", 0, "UDP local in use");

  rc = test_bind_udp(stack, attr, 0, local_addrs, 1, source_specific_raddr, 2000,
                     nop, nop);
  cmp_ok(rc, "==", 1, "UDP zero port");

  /* TCP active */
  /* We repeat this test to check that we can successfully rebind after
   * freeing a zocket.
   */
  rc = test_bind_tcp(stack, attr, port, local_addrs[0],
                     tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 1, "TCP local");

  rc = test_bind_tcp(stack, attr, port, local_addrs[0],
                     tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 1, "TCP local");

  rc = test_bind_tcp(stack, attr, port, local_addrs[0],
                     tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 1, "TCP local");

  rc = test_bind_tcp(stack, attr, port, remote_addrs[0],
                     tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 0, "TCP remote");

  /* Check we can't bind if the port is already in use by OS */
  rc = test_bind_tcp(stack, attr, port, local_addrs[0],
                     tcp_reserve_port, tcp_close_port);
  cmp_ok(rc, "==", 0, "TCP local in use");

  rc = test_bind_tcp(stack, attr, 0, local_addrs[0],
                     nop, nop);
  cmp_ok(rc, "==", 1, "TCP zero port");

  /* TCP listen */
  rc = test_bind_tcp_listen(stack, attr, port, local_addrs[0],
                            tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 1, "TCP listen local");

  rc = test_bind_tcp_listen(stack, attr, port, remote_addrs[0],
                            tcp_laddr_available, tcp_laddr_available);
  cmp_ok(rc, "==", 0, "TCP listen remote");

  /* Check we can't bind if the port is already in use by OS */
  rc = test_bind_tcp_listen(stack, attr, port, local_addrs[0],
                            tcp_reserve_port, tcp_close_port);
  cmp_ok(rc, "==", 0, "TCP listen in use");

  rc = test_bind_tcp_listen(stack, attr, 0, local_addrs[0],
                            nop, nop);
  cmp_ok(rc, "==", 1, "TCP listen zero port");

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

