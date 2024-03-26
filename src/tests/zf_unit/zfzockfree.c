/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**************************************************************************\
 * This test ensures that zocket-freeing releases resources and allows creation
 * of further zockets reusing those resources.  It is intended to test the
 * internal freeing mechanisms rather than those exposed via the API in the
 * cases where those are different.  The latter should be tested separately as
 * necessary; in those cases, it is enough to ensure that the internal freeing
 * mechanism is eventually called as appropriate.
\**************************************************************************/

#include <arpa/inet.h>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>

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


/* Convenience class for constructing a sockaddr_in with a fixed host address
 * but varying port. */
class Addr
{
  private:
    struct sockaddr_in addr;
  public:
    Addr(in_addr_t addr_ne) : addr({AF_INET, 0, addr_ne}) {}

    const struct sockaddr_in* with_port(short port_he)
    {
      addr.sin_port = htons(port_he);
      return &addr;
    }

    const socklen_t addrlen()
    {
      return (socklen_t)sizeof(addr);
    }
} laddrs[] {inet_addr("127.0.0.1"), inet_addr("127.0.0.2")}, raddr(0x03030303);


/* UDP TX */
static int create_zocket(struct zf_stack* stack, struct zf_attr* attr,
                         int local_port_he, int remote_port_he,
                         struct zfut** udp_tx_out)
{
  return zfut_alloc(udp_tx_out, stack,
                    (struct sockaddr*)laddrs[0].with_port(local_port_he),
                    laddrs[0].addrlen(),
                    (struct sockaddr*)raddr.with_port(remote_port_he),
                    raddr.addrlen(), 0, attr);
}

/* UDP RX */
static int create_zocket(struct zf_stack* stack, struct zf_attr* attr,
                         int local_port_he, int remote_port_he,
                         struct zfur** udp_rx_out)
{
  int rc = zfur_alloc(udp_rx_out, stack, attr);
  if( rc < 0 )
    return rc;

  /* Install a few filters. */
  for( unsigned i = 0; i < sizeof(laddrs) / sizeof(laddrs[0]); ++i ) {
    struct sockaddr_in laddr = *laddrs[i].with_port(local_port_he);
    rc = zfur_addr_bind(*udp_rx_out, (struct sockaddr*)&laddr, sizeof(laddr),
                        (struct sockaddr*)raddr.with_port(remote_port_he),
                        raddr.addrlen(),0);
    if( rc != 0 )
      goto fail;
    zf_assert( memcmp(&laddr, laddrs[i].with_port(local_port_he),
                      sizeof(laddr)) == 0 );
  }

  return 0;

 fail:
  zfur_free(*udp_rx_out);
  return rc;
}


/* TCP */
static int create_zocket(struct zf_stack* stack, struct zf_attr* attr,
                         int local_port_he, int remote_port_he,
                         struct zft** tcp_out)
{
  struct zft_handle* tcp_handle;
  int rc = zft_alloc(stack, attr, &tcp_handle);
  if( rc < 0 )
    return rc;

  /* Do a loopback connect.  There's nothing listening, but we don't care: we
   * just want to install the filters. */
  rc = zft_addr_bind(tcp_handle,
                     (struct sockaddr*)laddrs[0].with_port(local_port_he),
                     laddrs[0].addrlen(), 0);
  if( rc < 0 )
    goto fail;

  rc = zft_connect(tcp_handle,
                   (struct sockaddr*)laddrs[1].with_port(remote_port_he),
                   laddrs[1].addrlen(), tcp_out);
  if( rc < 0 )
    goto fail;

  return 0;

 fail:
  zft_handle_free(tcp_handle);
  return rc;
}


/* TCP listen */
static int create_zocket(struct zf_stack* stack, struct zf_attr* attr,
                         int local_port_he, int remote_port_he,
                         struct zftl** tcp_listen_out)
{
  (void) remote_port_he;
  return zftl_listen(stack,
                     (struct sockaddr*)laddrs[0].with_port(local_port_he),
                     laddrs[0].addrlen(), attr, tcp_listen_out);
}


/* TCP handle */
static int create_zocket(struct zf_stack* stack, struct zf_attr* attr,
                         int local_port_he, int remote_port_he,
                         struct zft_handle** tcp_handle_out)
{
  (void) local_port_he;
  (void) remote_port_he;

  int rc = zft_alloc(stack, attr, tcp_handle_out);
  if( rc < 0 )
    return rc;

  return 0;
}


static int free_zocket(struct zfut* udp_tx) { return zfut_free(udp_tx); }
static int free_zocket(struct zfur* udp_rx) { return zfur_free(udp_rx); }

/* At present, this just calls the public API call.  Soon, this will not
 * actually free the zocket, but will just release a reference.  Once that work
 * is completed, this test should reach straight in and ensure that the zocket
 * is actually freed. */
static int free_zocket(struct zft* tcp) { return zft_free(tcp); }

static int free_zocket(struct zft_handle* h) { return zft_handle_free(h); }

/* We rely here on the fact that there are no accepted connections ensuring
 * that the listener is freed on return from the API call. */
static int free_zocket(struct zftl* tl) { return zftl_free(tl); }


const int TESTS_PER_ZOCKET = 3;

template<typename Zocket>
static void test_zocket(struct zf_stack* stack, struct zf_attr* attr,
                        int num_endpoints, const char* zocket_type_name)
{
  const int BASE_LOCAL_PORT  = 2000;
  const int BASE_REMOTE_PORT = 3000;

  Zocket zockets[num_endpoints];
  Zocket fail_zocket;
  int rc;

  /* Create the maximum number of zockets. */
  for( int i = 0; i < num_endpoints; ++i ) {
    rc = create_zocket(stack, attr, BASE_LOCAL_PORT + i, BASE_REMOTE_PORT + i,
                       &zockets[i]);
    if( rc < 0 )
      BAIL_OUT("Failed to allocate %s %d (rc = %d)", zocket_type_name, i, rc);
  }

  rc = create_zocket(stack, attr, BASE_LOCAL_PORT + num_endpoints, 
                     BASE_REMOTE_PORT + num_endpoints, &fail_zocket);
  cmp_ok(rc, "==", -ENOBUFS, "Overallocated %s zocket", zocket_type_name);

  /* Free them all. */
  for( int i = 0; i < num_endpoints; ++i ) {
    rc = free_zocket(zockets[i]);
    cmp_ok(rc, "==", 0, "Freed %s zocket %d", zocket_type_name, i);
  }

  /* Re-allocate maximum number of zockets. */
  for( int i = 0; i < num_endpoints; ++i ) {
    rc = create_zocket(stack, attr, BASE_LOCAL_PORT + i, BASE_REMOTE_PORT + i,
                       &zockets[i]);
    cmp_ok(rc, "==", 0, "Reallocated %s zocket %d", zocket_type_name, i);
  }

  /* Free them all again. */
  for( int i = 0; i < num_endpoints; ++i ) {
    rc = free_zocket(zockets[i]);
    cmp_ok(rc, "==", 0, "Freed %s zocket %d again", zocket_type_name, i);
  }
}


static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  plan(TESTS_PER_ZOCKET * (attr->max_udp_tx_endpoints +
                           attr->max_udp_rx_endpoints +
                           /* TCP: Handles and fully-fledged zockets. */
                           attr->max_tcp_endpoints * 2 +
                           attr->max_tcp_listen_endpoints) + 5);

  test_zocket<struct zfut*>(stack, attr, attr->max_udp_tx_endpoints, "UDP TX");
  test_zocket<struct zfur*>(stack, attr, attr->max_udp_rx_endpoints, "UDP RX");
  test_zocket<struct zft*>(stack, attr, attr->max_tcp_endpoints, "TCP");
  test_zocket<struct zft_handle*>(stack, attr, attr->max_tcp_endpoints,
                                  "TCP handle");
  test_zocket<struct zftl*>(stack, attr, attr->max_tcp_listen_endpoints,
                            "TCP listening");

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

