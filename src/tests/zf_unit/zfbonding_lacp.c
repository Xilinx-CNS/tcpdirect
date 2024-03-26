/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
#include <initializer_list>

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"


struct zf_attr* attr;

static int lacp_tx_hwport(struct zf_stack* st, cicp_llap_type_t encap_type,
                          struct sockaddr_in* laddr, struct sockaddr_in* raddr,
                          const ci_mac_addr_t src_mac,
                          const ci_mac_addr_t dst_mac)
{
  /* For an active-active bond that uses hashing, choose the appropriate
   * interface to send out of.
   */
  struct cicp_hash_state hs;

  hs.flags = CICP_HASH_STATE_FLAGS_IS_TCP_UDP | CICP_HASH_STATE_FLAGS_IS_IP;

  memcpy(&hs.src_mac, src_mac, sizeof(ci_mac_addr_t));
  memcpy(&hs.dst_mac, dst_mac, sizeof(ci_mac_addr_t));
  hs.src_addr_be32 = laddr->sin_addr.s_addr;
  hs.dst_addr_be32 = raddr->sin_addr.s_addr;
  hs.src_port_be16 = laddr->sin_port;
  hs.dst_port_be16 = raddr->sin_port;

  return oo_cp_hwport_bond_get(encap_type, st->bond_state.tx_hwports, &hs);
}


static struct zfut*
alloc_tx(struct zf_stack* stack, const struct sockaddr_in* saddr,
         const struct sockaddr_in* daddr)
{
  struct zfut* ut;
  ZF_TRY(zfut_alloc(&ut, stack, (const struct sockaddr*)saddr, sizeof(*saddr),
                    (const struct sockaddr*)daddr, sizeof(*daddr), 0, attr));
  return ut;
}


static struct zfur*
alloc_rx(struct zf_stack* stack, struct sockaddr_in* laddr,
         const struct sockaddr_in* raddr)
{
  struct zfur* ur;

  ZF_TRY(zfur_alloc(&ur, stack, attr));
  ZF_TRY(zfur_addr_bind(ur, (struct sockaddr*)laddr, sizeof(*laddr),
                        (struct sockaddr*)raddr, sizeof(*raddr), 0));

  return ur;
}


void set_random_mac(ci_mac_addr_t mac)
{
  for( int i = 0; i < 6; i++ )
   mac[i] = (uint8_t)random();
};

struct hwport_rxer {
  struct zf_stack* st;
  struct zfur* zock;
};


/* Allocates a stack for each hwport_rxer. rx[i] will be assigned a stack
 * on interface eth%i. */
static void alloc_stacks(struct hwport_rxer* rx, int hwports)
{
  for( int i = 0; i < hwports; i++ ) {
    struct zf_stack* stack;
    char if_name[IF_NAMESIZE];

    snprintf(if_name, IF_NAMESIZE, "eth%d", i + hwports);
    ZF_TRY(zf_attr_set_str(attr, "interface", if_name));
    ZF_TRY(zf_stack_alloc(attr, &stack));

    rx[i].st = stack;
  }
}

/* Creates a stack on bond0, and two more stacks on eth2 and eth3, which are
 * the base peer interfaces.  UDP traffic is then sent from bond0, and we
 * check that it is received correctly at eth2 and eth3.
 *
 * By running the test a few times we'll get a range of different port
 * numbers, so should result in running across different tx hwports.
 *
 * TODO: randomise the tx port and the IP addrs
 */
#define LACP_TEST_ITERS 5
static void test_txport_lacp(int hwports, cicp_llap_type_t hash,
                             const ci_mac_addr_t src_mac)
{
  struct zf_stack* stack_bond0;
  struct hwport_rxer rx[hwports];

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  cmp_ok(zf_stack_alloc(attr, &stack_bond0), "==", 0,
         "Created stack on a bond");

  /* Allocate stacks on all client interfaces */
  alloc_stacks(rx, hwports);

  for( int i = 0; i < LACP_TEST_ITERS; i++ ) {
    /* Set up a dst mac */
    ci_mac_addr_t dst_mac;
    set_random_mac(dst_mac);
    zf_emu_set_dst_mac(dst_mac);

    /* The first call to zfur_addr_bind will select a local port, which we then
     * use for all our RX zockets. */
    struct sockaddr_in rx_addr = {
      AF_INET, 0, { inet_addr("127.0.0.2") },
    };
    struct sockaddr_in tx_addr = {
      AF_INET, htons(10000), { inet_addr("192.168.0.1") },
    };

    for( int i = 0; i < hwports; i++ )
      rx[i].zock = alloc_rx(rx[i].st, &rx_addr, &tx_addr);

    struct zfut* tx_zock = alloc_tx(stack_bond0, &tx_addr, &rx_addr);

    int rx_hwport = lacp_tx_hwport(stack_bond0, hash, &tx_addr, &rx_addr,
                                   src_mac, dst_mac);

    const char message = 0xef;
    char buf = 0;
    ZF_TRY(zfut_send_single(tx_zock, &message, sizeof(message)));

    while(zf_reactor_perform(rx[rx_hwport].st) == 0);
    while(zf_reactor_perform(rx[rx_hwport].st) != 0);
    cmp_ok(zfur_opaque_recv(rx[rx_hwport].zock, &buf, 1), "==", 1,
           "Received UDP");
    cmp_ok(buf, "==", message, "Data valid");

    for( int i = 0; i < hwports; i++ ) {
      int rc = zf_reactor_perform(rx[i].st);
      cmp_ok(rc, "==", 0, "No events on unexpected hwport");
      cmp_ok(zfur_opaque_recv(rx[i].zock, &buf, 1), "==", 0,
             "No unexpected RX");
    }

    ZF_TRY(zfut_free(tx_zock));
    for( int i = 0; i < hwports; i++ )
      ZF_TRY(zfur_free(rx[i].zock));
  }

  for( int i = 0; i < hwports; i++ )
    ZF_TRY(zf_stack_free(rx[i].st));

  ZF_TRY(zf_stack_free(stack_bond0));
}

static void test_no_hwports(int hwports, cicp_llap_type_t hash,
                            const ci_mac_addr_t src_mac)
{
  struct zf_stack* stack_bond0;
  struct hwport_rxer* rx;

  rx = (struct hwport_rxer*) malloc(hwports * sizeof(struct hwport_rxer));
  ZF_TEST(rx);

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  cmp_ok(zf_stack_alloc(attr, &stack_bond0), "==", 0,
         "Created stack on a bond");

  /* Allocate stacks on all client interfaces */
  alloc_stacks(rx, hwports);

  for( int i = 0; i < LACP_TEST_ITERS; i++ ) {
    ci_mac_addr_t dst_mac;
    set_random_mac(dst_mac);
    zf_emu_set_dst_mac(dst_mac);

    /* The first call to zfur_addr_bind will select a local port, which we then
     * use for all our RX zockets. */
    struct sockaddr_in rx_addr = {
      AF_INET, 0, { inet_addr("127.0.0.2") },
    };
    struct sockaddr_in tx_addr = {
      AF_INET, htons(10000), { inet_addr("192.168.0.1") },
    };

    for( int i = 0; i < hwports; i++ )
      rx[i].zock = alloc_rx(rx[i].st, &rx_addr, &tx_addr);

    /* Zocket will be pinned on allocation */
    struct zfut* tx_zock = alloc_tx(stack_bond0, &tx_addr, &rx_addr);

    /* Get the current hwport */
    int rx_hwport = lacp_tx_hwport(stack_bond0, hash, &tx_addr, &rx_addr,
                                   src_mac, dst_mac);

    /* Set the hwports to zero */
    zf_emu_intf_set_tx_hwports("bond0", 0);

    /* Poll to make bond changes visible */
    zf_reactor_perform(stack_bond0);

    /* Check that the application works as we expect it to: ignoring the bond
     * update. Note that the behaviour we're testing here is not contractual.
     * The most important thing here is that our applications a) doesn't crash
     * and b) recovers when the bond advertises TX hwports again. Testing here
     * that the bond state doesn't change is just a safety net rather than a
     * test for correctness. */
    const char message = 0xef;
    char buf = 0;

    ZF_TRY(zfut_send_single(tx_zock, &message, sizeof(message)));

    /* Ensure it's received on the right intf */
    while( zf_reactor_perform(rx[rx_hwport].st) == 0 );
    while( zf_reactor_perform(rx[rx_hwport].st) != 0 );
    cmp_ok(zfur_opaque_recv(rx[rx_hwport].zock, &buf, 1), "==", 1,
           "Received UDP");
    cmp_ok(buf, "==", message, "Data valid");

    /* Ensure the other stacks haven't received anything */
    for( int i = 0; i < hwports; i++ ) {
      int rc = zf_reactor_perform(rx[i].st);
      cmp_ok(rc, "==", 0, "No events on unexpected hwport");
      cmp_ok(zfur_opaque_recv(rx[i].zock, &buf, 1), "==", 0,
             "No unexpected RX");
    }

    ZF_TRY(zfut_free(tx_zock));
    for( int i = 0; i < hwports; i++ )
      ZF_TRY(zfur_free(rx[i].zock));
  }

  for( int i = 0; i < hwports; i++ )
    ZF_TRY(zf_stack_free(rx[i].st));

  ZF_TRY(zf_stack_free(stack_bond0));
}

static void test_lacp_failover(int hwports, cicp_llap_type_t hash, 
                               const ci_mac_addr_t src_mac)
{
  struct zf_stack* stack_bond0;
  struct hwport_rxer* rx;

  rx = (struct hwport_rxer*) malloc(hwports * sizeof(struct hwport_rxer));
  ZF_TEST(rx);

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  cmp_ok(zf_stack_alloc(attr, &stack_bond0), "==", 0,
         "Created stack on a bond");

  /* Allocate stacks on all client interfaces */
  alloc_stacks(rx, hwports);

  for( int i = 0; i < LACP_TEST_ITERS; i++ ) {
    ci_mac_addr_t dst_mac;
    set_random_mac(dst_mac);
    zf_emu_set_dst_mac(dst_mac);

    /* The first call to zfur_addr_bind will select a local port, which we then
     * use for all our RX zockets. */
    struct sockaddr_in rx_addr = {
      AF_INET, 0, { inet_addr("127.0.0.2") },
    };
    struct sockaddr_in tx_addr = {
      AF_INET, htons(10000), { inet_addr("192.168.0.1") },
    };

    for( int i = 0; i < hwports; i++ )
      rx[i].zock = alloc_rx(rx[i].st, &rx_addr, &tx_addr);

    struct zfut* tx_zock = alloc_tx(stack_bond0, &tx_addr, &rx_addr);

    /* By now, TX zocket has been pinned. Trigger failover on the hwport
     * traffic is currently being steered towards. */

    /* Get the current hwport */
    int rx_hwport = lacp_tx_hwport(stack_bond0, hash, &tx_addr, &rx_addr,
                                   src_mac, dst_mac);

    /* Unset the current hwport */
    int tx_hwports = ((1 << hwports) - 1) & ~(1 << rx_hwport);
    zf_emu_intf_set_tx_hwports("bond0", tx_hwports);

    /* Perform a reactor poll. The stack should notice that the bond is stale
     * and repin TX zockets.  */
    zf_reactor_perform(stack_bond0);

    /* Calculate the new hwport */
    rx_hwport = lacp_tx_hwport(stack_bond0, hash, &tx_addr, &rx_addr, src_mac,
                               dst_mac);
    /* Send single packet */
    const char message = 0xef;
    char buf = 0;

    ZF_TRY(zfut_send_single(tx_zock, &message, sizeof(message)));

    /* Ensure it's received on the right intf */
    while( zf_reactor_perform(rx[rx_hwport].st) == 0 );
    while( zf_reactor_perform(rx[rx_hwport].st) != 0 );
    cmp_ok(zfur_opaque_recv(rx[rx_hwport].zock, &buf, 1), "==", 1,
           "Received UDP");
    cmp_ok(buf, "==", message, "Data valid");

    /* Ensure the other stacks haven't received anything */
    for( int i = 0; i < hwports; i++ ) {
      int rc = zf_reactor_perform(rx[i].st);
      cmp_ok(rc, "==", 0, "No events on unexpected hwport");
      cmp_ok(zfur_opaque_recv(rx[i].zock, &buf, 1), "==", 0,
             "No unexpected RX");
    }

    ZF_TRY(zfut_free(tx_zock));
    for( int i = 0; i < hwports; i++ )
      ZF_TRY(zfur_free(rx[i].zock));
  }

  for( int i = 0; i < hwports; i++ )
    ZF_TRY(zf_stack_free(rx[i].st));

  ZF_TRY(zf_stack_free(stack_bond0));
}

void cplane_init(int hwports, cicp_llap_type_t hash_type, ci_mac_addr_t mac)
{
  ZF_TRY(zf_init());

  ZF_TRY(zf_attr_alloc(&attr));

  /* This test requires the loopback shim. */
  ZF_TEST(attr->emu == ZF_EMU_LOOPBACK);

  /* We need _somthing_ to test over */
  ZF_TEST(hwports > 0);

  /* We configure a bond over one set of interfaces, then use the partner
   * links directly:
   *
   *   -------------------
   *   |      bond0      |
   *   | ethX       ethY |
   *   ---|----------|----
   *      |          |
   *   ---|----------|----
   *   | ethM      ethN  |
   *   -------------------
   */

  set_random_mac(mac);

  for( int i = 0; i < hwports; i++ ) {
    char if_name[IF_NAMESIZE];
    int bond_vi = i;
    int peer_vi = i + hwports;

    snprintf(if_name, IF_NAMESIZE, "eth%d", bond_vi);
    zf_emu_intf_add(if_name, 1 << bond_vi, 1 << bond_vi, 0, 0, peer_vi, mac);

    snprintf(if_name, IF_NAMESIZE, "eth%d", peer_vi);
    zf_emu_intf_add(if_name, 1 << peer_vi, 1 << peer_vi, 0, 0, bond_vi, mac);
  }

  zf_emu_intf_add("bond0",  (1 << hwports) - 1, (1 << hwports) - 1, 0,
                  hash_type, -1, mac);
}


void enable_all_hwports(int n_hwports)
{
  zf_emu_intf_set_tx_hwports("bond0", (1 << n_hwports) - 1);
}


void cplane_fini(void)
{
  zf_emu_remove_all_intfs();
}


void init(void)
{
  ZF_TRY(zf_init());

  ZF_TRY(zf_attr_alloc(&attr));

  /* This test requires the loopback shim. */
  ZF_TEST(attr->emu == ZF_EMU_LOOPBACK);
}


void fini(void)
{
  zf_attr_free(attr);
  zf_deinit();
}


/* The emulator doesn't currently support a bond over a single interface */
#define MIN_HWPORTS 2
#define MAX_HWPORTS 4

static const int hash_types[] = { CICP_LLAP_TYPE_XMIT_HASH_LAYER2,
                                  CICP_LLAP_TYPE_XMIT_HASH_LAYER23,
                                  CICP_LLAP_TYPE_XMIT_HASH_LAYER34 };
const int n_hash_types = sizeof(hash_types)/sizeof(hash_types[0]);

int num_tests(void)
{
  /* For each number of hwports:
   * 1 - check stack allocation
   * (2 * LACP_TEST_ITERS) - on each iter check that a) zock receives data and
   *                         b) data is valid
   * (n_hwports * LACP_TEST_ITERS * 2) - on each iter, for each hwport
   *                         check that a) reactor poll receives no events and
   *                         b) zock receive returns no events
   */
  int n_tests = 0;

  for( int n_hwports = MIN_HWPORTS; n_hwports <= MAX_HWPORTS; n_hwports++)
    n_tests += (1 + (2 * LACP_TEST_ITERS) + (n_hwports * LACP_TEST_ITERS * 2));

  return 3 * n_tests * n_hash_types;
}

int main(int argc, char* argv[])
{
  ci_mac_addr_t mac;
  int seed = zf_frc64();
  srandom(seed);
  diag("Using seed %d", seed);

  plan(num_tests());

  init();

  for( int i = 0; i < n_hash_types; i++ ) {
    cicp_llap_type_t hash = hash_types[i];

    /* Test tx port selection for this hash type */
    for( int n_hwports = MIN_HWPORTS; n_hwports <= MAX_HWPORTS; n_hwports++ ) {
      cplane_init(n_hwports, hash, mac);

      enable_all_hwports(n_hwports);
      test_txport_lacp(n_hwports, hash, mac);

      enable_all_hwports(n_hwports);
      test_no_hwports(n_hwports, hash, mac);

      enable_all_hwports(n_hwports);
      test_lacp_failover(n_hwports, hash, mac);

      cplane_fini();
    }
  }

  fini();

  return 0;
}
