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


/* hwports for the interfaces used by this test. */
enum interface_hwports {
  ETH0 = 0x1,
  ETH1 = 0x2,
  ETH2 = 0x4,
  ETH3 = 0x8,
};


struct zf_attr* attr;


/* Creates a stack on bond0, and two more stacks on eth2 and eth3, which are
 * the base peer interfaces.  UDP traffic is then sent from each of eth2 and
 * eth3, and RX behaviour validated. */
#define SLAVE_RX_TESTS 5
static void test_slave_rx(void)
{
  struct zf_stack* stack_bond0;
  struct zf_stack* stack_eth2;
  struct zf_stack* stack_eth3;

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  cmp_ok(zf_stack_alloc(attr, &stack_bond0), "==", 0,
         "Created stack on a bond");
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth2"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth2));
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth3"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth3));

  /* Create UDP zockets on both legs of the bond. */
  struct abstract_zocket_pair pair_eth2, pair_eth3;
  alloc_udp_pair(stack_bond0, stack_eth2, attr, &pair_eth2);
  alloc_udp_pair(stack_bond0, stack_eth3, attr, &pair_eth3);

  for( struct abstract_zocket_pair* pair: {&pair_eth2, &pair_eth3} ) {
    /* The abstract_zocket_pair.h apparatus sends and receives single-byte
     * messages.  We send [message] and receive it into [buf]. */
    const char message = 0xef;
    char buf = 0;
    ZF_TEST(message != buf);
    ZF_TRY(pair->send(pair->opaque_tx, message));
    while(zf_reactor_perform(stack_bond0) == 0);
    while(zf_reactor_perform(stack_bond0) != 0);
    cmp_ok(pair->recv(pair->opaque_rx, &buf, 1), "==", 1, "Received UDP");
    cmp_ok(buf, "==", message, "Data valid");
  }

  ZF_TRY(zf_stack_free(stack_eth3));
  ZF_TRY(zf_stack_free(stack_eth2));
  ZF_TRY(zf_stack_free(stack_bond0));
}


/* Creates a stack on bond0, and two more stacks on eth2 and eth3, which are
 * the base peer interfaces.  eth2 floods the bond with UDP traffic while eth3
 * sends sparse traffic.  We ensure that eth3's traffic is received despite
 * the flood from eth2. */
#define RX_FAIRNESS_TESTS 2
#define RX_FAIRNESS_ITERATIONS 20
#define RX_FAIRNESS_BURST_A 30
#define RX_FAIRNESS_BURST_B 4
static void test_rx_fairness(void)
{
  struct zf_stack* stack_bond0;
  struct zf_stack* stack_eth2;
  struct zf_stack* stack_eth3;

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  ZF_TRY(zf_stack_alloc(attr, &stack_bond0));
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth2"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth2));
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth3"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth3));

  /* Create UDP zockets on both legs of the bond. */
  struct abstract_zocket_pair pair_eth2, pair_eth3;
  alloc_udp_pair(stack_bond0, stack_eth2, attr, &pair_eth2);
  alloc_udp_pair(stack_bond0, stack_eth3, attr, &pair_eth3);

  const char message = 0xef;
  char buf = 0;

  unsigned eth2_sent = 0;
  unsigned eth3_sent = 0;
  unsigned eth2_received = 0;
  unsigned eth3_received = 0;

  /* Send UDP packets on both eth2 and eth3 while polling "slowly". */
  for( int i = 0; i < RX_FAIRNESS_ITERATIONS; ++i ) {
    for( int j = 0; j < RX_FAIRNESS_BURST_A; ++j ) {
      int rc = pair_eth2.send(pair_eth2.opaque_tx, message);
      if( rc == -EAGAIN )
        break;
      ZF_TEST(rc >= 0);
      ++eth2_sent;
    }
    for( int j = 0; j < RX_FAIRNESS_BURST_B; ++j ) {
      int rc = pair_eth3.send(pair_eth3.opaque_tx, message);
      if( rc == -EAGAIN )
        break;
      ZF_TEST(rc >= 0);
      ++eth3_sent;
    }

    /* Run the reactor enough to receive 1 batch of events,
     * but don't exhaust it. */
    while( zf_reactor_perform(stack_bond0) == 0 );

    while( pair_eth2.recv(pair_eth2.opaque_rx, &buf, 1) == 1 )
      ++eth2_received;
    while( pair_eth3.recv(pair_eth3.opaque_rx, &buf, 1) == 1 )
      ++eth3_received;

    /* Ensure we have not received all of eth2's traffic,
     * otherwise this test is invalid. */
    ZF_TEST(eth2_received < eth2_sent);
  }

  diag("Received %u of %u packets on 1st VI\n", eth2_received, eth2_sent);
  diag("Received %u of %u packets on 2nd VI\n", eth3_received, eth3_sent);
  cmp_ok(eth2_received, ">=", eth2_sent / 4,
         "Received enough traffic from 1st VI");
  cmp_ok(eth3_received, ">=", eth3_sent / 4,
         "Received enough traffic from 2nd VI");

  ZF_TRY(zf_stack_free(stack_eth3));
  ZF_TRY(zf_stack_free(stack_eth2));
  ZF_TRY(zf_stack_free(stack_bond0));
}


#define UNSUPPORTED_TESTS 4
void test_unsupported(void)
{
  struct zf_attr* local_attr = zf_attr_dup(attr);
  ZF_TEST(local_attr);

  struct zf_stack* stack;

  /* Bond with no slaves. */
  ZF_TRY(zf_attr_set_str(local_attr, "interface", "bond2"));
  cmp_ok(zf_stack_alloc(local_attr, &stack), "==", -EIO,
         "Didn't allocate bonded stack with no slaves");

  ZF_TRY(zf_attr_set_str(local_attr, "interface", "bond0"));
  ZF_TRY(zf_attr_set_int(local_attr, "alt_count", 2));
  cmp_ok(zf_stack_alloc(local_attr, &stack), "==", -EINVAL,
         "Didn't allocate bonded stack with alternatives");

  /* Test the check for bond-homogeneity.  The emulator doesn't have enough
   * plumbing to attempt to create stacks on inhomogeneous VIs, so we check the
   * underlying implementation instead. */

  ef_vi vi_a, vi_b;
  vi_a.nic_type.arch = EF_VI_ARCH_EF10;
  vi_a.nic_type.variant = 'A';
  vi_a.rx_prefix_len = 0;
  vi_a.rx_ts_correction = 0;
  vi_a.tx_ts_correction_ns = 0;
  vi_a.ts_format = TS_FORMAT_SECONDS_27FRACTION;

  vi_b = vi_a;
  cmp_ok(zf_stack_check_vi_compatibility(NO_STACK, local_attr, &vi_a, &vi_b),
         "==", 0, "Identical VIs are compatible");

  vi_b = vi_a;
  vi_b.rx_prefix_len++;
  cmp_ok(zf_stack_check_vi_compatibility(NO_STACK, local_attr, &vi_a, &vi_b),
         "==", -EDOM, "Mismatched prefix lengths");

  zf_attr_free(local_attr);
}


/* Creates a stack on bond0, and two more stacks on eth2 and eth3, which are
 * the base peer interfaces.  UDP traffic is then sent from bond0, and we
 * check that it is received correctly at one of the rx zocks.
 */
#define SANITY_LACP_TESTS 3
static void test_sanity_lacp(void)
{
  struct zf_stack* stack_bond0;
  struct zf_stack* stack_eth2;
  struct zf_stack* stack_eth3;
  struct zfut* tx;
  struct zfur* rx_eth2;
  struct zfur* rx_eth3;

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond0"));
  ZF_TRY(zf_stack_alloc(attr, &stack_bond0));

  ZF_TRY(zf_attr_set_str(attr, "interface", "eth2"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth2));
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth3"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth3));

  ok(1, "Created stacks");

  /* Initialise RX port as 0.  On the first zfur bind this will be replaced
   * with an ephemeral port, and we then use the same structure for the
   * second zfur, so they're both waiting for packets to the same address.
   */
  struct sockaddr_in rx_addr = {
    AF_INET,
    0,
    { inet_addr("127.0.0.2") },
  };
  struct sockaddr_in tx_addr = {
    AF_INET,
    htons(10000),
    { inet_addr("192.168.0.1") },
  };

  /* Create UDP zockets on both legs of the bond. */
  ZF_TRY(zfur_alloc(&rx_eth2, stack_eth2, attr));
  ZF_TRY(zfur_addr_bind(rx_eth2, (struct sockaddr*)&rx_addr, sizeof(rx_addr),
                        (struct sockaddr*)&tx_addr, sizeof(tx_addr), 0));

  ZF_TRY(zfur_alloc(&rx_eth3, stack_eth3, attr));
  ZF_TRY(zfur_addr_bind(rx_eth3, (struct sockaddr*)&rx_addr, sizeof(rx_addr),
                        (struct sockaddr*)&tx_addr, sizeof(tx_addr), 0));

  ZF_TRY(zfut_alloc(&tx, stack_bond0,
                    (const struct sockaddr*)&tx_addr, sizeof(tx_addr),
                    (const struct sockaddr*)&rx_addr, sizeof(rx_addr),
                    0, attr));

  ok(1, "Created zocks");

  const char message = 0xef;
  char buf = 0;
  ZF_TEST(message != buf);

  ZF_TRY(zfut_send_single(tx, &message, sizeof(message)));

  while( (zf_reactor_perform(stack_eth2) == 0) &&
         (zf_reactor_perform(stack_eth3) == 0) );
  while( (zf_reactor_perform(stack_eth2) != 0) ||
         (zf_reactor_perform(stack_eth3) != 0) );

  int rx = zfur_opaque_recv(rx_eth2, &buf, 1);
  rx += zfur_opaque_recv(rx_eth3, &buf, 1);

  cmp_ok(rx, "==", 1, "Received UDP");

  ZF_TRY(zf_stack_free(stack_eth2));
  ZF_TRY(zf_stack_free(stack_eth3));
  ZF_TRY(zf_stack_free(stack_bond0));
}


/* Creates a stack on bond1, and two more stacks on eth0 and eth1, which are
 * the base peer interfaces.  UDP traffic is then sent from bond0, and we
 * check that it is received correctly at eth0 and not eth1.
 */
#define SANITY_AB_TESTS 9
static void test_sanity_ab(void)
{
  struct zf_stack* stack_bond1;
  struct zf_stack* stack_eth0;
  struct zf_stack* stack_eth1;
  struct zfut* tx;
  struct zfur* rx_eth0;
  struct zfur* rx_eth1;

  ZF_TRY(zf_attr_set_str(attr, "interface", "bond1"));
  ZF_TRY(zf_stack_alloc(attr, &stack_bond1));

  ZF_TRY(zf_attr_set_str(attr, "interface", "eth0"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth0));
  ZF_TRY(zf_attr_set_str(attr, "interface", "eth1"));
  ZF_TRY(zf_stack_alloc(attr, &stack_eth1));

  ok(1, "Created stacks");

  /* Initialise RX port as 0.  On the first zfur bind this will be replaced
   * with an ephemeral port, and we then use the same structure for the
   * second zfur, so they're both waiting for packets to the same address.
   */
  struct sockaddr_in rx_addr = {
    AF_INET,
    0,
    { inet_addr("127.0.0.2") },
  };
  struct sockaddr_in tx_addr = {
    AF_INET,
    htons(10000),
    { inet_addr("192.168.0.1") },
  };

  /* Create UDP zockets on both legs of the bond. */
  ZF_TRY(zfur_alloc(&rx_eth0, stack_eth0, attr));
  ZF_TRY(zfur_addr_bind(rx_eth0, (struct sockaddr*)&rx_addr, sizeof(rx_addr),
                        (struct sockaddr*)&tx_addr, sizeof(tx_addr), 0));

  ZF_TRY(zfur_alloc(&rx_eth1, stack_eth1, attr));
  ZF_TRY(zfur_addr_bind(rx_eth1, (struct sockaddr*)&rx_addr, sizeof(rx_addr),
                        (struct sockaddr*)&tx_addr, sizeof(tx_addr), 0));

  ZF_TRY(zfut_alloc(&tx, stack_bond1,
                    (const struct sockaddr*)&tx_addr, sizeof(tx_addr),
                    (const struct sockaddr*)&rx_addr, sizeof(rx_addr),
                    0, attr));

  ok(1, "Created zocks");

  const char message = 0xef;
  char buf = 0;
  ZF_TEST(message != buf);

  ZF_TRY(zfut_send_single(tx, &message, sizeof(message)));

  while(zf_reactor_perform(stack_eth0) == 0);
  while(zf_reactor_perform(stack_eth0) != 0);

  cmp_ok(zfur_opaque_recv(rx_eth0, &buf, 1), "==", 1, "Received UDP");
  cmp_ok(buf, "==", message, "Data valid");
  cmp_ok(zf_reactor_perform(stack_eth1), "==", 0, "No events on wrong port");

  /* Failover: set active slave to eth3 and poll the stack to cause it to take
   * notice. */
  zf_emu_intf_set_tx_hwports("bond1", ETH3);
  zf_reactor_perform(stack_bond1);

  /* Repeat the sending test from before the failover.  This time, the traffic
   * should flow on the other link. */
  buf = 0;
  ZF_TEST(message != buf);

  ZF_TRY(zfut_send_single(tx, &message, sizeof(message)));

  while(zf_reactor_perform(stack_eth1) == 0);
  while(zf_reactor_perform(stack_eth1) != 0);

  cmp_ok(zfur_opaque_recv(rx_eth1, &buf, 1), "==", 1,
         "Received UDP after failover");
  cmp_ok(buf, "==", message, "Data valid");
  cmp_ok(zf_reactor_perform(stack_eth0), "==", 0,
         "No events on wrong port after failover");

  /* Change the bond's MAC address.  In principle we only have to notice
   * changes when failing over, but assuming that "failover" is an atomic
   * concept seems unwise, so in fact we notice any change in a bond's MAC
   * address, and that's what we test here. */
  struct zf_udp_tx* udp_tx = ZF_CONTAINER(struct zf_udp_tx, handle, tx);
  ci_mac_addr_t mac;
  /* Flip all the bits of the MAC address.  In real life, we'd expect the
   * bond's MAC address to come from a slave, but there's no reason that it has
   * to be so. */
  for( int i = 0; i < ETH_ALEN; ++i )
    mac[i] = ~zf_tx_ethhdr(&udp_tx->tx)->h_source[i];

  zf_emu_intf_set_mac("bond1", mac);

  /* Poll the stack so that ZF can update the MAC address. */
  zf_reactor_perform(stack_bond1);

  /* Check that the MAC address was updated. */
  cmp_ok(memcmp(zf_tx_ethhdr(&udp_tx->tx)->h_source, mac, ETH_ALEN), "==", 0,
         "MAC address was updated");

  ZF_TRY(zf_stack_free(stack_eth0));
  ZF_TRY(zf_stack_free(stack_eth1));
  ZF_TRY(zf_stack_free(stack_bond1));

  /* Restore the original active slave. */
  zf_emu_intf_set_tx_hwports("bond1", ETH2);
}


/* Sets bond1's TX hwports to zero, creates a stack on bond1 and tests that we
 * can send without crashing. */
#define NO_INITIAL_TX_HWPORTS_TESTS 3
static void test_no_initial_tx_hwports(void)
{
  struct zf_stack* stack_bond1;
  struct zfut* tx;

  zf_emu_intf_set_tx_hwports("bond1", 0);
  ZF_TRY(zf_attr_set_str(attr, "interface", "bond1"));
  ZF_TRY(zf_stack_alloc(attr, &stack_bond1));

  pass("Created stack with no TX hwports");

  struct sockaddr_in rx_addr = { AF_INET, 0x8888, {inet_addr("127.0.0.2")} };
  struct sockaddr_in tx_addr = { AF_INET, 0x8888, {inet_addr("192.168.0.1")} };
  ZF_TRY(zfut_alloc(&tx, stack_bond1,
                    (const struct sockaddr*)&tx_addr, sizeof(tx_addr),
                    (const struct sockaddr*)&rx_addr, sizeof(rx_addr),
                    0, attr));

  pass("Created zocket with no TX hwports");

  const char message = 0xef;
  char buf = 0;
  ZF_TEST(message != buf);

  ZF_TRY(zfut_send_single(tx, &message, sizeof(message)));

  pass("Sent UDP datagram with no TX hwports");

  /* We don't try to receive that datagram, because we don't guarantee that it
   * will go out when there are no TX hwports. */

  ZF_TRY(zf_stack_free(stack_bond1));

  /* Restore the original active slave. */
  zf_emu_intf_set_tx_hwports("bond1", ETH2);
}


void init(void)
{
  ZF_TRY(zf_init());

  ZF_TRY(zf_attr_alloc(&attr));

  /* This test requires the loopback shim. */
  ZF_TEST(attr->emu == ZF_EMU_LOOPBACK);

  /* We configure two bonds over two pairs of interfaces, connected like so:
   *
   *   -------------------
   *   |      bond0      |
   *   | eth0       eth1 |
   *   ---|----------|----
   *      |          |
   *   ---|----------|----
   *   | eth2       eth3 |
   *   |      bond1      |
   *   -------------------
   *
   * We also create a bond2 with no slaves.
   */

  zf_emu_intf_add("eth0", ETH0, ETH0, 0, 0, 2, NULL);
  zf_emu_intf_add("eth1", ETH1, ETH1, 0, 0, 3, NULL);
  zf_emu_intf_add("eth2", ETH2, ETH2, 0, 0, 0, NULL);
  zf_emu_intf_add("eth3", ETH3, ETH3, 0, 0, 1, NULL);

  /* Create one LACP bond, with tx_hwports == rx_hwports, and one active-backup
   * bond, with a single TX hwport. */
  zf_emu_intf_add("bond0", ETH0 | ETH1, ETH0 | ETH1, 0,
                  CICP_LLAP_TYPE_XMIT_HASH_LAYER34, -1, NULL);
  zf_emu_intf_add("bond1", ETH2 | ETH3, ETH2, 0, 0, -1, NULL);
  zf_emu_intf_add("bond2", 0, 0, 0, 0, -1, NULL);
}


void fini(void)
{
  zf_attr_free(attr);
  zf_deinit();
}


int main(int argc, char* argv[])
{
  plan(SLAVE_RX_TESTS + RX_FAIRNESS_TESTS + UNSUPPORTED_TESTS +
       SANITY_AB_TESTS + SANITY_LACP_TESTS + NO_INITIAL_TX_HWPORTS_TESTS);
  init();

  /* UDP from base interfaces to bond. */
  test_slave_rx();

  /* Reactor poll fairness for LACP. */
  test_rx_fairness();

  /* Graceful handling of unsupported cases. */
  test_unsupported();

  /* Sanity check TX via lacp */
  test_sanity_lacp();

  /* Sanity check TX via active backup, including failover. */
  test_sanity_ab();

  /* Test that we don't fall over when there are no TX hwports. */
  test_no_initial_tx_hwports();

  fini();

  return 0;
}
