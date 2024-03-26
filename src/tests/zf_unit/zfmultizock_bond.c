/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2018 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/rx.h>
#include <zf_internal/tx.h>
#include <zf_internal/attr.h>
#include <zf_internal/zf_tcp_impl.h>
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/private/zf_emu.h>

#include <arpa/inet.h>

#include "../tap/tap.h"
#include "abstract_zocket_pair.h"
#include "zfmultizock.h"


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

  /* We configure a bond over two interfaces, looped back:
   *
   *   -------------------
   *   |      bond0      |
   *   | eth0       eth1 |
   *   ---|-|--------|-|--
   *      | |        | |
   *      ---        ---
   */

  zf_emu_intf_add("eth0", 1, 1, 0, 0, 0, NULL);
  zf_emu_intf_add("eth1", 2, 2, 0, 0, 1, NULL);

  /* The bond is LACP, with tx_hwports == rx_hwports */
  zf_emu_intf_add("bond0",  3, 3, 0, CICP_LLAP_TYPE_XMIT_HASH_LAYER34, -1,
                  NULL);

  ZF_TRY(zf_attr_set_str(*attr_out, "interface", "bond0"));
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


int main(void)
{
  int rc;
  struct zf_stack* stack;
  struct zf_attr* attr;

  ZF_TRY(init(&stack, &attr));
  rc = zfmultizock_test(stack, attr);
  ZF_TRY(fini(stack, attr));

  return rc;
}

