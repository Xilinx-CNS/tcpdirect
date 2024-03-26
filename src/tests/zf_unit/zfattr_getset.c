/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2019-2019 Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/attr.h>
#include <zf_internal/utils.h>

#include "../tap/tap.h"


#define NUM_TESTS 7

static void test(void)
{
  struct zf_attr* attr;
  int rc;
  char* val;

  /* create first set of attr */
  ZF_TRY(zf_attr_alloc(&attr));

  /* Can we read the default value of "name" */
  rc = zf_attr_get_str(attr, "name", &val);
  cmp_ok(rc, "==", 0, "rc for zf_attr_get_str(name)");
  ok(val == NULL, "value for zf_attr_get_str(name)");

  /* Can we read the default value of "ctpio_mode" */
  rc = zf_attr_get_str(attr, "ctpio_mode", &val);
  cmp_ok(rc, "==", 0, "rc for zf_attr_get_str(ctpio_mode)");
  ok(! strcmp(val,"sf-np"), "value for zf_attr_get_str(ctpio_mode)");

  /* Can we set "ctpio_mode" */
  rc = zf_attr_set_str(attr, "ctpio_mode", "ct");
  cmp_ok(rc, "==", 0, "rc for zf_attr_set_str(ctpio_mode)");
  ZF_TRY(zf_attr_get_str(attr, "ctpio_mode", &val));
  ok(! strcmp(val,"ct"), "value for zf_attr_get_str(ctpio_mode)");

  /* Does zf_attr_reset() work correctly */
  zf_attr_reset(attr);
  ZF_TRY(zf_attr_get_str(attr, "ctpio_mode", &val));
  ok(! strcmp(val,"sf-np"), "value for zf_attr_get_str(ctpio_mode)");

  /* TODO add extra tests for bitmask/int attributes etc */

  /* finish up */
  zf_attr_free(attr);
}


int main(void)
{
  plan(NUM_TESTS);

  int rc = zf_init();
  if( rc != 0 )
    return rc;

  test();

  zf_deinit();

  return rc;
}

