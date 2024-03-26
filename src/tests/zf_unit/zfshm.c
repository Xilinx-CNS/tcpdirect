/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2016-2017 Advanced Micro Devices, Inc. */
/**
 * \brief Shared-memory tests.
 *
 * ZF shares the memory backing its stacks and packet buffers so that they can
 * be mapped by other processes for debugging purposes.  Support for this is
 * split between two components:
 *   - a generic shared-memory mechanism, which is implemented in the kernel,
 *     and
 *   - the means of accessing data in such shared buffers when not mapped at
 *     their original locations.
 * For unit testing, the former is emulated in the shim, so testing this
 * functionality is not interesting.  This must be covered elsewhere.  Still,
 * this test can exercise the latter functionality, and it also ensures that
 * ZF's use of the shm API is correct.
 */

#include <zf/zf.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_stackdump.h>

#include "../tap/tap.h"

static int init(struct zf_stack** stack_out, struct zf_attr** attr_out)
{
  int rc;
  rc = zf_init();
  if( rc != 0 )
    return rc;

  rc = zf_attr_alloc(attr_out);
  if( rc != 0 )
    return rc;

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


#define NUM_TESTS 3

static int test(struct zf_stack* stack, struct zf_attr* attr)
{
  plan(NUM_TESTS);

  int rc;
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, stack);

  struct zf_stack* remapped_stack;
  rc = zf_stack_map(sti->onload_dh, sti->shm_id, &remapped_stack);
  if( rc != 0 )
    BAIL_OUT("Failed to map stack: rc = %d", rc);

  /* Here we're really testing the shim's emulation of the shared-memory
   * mechanism, but we do want to check these things before continuing. */
  cmp_ok((intptr_t) stack, "!=", (intptr_t) remapped_stack,
         "Stack mappings are different.");
  cmp_ok(memcmp(stack, remapped_stack, sti->alloc_len), "==", 0,
         "Both mappings map the same memory.");

  /* Dump the stack and make sure that we survive. */
  zf_stack_dump(remapped_stack);
  pass("Survived zf_stack_dump().");

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

