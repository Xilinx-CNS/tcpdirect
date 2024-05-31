/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) 2021 Advanced Micro Devices, Inc. */
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
#include <stdio.h>

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


#define NUM_TESTS 2
static void test_stack_dump(struct zf_stack* stack, struct zf_attr* attr)
{
  zf_stack_dump(stack);
  pass("Survived zf_stack_dump().");
}


static void test_stack_version(struct zf_stack* stack, struct zf_attr* attr)
{
  FILE* f = tmpfile();
  int fd = fileno(f);
  dup2(fd, 1000);

  /* For the purpose of capturing output of zf_stackdump, stdout is redirected to a temporary file. */
  int stdout_fd = dup(STDOUT_FILENO);
  fflush(stdout);
  dup2(fd, STDOUT_FILENO);
  zf_stack_dump(stack);
  fflush(stdout);
  dup2(stdout_fd, STDOUT_FILENO);
  lseek(1000, 0, SEEK_SET);
  int rc = system("cat /proc/self/fd/1000 | grep -E 'version=.*'");
  fclose(f);

  cmp_ok(rc, "==", 0, "Version found.");
}


int main(void)
{
  struct zf_stack* stack;
  struct zf_attr* attr;

  plan(NUM_TESTS);
  ZF_TRY(init(&stack, &attr));
  test_stack_dump(stack, attr);
  test_stack_version(stack, attr);
  ZF_TRY(fini(stack, attr));
  done_testing();

  return 0;
}

