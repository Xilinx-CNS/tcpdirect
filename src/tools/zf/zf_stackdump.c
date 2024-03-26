/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/zf_stackdump.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_log.h>

#include <onload/driveraccess.h>


static void usage(int rc)
{
  zf_log(NULL, "zf_stackdump [command [stack_ids...]]\n");
  zf_log(NULL, "\n");
  zf_log(NULL, "Commands:\n");
  zf_log(NULL, "  help       Print this usage information\n");
  zf_log(NULL, "  list       List stack(s)\n");
  zf_log(NULL, "  dump       Show state of stack(s)\n");
  zf_log(NULL, "  version    Print tcpdirect version information\n");
  zf_log(NULL, "\n");
  zf_log(NULL, "The default command is 'list'.  Commands iterate over all\n");
  zf_log(NULL, "stacks if no stacks are specified on the command line.\n");

  exit(rc);
}

void version()
{
  zf_log(NULL, "%s", zf_version());
  exit(0);
}


int main(int argc, char *argv[])
{
  constexpr int MAX_DUMP_STACKS = 256;
  int ids[MAX_DUMP_STACKS];
  int onload_dh;
  int num_stacks = 0;
  void (*cmd)(struct zf_stack*) = zf_stack_dump_summary;

  ZF_TRY(oo_fd_open(&onload_dh));
  ZF_TRY(zf_init());

  ++argv;
  --argc;

  if( argc > 0 ) {
    if( strcmp(argv[0], "list") == 0 )
      cmd = zf_stack_dump_summary;
    /* Support "lots" as an undocumented alias for "dump". */
    else if( strcmp(argv[0], "dump") == 0 || strcmp(argv[0], "lots") == 0 )
      cmd = zf_stack_dump;
    else if( strcmp(argv[0], "version") == 0 )
      version();
    else if( strcmp(argv[0], "help") == 0 )
      usage(0);
    else
      usage(1);

    while( --argc > 0 && num_stacks < MAX_DUMP_STACKS )
      ids[num_stacks++] = atoi(*++argv);
  }

  /* If there were no stacks specified on the command line, ask the driver for
   * a list of all stacks. */
  if( num_stacks == 0 ) {
    num_stacks = zf_get_all_stack_shm_ids(onload_dh, ids, MAX_DUMP_STACKS);
    ZF_TRY(num_stacks);
  }

  for( int i = 0; i < num_stacks; ++i ) {
    struct zf_stack* stack;
    int rc = zf_stack_map(onload_dh, ids[i], &stack);
    if( rc == 0 )
      cmd(stack);
    else
      zf_log(NULL, "Failed to map stack %d (rc = %d)\n", ids[i], rc);
  }

  zf_deinit();
  return 0;
}

