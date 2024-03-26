/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**
 * \file
 * \brief Sockets API shim layer for ZF: fd table
 */

#include <netdb.h>

/* We use Public ZF API only */
#include <zf/zf.h>

/* But we need our own include file for the bits of the API that we don't
 * advertise to customers. */
#include <zf_internal/shim/shim.h>

#include <sys/syscall.h>

struct zf_stack* stack;
struct zf_attr* attr;
struct zf_attr* attr_short_poll;
struct sockaddr_in laddr_implict;

static enum {
  INIT_NONE,
  INIT_STARTING,
  INIT_READY,
  INIT_FINISHED
} init_level = INIT_NONE;




static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


static int parse_host(const char* s, struct in_addr* ip_out)
{
  const struct sockaddr_in* sin;
  struct addrinfo* ai;
  if( my_getaddrinfo(s, 0, &ai) < 0 )
    return 0;
  sin = (const struct sockaddr_in*) ai->ai_addr;
  *ip_out = sin->sin_addr;
  return 1;
}


/* A single static table.  User can request larger table via the attribute. */
static int zfss_fd_table_size = 256;
static struct zfss_file** fd_table;

bool zfss_init(void)
{
  return init_level == INIT_READY;
}

static void zfss_fini(void)
{
  if( zfss_enter_lib() ) {
    init_level = INIT_FINISHED;
    zfss_exit_lib();

    if( stack != NULL )
      zf_stack_free(stack);
    stack = NULL;

    if( attr != NULL )
      zf_attr_free(attr);
    attr = NULL;

    if( attr_short_poll != NULL )
      zf_attr_free(attr_short_poll);
    attr_short_poll = NULL;
  }
}


/* We used to dig inside zf_attr objects to get at socket-shim attributes, but
 * we want to maintain binary compatibility between the shim and old GA
 * versions of ZF (including hotfixes), so now we just process the ZF_ATTR
 * environment variable ourselves. */
static void zfss_process_environment(void)
{
  const char* env_attr = getenv("ZF_ATTR");
  if( env_attr == NULL )
    return;

  char* local_attr = strdup(env_attr);
  char* token;
  char* save_ptr;

  token = strtok_r(local_attr, ";", &save_ptr);
  while( token != NULL ) {
    char* implicit_host;

    if( sscanf(token, "zfss_implicit_host=%ms", &implicit_host) == 1 ) {
      /* Allow apps doing implicit binds/binds to INADDR_ANY to function. */
      parse_host(implicit_host, &laddr_implict.sin_addr);
      free(implicit_host);
    }
    else {
      sscanf(token, "zfss_fd_table_size=%d", &zfss_fd_table_size);
    }

    token = strtok_r(NULL, ";", &save_ptr);
  }

  free(local_attr);
}


bool zfss_init_real(void)
{
  if( init_level > INIT_NONE )
    return init_level == INIT_READY;

  /* We set this first, because the ZF library can make socket API calls, which
   * would otherwise bring us back into here. */
  init_level = INIT_STARTING;

  /* Do not intercept any socket() calls from zf_stack_alloc() and others */
  bool should_exit_lib = zfss_enter_lib();

  ZF_TRY(zf_init());
  ZF_TRY(zf_attr_alloc(&attr));
  attr_short_poll = zf_attr_dup(attr);
  ZF_TEST(attr_short_poll);
  ZF_TRY(zf_attr_set_int(attr_short_poll, "reactor_spin_count", 1));
  ZF_TRY(zf_stack_alloc(attr, &stack));
  ZF_TRY(atexit(zfss_fini));
  zf_log(stack, "PID=%d: Using ZF Socket Shim\n", getpid());

  zfss_process_environment();
  laddr_implict.sin_port = 0;
  fd_table = (zfss_file**)calloc(zfss_fd_table_size, sizeof(fd_table[0]));

  if( should_exit_lib )
    zfss_exit_lib();

  if( fd_table == NULL ) {
    zf_log_ss_err(stack, "Socket shim: Failed to allocate fd_table");
    /* Fixme: free stack?  crash? */
    return false;
  }

  init_level = INIT_READY;
  return true;
}


int zfss_fd_table_insert(int fd, struct zfss_file* file)
{
  if( fd >= zfss_fd_table_size )
    return -ENOSPC;

  if( fd_table[fd] != NULL ) {
    zf_assert(0);
    return -EEXIST;
  }

  file->fd = fd;
  fd_table[fd] = file;
  return 0;
}

struct zfss_file* zfss_fd_table_get(int fd)
{
  if( ! zfss_init() || fd < 0 )
    return NULL;
  return fd_table[fd];
}



int zfss_close(int fd)
{
  struct zfss_file* file = fd_table[fd];
  zf_assert(file);
  zf_assert(file->fd == fd);
  fd_table[fd] = NULL;
  free(file);
  return zfss_sys_close(fd);
}


int zfss_handover(int fd)
{
  struct zfss_file* file = fd_table[fd];
  zf_assert(file);
  zf_assert(file->fd == fd);
  fd_table[fd] = NULL;
  free(file);
  return 0;
}

