/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF library logging facitilites */

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_log.h>

#include <execinfo.h>

#ifndef NDEBUG
void zf_backtrace()
{
  void* stack[15];
  int n = 15;
  n = backtrace(stack, n);
  backtrace_symbols_fd(stack, n, STDERR_FILENO);
}
#endif


/* These are initialized by the call to zf_attr_alloc() from zf_init() */
uint64_t zf_log_level = ZF_LCL_ALL_ERR;
int zf_log_format;

static FILE* zf_log_file;
char zf_log_file_name[ZF_LOG_FILE_NAME_SIZE] = "/dev/stderr";

static uint64_t zf_log_level_get()
{
  return zf_log_level;
}

static void zf_log_header(struct zf_stack* st)
{
  if( zf_log_format & ZF_LF_PROCESS ) {
    fprintf(zf_log_file, "[%s:%d] ", program_invocation_short_name, getpid());
  }
  if( zf_log_format & ZF_LF_FRC ) {
    fprintf(zf_log_file, "%21lu ", zf_frc64());
  }
  if( st && zf_log_format & ZF_LF_STACK_NAME) {
    fprintf(zf_log_file, "%." ZF_STRINGIFY(ZF_STACK_NAME_SIZE) "s ", st->st_name);
  }
  if( st && zf_log_format & ZF_LF_TCP_TIME) {
    fprintf(zf_log_file, "%5u ", zf_wheel_get_current_tick(&st->times.wheel));
  }
  if( st && zf_log_format )
    fprintf(zf_log_file, "| ");
}


static void zf_log_header(struct zf_pool* pool)
{
  struct zf_stack* st = pool ? ZF_CONTAINER(struct zf_stack, pool, pool) : NULL;
  zf_log_header(st);
}


static void zf_log_header(struct zf_tcp* tcp)
{
  struct zf_stack* st = tcp ? zf_stack_from_zocket(tcp) : NULL;
  zf_log_header(st);
  if( tcp )
    fprintf(zf_log_file, "TCP#%02ld | ", TCP_ID(st, tcp));
}


static void zf_log_header(struct zf_tcp_listen_state* tls)
{
  struct zf_stack* st = tls ? zf_stack_from_zocket(tls) : NULL;
  zf_log_header(st);
  if( tls )
    fprintf(zf_log_file, "TCPL#%02ld | ", TCP_LISTEN_ID(st, tls));
}


static void zf_log_header(struct zf_udp_rx* udp_rx)
{
  struct zf_stack* st = udp_rx ? zf_stack_from_zocket(udp_rx) : NULL;
  zf_log_header(st);
  if( udp_rx )
    fprintf(zf_log_file, "UDP RX#%02ld | ", UDP_RX_ID(st, udp_rx));
}


static void zf_log_header(struct zf_udp_tx* udp_tx)
{
  struct zf_stack* st = udp_tx ? zf_stack_from_zocket(udp_tx) : NULL;
  zf_log_header(st);
  if( udp_tx )
    fprintf(zf_log_file, "UDP TX#%02ld | ", UDP_TX_ID(st, udp_tx));
}


static void zf_log_header(struct zf_muxer_set* muxer)
{
  struct zf_stack* st = muxer ? muxer->stack : NULL;
  zf_log_header(st);
}


static void zf_log_rawv(const char* fmt, va_list va, FILE* f = zf_log_file)
{
  vfprintf(f, fmt, va);
}


static void zf_logv(struct zf_stack* st, const char* fmt, va_list va)
{

  zf_log_header(st);
  zf_log_rawv(fmt, va);
}


void zf_dump(const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  zf_log_rawv(fmt, va, stdout);
  va_end(va);
}


void zf_log(struct zf_stack* st, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  zf_logv(st, fmt, va);
  va_end(va);
}

static int zf_log_set_file_name(const char *file)
{
  if( strnlen(file, ZF_LOG_FILE_NAME_SIZE) > ZF_LOG_FILE_NAME_SIZE-1 ) {
    zf_log_stack_err(NO_STACK, "%s: File name is longer than %i characters: %s\n",
                     __func__, ZF_LOG_FILE_NAME_SIZE-1, strerror(-EINVAL));
    return -EINVAL;
  }

  strncpy(zf_log_file_name, file, sizeof(zf_log_file_name));

  return 0;
}

int zf_log_redirect(const char* file)
{
  char* previous_file_name = strdup(zf_log_file_name);
  if( !previous_file_name )
    return -errno;

  int rc = zf_log_set_file_name(file);
  if( rc < 0 ) {
    free(previous_file_name);
    return rc;
  }

  FILE* f = fopen(zf_log_file_name, "a");
  if( !f ) {
    zf_log_set_file_name(previous_file_name);
    return -errno;
  }

  zf_log_stderr(); /* close any existing file */ 
  zf_log_file = f;
  
  free(previous_file_name);
  
  return fileno(f);
}

void zf_log_stderr(void)
{
  if( zf_log_file && zf_log_file != stderr )
    fclose(zf_log_file);
  zf_log_file = stderr;
}

int zf_log_replace_stderr(const char* file)
{
  int fd = open(file, O_WRONLY);
  if( fd < 0 )
    return fd;
  int rc = dup2(fd, STDERR_FILENO);
  zf_log_set_file_name(file);
  close(fd);
  return rc;
}


ZF_VISIBLE
void zf_logger::operator()(const char* fmt, va_list va) const {
  if( log_comp_level & zf_log_level_get() ) {
    zf_log_rawv(fmt, va);
  }
}


template <typename T> ZF_VISIBLE
void zf_logger::operator()(T obj, const char* fmt, ...) const {
  va_list va;
  va_start(va, fmt);
  if( log_comp_level & zf_log_level_get() ) {
    zf_log_header(obj);
    zf_log_rawv(fmt, va);
  }
  va_end(va);
}


template ZF_VISIBLE void
zf_logger::operator()<struct zf_stack*>(struct zf_stack*, const char* fmt,
                                        ...) const;
template ZF_VISIBLE void
zf_logger::operator()<struct zf_pool*>(struct zf_pool*, const char* fmt,
                                       ...) const;
template ZF_VISIBLE void
zf_logger::operator()<struct zf_tcp*>(struct zf_tcp*, const char* fmt,
                                      ...) const;
template ZF_VISIBLE void
zf_logger::operator()<struct zf_tcp_listen_state*>(struct zf_tcp_listen_state*,
                                                   const char* fmt,
                                                   ...) const;
template ZF_VISIBLE void
zf_logger::operator()<struct zf_udp_rx*>(struct zf_udp_rx*, const char* fmt,
                                         ...) const;

template ZF_VISIBLE void
zf_logger::operator()<struct zf_udp_tx*>(struct zf_udp_tx*, const char* fmt,
                                         ...) const;

template ZF_VISIBLE void
zf_logger::operator()<struct zf_muxer_set*>(struct zf_muxer_set*,
                                            const char* fmt, ...) const;
