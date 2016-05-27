/*
 *
 * to do
 */

#include"myerr.h"


static void
err_doit(int, const char *, va_list);

static void
err_doit2(int errnoflag, int error, const char *fmt, va_list ap);

/*
 *  * Fatal error unrelated to a system call.
 *   * Error code passed as explict parameter.
 *    * Print a message and terminate.
 *     */
void
err_exit(int error, const char *fmt, ...)
{
     va_list         ap;

     va_start(ap, fmt);
     err_doit2(1, error, fmt, ap);
     va_end(ap);
     exit(1);
}


/* Nonfatal error related to a system call.
 * Print a message and return. */
void
err_ret(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  return;
}

/* Fatal error related to a system call.
 * Print a message and terminate. */
void
err_sys(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

/* Nonfatal error unrelated to a system call.
 * Print a message and return. */
void
err_msg(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  err_doit(0, fmt, ap);
  va_end(ap);
  return;
}

/* Fatal error unrelated to a system call.
 * Print a message and terminate. */
void
err_quit(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  err_doit(0, fmt, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

/* Print a message and return to caller.
 * Caller specifies "errnoflag". */
static void
err_doit(int errnoflag, const char *fmt, va_list ap)
{
  int errno_save;
  char buf[4096];

  errno_save = errno; /* value caller might want printed */
  vsprintf(buf, fmt, ap);
  if (errnoflag)    // if a sys call
    sprintf(buf + strlen(buf), ": %s", strerror(errno_save));
  strncat(buf, "\n",2);
  fflush(stdout); /* in case stdout and stderr are the same */
  fputs(buf, stderr);
  fflush(NULL); /* flushes all stdio output streams */
  return;
}

/*
 *  * Print a message and return to caller.
 *   * Caller specifies "errnoflag".
 *    */
static void
err_doit2(int errnoflag, int error, const char *fmt, va_list ap)
{
    char    buf[64];

    vsnprintf(buf, 63, fmt, ap);
    if (errnoflag)
    snprintf(buf+strlen(buf), 64-strlen(buf)-1, ": %s",
    strerror(error));
    strcat(buf, "\n");
    fflush(stdout);         /* in case stdout and stderr are the same */
    fputs(buf, stderr);
    fflush(NULL);           /* flushes all stdio output streams */
}
