#include "common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_log = LOG_ERR;

void
log_init (void)
{
  const char *s = getenv ("LOG_LEVEL");
  if (!s)
    return;
  if (!strcmp (s, "silent"))
    g_log = LOG_OFF;
  else if (!strcmp (s, "debug") || !strcmp (s, "verbose"))
    g_log = LOG_DBG;
}

void
log_msg (int lvl, const char *fmt, ...)
{
  va_list ap;
  if (lvl > g_log || lvl == LOG_OFF)
    return;
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  fputc ('\n', stderr);
  va_end (ap);
}
