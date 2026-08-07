#include "common.h"
#include "ctl.h"
#include "device.h"
#include "loop.h"
#include "tun.h"
#include "uapi.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void
on_sig (int sig)
{
  (void)sig;
  loop_stop ();
}

static int
daemonize (void)
{
  pid_t pid = fork ();
  if (pid < 0)
    return -1;
  if (pid > 0)
    return 1;
  if (setsid () < 0)
    return -1;
  if (!getenv ("LOG_LEVEL"))
    {
      int fd = open ("/dev/null", O_RDWR);
      if (fd >= 0)
        {
          dup2 (fd, STDIN_FILENO);
          dup2 (fd, STDOUT_FILENO);
          dup2 (fd, STDERR_FILENO);
          if (fd > STDERR_FILENO)
            close (fd);
        }
    }
  return 0;
}

static void
usage (const char *arg0)
{
  fprintf (stderr, "usage: %s [-f|--foreground] INTERFACE\n", arg0);
}

int
main (int argc, char **argv)
{
  bool fg = false;
  const char *name;
  Dev *d;
  int ctl = -1;
  int rc = 1;

  if (argc == 2 && !strcmp (argv[1], "--version"))
    {
      puts ("cwg 0.1");
      return 0;
    }
  if (argc == 3
      && (!strcmp (argv[1], "-f") || !strcmp (argv[1], "--foreground")))
    {
      fg = true;
      name = argv[2];
    }
  else if (argc == 2)
    name = argv[1];
  else
    {
      usage (argv[0]);
      return 1;
    }
  if (!if_ok (name))
    {
      errno = EINVAL;
      perror ("interface");
      return 1;
    }
  if (getenv ("WG_PROCESS_FOREGROUND"))
    fg = true;
  if (sodium_init () < 0)
    return 1;
  log_init ();

  if (ctl_add (name) == 0)
    return 0;
  if (errno != ENOENT && errno != ECONNREFUSED)
    {
      err ("%s: master: %s", name, strerror (errno));
      return 1;
    }
  if (errno == ECONNREFUSED)
    unlink (CTL_PATH);

  d = dev_new (name);
  if (!d)
    return 1;
  d->tun = tun_open (name);
  if (d->tun < 0)
    {
      err ("%s: tun: %s", name, strerror (errno));
      goto out;
    }
  if (uapi_open (d) < 0)
    {
      err ("%s: uapi: %s", name, strerror (errno));
      goto out;
    }
  if (dev_bind (d, 0, 0) < 0)
    {
      err ("%s: udp: %s", name, strerror (errno));
      goto out;
    }
  ctl = ctl_open ();
  if (ctl < 0)
    {
      err ("master: %s", strerror (errno));
      goto out;
    }
  if (!fg)
    {
      int dr = daemonize ();
      if (dr < 0)
        goto out;
      if (dr > 0)
        return 0;
    }

  signal (SIGINT, on_sig);
  signal (SIGTERM, on_sig);
  signal (SIGHUP, on_sig);
  dbg ("(%s) up", d->name);
  rc = loop_run (d, ctl) < 0;
  d = NULL;

out:
  ctl_close (ctl);
  if (d)
    {
      uapi_close (d);
      if (d->tun >= 0)
        close (d->tun);
      dev_free (d);
    }
  return rc;
}
