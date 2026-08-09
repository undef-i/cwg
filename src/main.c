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
  if (g_log != LOG_DBG)
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
usage (const char *arg0, bool direct)
{
  fprintf (stderr, direct ? "usage: %s [--wg|--awg] [-f|--foreground] INTERFACE\n"
                           : "usage: %s [-f|--foreground] INTERFACE\n",
           arg0);
}

static int
env_fd (const char *name, int *out)
{
  const char *value = getenv (name);
  char *end;
  long fd;
  if (!value || !*value)
    return 0;
  errno = 0;
  fd = strtol (value, &end, 10);
  if (errno || end == value || *end || fd < 0 || fd > INT_MAX)
    return -1;
  *out = (int)fd;
  return 1;
}

int
main (int argc, char **argv)
{
  bool fg = false;
  bool mode_arg = false;
  const char *name = NULL;
  const char *socket_dir = NULL;
  const char *arg0 = strrchr (argv[0], '/');
  bool direct;
  Dev *d;
  int ctl = -1;
  int tun_fd;
  int uapi_fd;
  bool inherited;
  int rc = 1;

  arg0 = arg0 ? arg0 + 1 : argv[0];
  direct = strcmp (arg0, "wireguard-go") && strcmp (arg0, "amneziawg-go");
  if (!strcmp (arg0, "wireguard-go"))
    socket_dir = WG_SOCKET_DIR;
  else if (!strcmp (arg0, "amneziawg-go"))
    socket_dir = AWG_SOCKET_DIR;
  if (argc == 2 && !strcmp (argv[1], "--version"))
    {
      puts ("cwg 0.1");
      return 0;
    }
  for (int i = 1; i < argc; i++)
    {
      if (!strcmp (argv[i], "-f") || !strcmp (argv[i], "--foreground"))
        fg = true;
      else if (!strcmp (argv[i], "--wg"))
        {
          if (mode_arg)
            goto bad_usage;
          socket_dir = WG_SOCKET_DIR;
          mode_arg = true;
        }
      else if (!strcmp (argv[i], "--awg"))
        {
          if (mode_arg)
            goto bad_usage;
          socket_dir = AWG_SOCKET_DIR;
          mode_arg = true;
        }
      else if (argv[i][0] != '-' && !name)
        name = argv[i];
      else
        goto bad_usage;
    }
  if (!name || !socket_dir)
    {
      usage (arg0, direct);
      return 1;
    }
  if (!if_ok (name))
    {
      errno = EINVAL;
      perror ("interface");
      return 1;
    }
  const char *foreground = getenv ("WG_PROCESS_FOREGROUND");
  if (foreground && !strcmp (foreground, "1"))
    fg = true;
  if (sodium_init () < 0)
    return 1;
  log_init ();
  int has_tun_fd = env_fd ("WG_TUN_FD", &tun_fd);
  int has_uapi_fd = env_fd ("WG_UAPI_FD", &uapi_fd);
  if (has_tun_fd < 0 || has_uapi_fd < 0)
    {
      err ("invalid WG_TUN_FD or WG_UAPI_FD");
      return 1;
    }
  inherited = has_tun_fd || has_uapi_fd;

  if (has_tun_fd != has_uapi_fd || (inherited && tun_fd == uapi_fd))
    {
      err ("WG_TUN_FD and WG_UAPI_FD must be distinct and set together");
      return 1;
    }

  if (!inherited && ctl_add (name, socket_dir) == 0)
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
  snprintf (d->socket_dir, sizeof (d->socket_dir), "%s", socket_dir);
  d->tun = inherited ? tun_adopt (tun_fd, name) : tun_open (name);
  if (d->tun < 0)
    {
      err ("%s: tun: %s", name, strerror (errno));
      goto out;
    }
  if ((inherited ? uapi_adopt (d, uapi_fd) : uapi_open (d)) < 0)
    {
      err ("%s: uapi: %s", name, strerror (errno));
      goto out;
    }
  if (dev_bind (d, 0, 0) < 0)
    {
      err ("%s: udp: %s", name, strerror (errno));
      goto out;
    }
  ctl = inherited ? -1 : ctl_open ();
  if (!inherited && ctl < 0)
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

bad_usage:
  usage (arg0, direct);
  return 1;
}
