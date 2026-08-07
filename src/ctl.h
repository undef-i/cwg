#pragma once

#include "device.h"

#define CTL_PATH "/var/run/cwg.sock"

int ctl_open (void);
int ctl_add (const char *name);
int ctl_hnd (int fd, Dev **head, int ep);
void ctl_close (int fd);
