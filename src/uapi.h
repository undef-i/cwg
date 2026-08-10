#pragma once

#include "device.h"

int uapi_open (Dev *d);
int uapi_adopt (Dev *d, int fd);
int uapi_hnd (Dev *d);
void uapi_drain (Dev *d);
void uapi_close (Dev *d);
