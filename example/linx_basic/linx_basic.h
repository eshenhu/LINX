/*
 * Copyright (C) 2006-2009 by Enea Software AB.
 * All rights reserved.
 *
 * This Example is furnished under a Software License Agreement and
 * may be used only in accordance with the terms of such agreement.
 * No title to and ownership of the Example is hereby transferred.
 *
 * The information in this Example is subject to change
 * without notice and should not be construed as a commitment
 * by Enea Software AB.
 *
 * DISCLAIMER
 * This Example is delivered "AS IS", consequently 
 * Enea Software AB makes no representations or warranties, 
 * expressed or implied, for the Example. 
 */

#ifndef __LINX_BASIC_H
#define __LINX_BASIC_H
#include <errno.h>
#include <string.h>

#define SERVER_NAME "example_server"
#define CLIENT_NAME "example_client"
#define IDLE_TIMEOUT 30000	/* milliseconds */
#define CLIENT_TIMEOUT 2000	/* milliseconds */

#define TOUCH(a)      ((a) = (a))

#define ERR(msg) \
do { \
  printf("ERROR @ %s:%d\n", __FILE__, __LINE__); \
  printf(msg " (errno = %d, %s)\n", errno, strerror(errno)); \
} while(0)

#endif				/*  __LINX_BASIC_H */
