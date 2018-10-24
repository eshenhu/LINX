/*
 * Copyright (c) 2006-2007, Enea Software AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Enea Software AB nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "linxdisc.h"

extern struct linxdisc_data linxdisc;

static void err_print(int do_errno, int level, const char *fmt, va_list ap)
{
#define MAXLINE		   2048
	char buf[MAXLINE];
	int n;
	sigset_t newset, oldset;

	n = vsnprintf(buf, sizeof buf, fmt, ap);

	if (do_errno)
		snprintf(buf + n, sizeof buf - n, ": %s\n", strerror(errno));

	sigaddset(&newset, SIGTERM);
	sigaddset(&newset, SIGHUP);
	sigprocmask(SIG_BLOCK, &newset, &oldset);

	if (linxdisc.daemon_proc) {
		/* "%s", in order to get rid of annoying compile warning. */
		syslog(level, "%s", buf);
	} else {
		fflush(stdout);
		fputs(buf, stderr);
		fflush(stderr);
	}

	sigprocmask(SIG_SETMASK, &oldset, NULL);
	return;
}

void err_dbg(const char *fmt, ...)
{
#ifndef NDEBUG
	va_list ap;

	va_start(ap, fmt);
	err_print(0, LOG_DEBUG, fmt, ap);
	va_end(ap);
#else
	(void)fmt;
#endif
}

void err_msg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_print(0, LOG_INFO, fmt, ap);
	va_end(ap);
}

void err_quit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_print(0, LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}

void err_sys(const char *fmt, ...)
{
	if (errno == ENETDOWN)
		return;		/* not an error */
	va_list ap;

	va_start(ap, fmt);
	err_print(1, LOG_ERR, fmt, ap);
	va_end(ap);

	exit(1);
}
