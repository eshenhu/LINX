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

#ifndef LINX_CFG_H
#define LINX_CFG_H

#include <stdlib.h>

#include "config.h"

#define MAC(p, n)      ((unsigned int)(*((unsigned char*)((p)+(n)))))
#define MAC_FORMAT     "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDRESS(p) MAC(p,0),MAC(p,1),MAC(p,2),MAC(p,3),MAC(p,4),MAC(p,5)

/* commands */
enum { CMD_UNKNOWN = 0,
	CMD_CREATE = 1,
	CMD_DESTROY,
	CMD_HELP
};

struct option_value {
	char *name;
	char *val;
};

/* callback type definitiosns */
typedef int (*cm_init_callback) (int argc, char **argv);
typedef void (*cm_help_callback) (int indent);

typedef struct {
	char *name;
	char *description;
	cm_init_callback init;
	cm_help_callback help;
	struct cfg_template *t;
} linxcfg_cm_handler;

void *Malloc(size_t s);

void show_help(const char *cm_name);
void linxcfg_usage(int indent, const char *fmt, ...);
unsigned int linxcfg_verbose(const char *fmt, ...);
char *get_link_feature_string(void);
char *get_connection_feature_string(void);

int get_command(const char *command);

#endif
