/*
 * Copyright (c) 2006-2010, Enea Software AB
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

/*
 * File: linx_cfg_cmcl.c - This is the LINX CMCL configuration command
 *
 * Mandatory options:
 * create <interface> <link name>
 * destroy <link name>
 *
 */

#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <linx.h>
#include <linxcfg.h>
#include "linx_cfg.h"
#include "config.h"
#include "db_utils.h"
#include "cmcl_utils.h"

#define _usage   linxcfg_usage
#define _verbose linxcfg_verbose

#define POS_COMMAND 0
#define POS_LNAME   1
#define POS_OPTIONS 2
#define POS_DESTROY_LNAME 1

char *cmcl_usage_str =
	"create <link> [OPTIONS]\n"
	"    <link>        Name of the link.\n"
	"                  This will be the name used in:\n"
	"                  /proc/net/linx/rlnh\n"
	"\n"
	"    OPTIONS for 'create':\n"
	"        --tmo=<tmo>\n"
	"            Connection supervision timeout given in hundreds of ms to wait\n"
	"            before a connection is considered broken.\n"
	"            Default value is 10.\n"
	"    Examples:\n"
	"        linxcfg -t cmcl destroy link_A [link_B [...]]\n";

static struct cfg_template cmcl_template[] = {
	CFG_PARAM_ULONG("tmo", NULL),
	CFG_PARAM_LAST
};

int cmcl_main(int argc, char **argv);
void cmcl_usage(int indent);

linxcfg_cm_handler cmcl_cm_handler_obj = {
	.name = "cmcl",
	.init = cmcl_main,
	.help = cmcl_usage,
	.t = cmcl_template,
	.description = "Linx CMCL",
};

void cmcl_usage(int indent)
{
	_usage(indent, cmcl_usage_str);
}

static int parse_ul_param(unsigned long int *tmp, const char *str,
                          const char *tag, unsigned long int max)
{
	char *endptr;

	*tmp = strtoul(str, &endptr, 0);

	if (*endptr != '\0') {
		fprintf(stdout,
			"Warning: parameter <%s>:%s contains illegal characters:%s\n"
			"in addition to parsed number %lu\n",
			tag, str, endptr, *tmp);
	}

	if (max < *tmp) {
		fprintf(stderr,
			"Error: parameter <%s>:%lu is out of bounds. "
			"Max allowed value is %lu \n",
			tag, *tmp, max);
		return 1;
	}

	return 0;
}

static int mkcmcllink(char **argv)
{
	union linx_con_arg con;
	struct linx_link_arg lnk;
	char *con_name, *s, version[14];
	int status, ver;

	con_name = mk_db_key("%s_%s", CMCLCONN_PREFIX, argv[POS_LNAME]);
	if (con_name == NULL)
		return 1;

	ver = linx_get_version(version);
	if (ver == -1) {
		printf("WARNING: failed to retrieve LINX version\n");
		ver = 0;
		strcpy(version, "unknown");
	}

	memset(&con.cmcl, 0, sizeof(con.cmcl));
	memset(&lnk, 0, sizeof(lnk));
                
	{
		/* Get [OPTIONS] */
		unsigned long int tmp;

		cfg_get_value(cmcl_template, "tmo", &tmp);
		if (0xff < tmp) {
			fprintf(stderr,
				"Error: argument --tmo=%lu is out of bounds. "
				"Max allowed value is %d\n",
				tmp, 0xff);
			return 1;
		}
		if (tmp != 0)
		{
			con.cmcl.con_tmo = (uint8_t)(0xff & tmp);
		}
	}

	con.cmcl.name = con_name;

	s = NULL;
	status = linx_create_connection(LINX_CON_CMCL, &con, &s);
	if (status != 0) {
		free(con_name);
		return 1;
	}

	lnk.name = argv[POS_LNAME];
	lnk.connections = s;
	lnk.features = "";
	s = NULL;
	status = linx_create_link(&lnk);

	free(lnk.connections);
	free(con_name);
	return status;
}

int cmcl_main(int argc, char **argv)
{
	int i, retval = 0;
	printf("This is not done yet!!\n");
	switch (get_command(argv[POS_COMMAND])) {
	case CMD_CREATE:
		/* this requires at least 6 parameters */
		if (argc < POS_OPTIONS) {
			fprintf(stderr, "Error: too few arguments\n");
			show_help("cmcl");
			exit(1);
		} else if (argc > POS_OPTIONS) {
			fprintf(stderr, "Error: too many arguments\n");
			show_help("cmcl");
			exit(1);
		}
		if (mkcmcllink(argv) != 0) {
			fprintf(stderr, "Error: couldn't create link\n");
			exit(1);
		}
		break;
	case CMD_DESTROY:
		if (argc < 2) {
			fprintf(stderr, "Too few arguments.\n");
			show_help("cmcl");
			exit(1);
		}
		/* for each link */
		for (i = POS_DESTROY_LNAME; i < argc; i++) {                        
			if (argv[i] == NULL) {
				fprintf(stderr, "Error: wrong link name: %s\n",
					argv[i]);
				retval = 1;
				continue; /* Try next link... */
			}
			if (linx_remove_link_and_connections(argv[i]) != 0) {
				fprintf(stderr, "Error: link %s not removed\n",
					argv[i]);
				retval = 1;
				continue; /* Try next link... */
			}
		}
		break;
	case CMD_HELP:
		show_help("cmcl");
		return 0;
	default:
		printf("Unknown command %s\n", argv[POS_COMMAND]);
		return 1;
	}

	return retval;
}
