/*
 * Copyright (c) 2007, Enea Software AB
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#define _GNU_SOURCE
#include <getopt.h>

#include "config.h"
#include "linx_cfg.h"
#include "linx_cfg_cm.h"

#define _usage   linxcfg_usage
#define _verbose linxcfg_verbose

static unsigned int VERBOSE = 0;
static unsigned int DO_HELP = 0;

#define TOTAL_MAIN_OPTIONS 7
static struct option main_options[] = {
	{"link-feature", 1, 0, 'l'},
	{"lf", 1, 0, 'l'},
	{"conn-feature", 1, 0, 'c'},
	{"cf", 1, 0, 'c'},
	{"help", 0, 0, 'h'},
	{"type", 1, 0, 't'},
	{"verbose", 0, 0, 'v'}
};
static char *main_short_options = "c:ht:v";

char *conn_fstr = NULL;
char *link_fstr = NULL;

/* this returns */
unsigned int linxcfg_verbose(const char *fmt, ...)
{
	va_list ap;

	/* Do not proceed if not in verbose mode */
	if (!VERBOSE) {
		return 0;
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	return 1;
}

void linxcfg_usage(int indent, const char *fmt, ...)
{
	int i;
	va_list ap;

	/* lame indent */
	for (i = 0; i < indent; ++i) {
		printf(" ");
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void *Malloc(size_t s)
{
	void *ret;

	if ((ret = malloc(s)) == NULL) {
		perror("malloc");
		exit(1);
	}

	return ret;
}

void show_help(const char *cm_name)
{
	int i = 0;

	_usage(0,
	       "Usage: linxcfg [OPTIONS] <command> [COMMAND PARAMETERS]\n\n");
	_usage(4, "OPTIONS:\n");
	_usage(8, "-h      Shows this help message and exits.\n");
	_usage(8,
	       "-t <cm> Use the given <cm> for <command> "
	       "(default is 'eth')\n");
	_usage(8, "-v      Sets verbose mode on.\n\n");
	_usage(4, "FEATURES:\n");
	_usage(8,
	       "--conn-feature, --cf, -c <f[=v]>  "
	       "Adds a connection feature.\n");
	_usage(8,
	       "--link-feature, --lf, -l <f[=v]>  " "Adds a link feature.\n");
	_usage(8, "Where f is a feature and v its value (optional),\n");
	_usage(8, "depending on the CM and connection layer versions.\n\n");
	_usage(4, "COMMANDS:\n");
	_usage(8,
	       "create [CM PARAMETERS]  Creates a link using the "
	       "desired CM.\n");
	_usage(8, "destroy <link>          Destroys the given link.\n");
	_usage(8, "help [<cm>]             Provides help about cm.\n\n");

	if (cm_name) {
		/* find out the position of the desired cm */
		while (cm_handler_list[i] != NULL) {
			if (!strncmp(cm_handler_list[i]->name,
				     cm_name, strlen(cm_name))) {
				break;
			}
			i++;
		}

		if (cm_handler_list[i] != NULL) {
			_usage(4, "CM PARAMETERS and OPTIONS for '%s':\n",
			       cm_name);
			_usage(8, "%s (%s)\n",
			       cm_handler_list[i]->description,
			       cm_handler_list[i]->name);
			if (cm_handler_list[i]->help != NULL) {
				cm_handler_list[i]->help(12);
			}
			return;
		}
	}

	_usage(4, "AVAILABLE CM TYPES:\n");
	for (i = 0; cm_handler_list[i] != NULL; i++) {
		_usage(8,
		       "%s\t%s\n",
		       cm_handler_list[i]->name,
		       cm_handler_list[i]->description);
	}
}

int get_command(const char *command)
{
	if (command == NULL)
		return CMD_UNKNOWN;

	if (strncmp(command, "create", 6) == 0 && command[6] == '\0') {
		return CMD_CREATE;
	} else if (strncmp(command, "destroy", 7) == 0 && command[7] == '\0') {
		return CMD_DESTROY;
	} else if (strncmp(command, "help", 4) == 0 && command[4] == '\0') {
		return CMD_HELP;
	}

	return CMD_UNKNOWN;
}

int get_all_longoptions(struct option **ops)
{
	char **list = NULL;
	int x;
	int total = TOTAL_MAIN_OPTIONS;
	struct option *new;

	*ops = Malloc(sizeof(struct option) * TOTAL_MAIN_OPTIONS);
	memcpy(*ops, main_options, sizeof(struct option) * TOTAL_MAIN_OPTIONS);

	for (x = 0; cm_handler_list[x] != NULL; x++) {
		int i;
		int count = config_get_option_list(cm_handler_list[x]->t,
						   &list,
						   0);

		if (count <= 0) {
			fprintf(stderr, "%s didn't return a list\n",
				cm_handler_list[x]->name);
			exit(1);
		}
		new = realloc(*ops, sizeof(struct option) * (count + total));
		if (new == NULL) {
			perror("realloc");
			exit(1);
		}
		for (i = 0; i < count; i++) {
			new[total + i].name = list[i];
			new[total + i].has_arg = 1;
			new[total + i].flag = NULL;
			new[total + i].val = 0;
		}
		free(list);	/* notice we don't free the strings,
				 * they are still referenced in ops
				 */
		*ops = new;
		total += count;
	}
	new = realloc(*ops, sizeof(struct option) * (total + 1));
	if (new == NULL) {
		perror("realloc");
		exit(1);
	}
	new[total].name = NULL;
	new[total].has_arg = 0;
	new[total].flag = NULL;
	new[total].val = 0;

	return total;
}

void add_feature(char **str, char *arg)
{
	char *tmp;

	if (arg == NULL || strlen(arg) == 0) {
		fprintf(stderr, "Error: No feature given.\n");
		return;
	}

	/* allow to have --link-feature blah=bleg or --lf blah:bleh */
	if ((tmp = strchr(arg, '=')) != NULL) {
		*tmp = ':';
	}

	if (*str != NULL) {
		tmp = Malloc(strlen(*str) + strlen(arg) + 2);
		sprintf(tmp, "%s,%s", *str, arg);
		free(*str);
	} else {
		tmp = Malloc(strlen(arg) + 1);
		strcpy(tmp, arg);
	}
	*str = tmp;
}

char *get_link_feature_string(void)
{
	return link_fstr;
}

char *get_connection_feature_string(void)
{
	return conn_fstr;
}

int main(int argc, char **argv)
{
	int x = 0, i, opt, ind;
	struct option_value *opval;
	linxcfg_cm_handler *cmh;
	char *cm_name = NULL;

	struct option *lops;

	x = get_all_longoptions(&lops);
	if (x <= 0) {
		fprintf(stderr, "Could not get options (%d)\n", x);
		exit(1);
	}

	opval = Malloc(sizeof(struct option_value) * (x + 1));
	i = 0;			/* keeps track on the number of options set */
	while (1) {
		opt = getopt_long(argc, argv, main_short_options, lops, &ind);
		if (opt == -1)
			break;
		switch (opt) {
		case 0:
			/* --option=value kind of option */
			opval[i].name = Malloc(strlen(lops[ind].name) + 1);
			strcpy(opval[i].name, lops[ind].name);
			if (optarg) {
				opval[i].val = Malloc(sizeof(optarg + 1));
				strcpy(opval[i].val, optarg);
			} else {
				opval[i].val = NULL;
			}
			i++;
			break;
		case 'c':
			/* connection feature */
			add_feature(&conn_fstr, optarg);
			break;
		case 'l':
			/* link feature */
			add_feature(&link_fstr, optarg);
			break;
		case 't':
			/* specifies the type of CM */
			cm_name = Malloc(strlen(optarg) + 1);
			strcpy(cm_name, optarg);
			break;
		case 'h':
			/* help */
			DO_HELP = 1;
			break;
		case 'v':
			/* verbose */
			VERBOSE = 1;
			break;
		case '?':
			printf("unknown option code: %d\n", opt);
			show_help(NULL);
			exit(1);
			break;
		default:
			printf("?? opt code 0%o ??\n", opt);
			show_help(NULL);
			exit(1);
		}
	}
	opval[i].name = NULL;

	if (DO_HELP) {
		if (cm_name == NULL && optind < argc)
			cm_name = argv[optind];
		show_help(cm_name);
		exit(0);
	}

	if (optind >= argc) {
		fprintf(stderr, "Too few arguments\n");
		show_help(cm_name);
		exit(1);
	}

	/* if none given, set default <cm> */
	if (cm_name == NULL) {
		/* it could be the 'help' command */
		if (get_command(argv[optind]) == CMD_HELP) {
			optind++;
			if (optind < argc)
				cm_name = argv[optind];
			show_help(cm_name);
			exit(0);
		}
		_verbose("Using " DEFAULT_CM " as default CM.\n");
		cm_name = (char *)Malloc(strlen(DEFAULT_CM) + 1);
		strcpy(cm_name, DEFAULT_CM);
	}

	if (cm_name == NULL) {
		fprintf(stderr, "No default CM found!\n");
		show_help(NULL);
		exit(1);
	}

	x = 0;
	for (x = 0; cm_handler_list[x] != NULL; x++) {
		cmh = cm_handler_list[x];
		if (cmh->name == NULL)
			continue;
		if (cmh->name != NULL &&
		    cm_name != NULL &&
		    strncmp(cm_name, cmh->name, strlen(cmh->name)) == 0 &&
		    cm_name[strlen(cmh->name)] == '\0') {
			_verbose("--- Selected CM is %s\n", cmh->name, opval);
			/* set values */
			for (i = 0; opval[i].name != NULL; i++) {
				if (config_set_value(cmh->t,
						     opval[i].name,
						     opval[i].val)) {
					fprintf(stderr,
						"Wrong value (%s) for %s\n",
						opval[i].val, opval[i].name);
					exit(1);
				}
			}
			i = optind ? optind : 1;
			config_parse_noops(cmh->t, argc - i, &argv[i]);
			return (cmh->init(argc - i, &argv[i]));
		}
	}

	fprintf(stderr, "No such CM: %s\n", cm_name);
	show_help(NULL);

	return 0;
}
