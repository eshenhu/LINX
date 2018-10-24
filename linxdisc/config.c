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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "linxdisc.h"

static char *get_conf_param(char *dest, char *from)
{
	uint8_t l = 0;
	char *s = NULL;

	/* align parameter */
	while (1) {
		if (*from == ' ' || *from == '"')
			from++;
		else
			break;
	}

	if (NULL == (s = strchr(from, ' ')))
		if (NULL == (s = strchr(from, '"')))
			return NULL;

	/* s points at end of parameter */
	l = (uint8_t) (s - from);

	strncpy(dest, from, l);

	dest[l] = '\0';

	return s;
}

static int get_conf_parameters(char *buf, struct conf_data *conf)
{
	uint8_t i = 0;
	char s = *buf;

	/* Align start of parameters */
	buf = strchr(buf, '"');
	/* Check that we have correct formatted parameters */
	if (NULL == buf)
		return 1;
	/* Bail out if parameter list is empty */
	if (buf[0] == '"' && buf[1] == '"')
		return 0;
	/* Check final '"' */
	if (NULL == strrchr(buf + 1, '"'))
		return 1;

	while (NULL != buf) {
		switch (s) {
		case 'I':
			buf = get_conf_param(conf->iface[i].name, buf);
			if (buf != NULL)
				conf->no_iface++;
			break;
		case 'L':
			buf = get_conf_param(conf->linx_net_name, buf);
			return 0;	/* if several linx_net_names specified,
					 * only use first */
			break;
		case 'N':
			buf = get_conf_param(conf->node_name, buf);
			return 0;	/* if several node_names specified,
					 * only use first */
			break;
		case 'A':
			buf = get_conf_param(conf->allow[i].name, buf);
			if (buf != NULL)
				conf->no_allow++;
			break;
		case 'D':
			buf = get_conf_param(conf->deny[i].name, buf);
			if (buf != NULL)
				conf->no_deny++;
			break;
		case 'P':
			buf = get_conf_param(conf->params[i].name_val, buf);
			if (buf != NULL)
				conf->no_param++;
			break;
		default:
			return 1;
		}
		if (MAX_CONF_PARAM == i++)
			break;
	}
	return 0;
}

static int parse_line(char *buf, struct conf_data *conf, int line)
{
	int ret = 0;

	switch (buf[0]) {
	case '#':
		err_dbg("Comment @ line %d\n", line);
		break;
	case 'I':
	case 'L':
	case 'N':
	case 'A':
	case 'D':
	case 'P':
		err_dbg("Processing line %d %c\n", line, buf[0]);
		ret = get_conf_parameters(buf, conf);
		break;
	default:
		err_dbg("Unknown / Empty line %d\n", line);
		break;
	}

	return ret;
}

struct conf_data *read_conf(const char *filename)
{
#define BUFLEN 2048
	FILE *file;
	char buf[BUFLEN];
	int line = 0;
	struct conf_data *conf;

	if ((file = fopen(filename, "r")) == NULL)
		err_sys("%s could not be opened\n", filename);

	memset(buf, 0, BUFLEN);

	conf = Malloc(sizeof(struct conf_data));
	memset(conf, 0, sizeof(struct conf_data));

	/* set parameters */
	while (fgets(buf, sizeof buf, file) != NULL)
		if (parse_line(buf, conf, ++line) != 0)
			err_quit("Error in config file @ %d\n", line);

	fclose(file);
	return conf;
#undef BUFLEN
}
