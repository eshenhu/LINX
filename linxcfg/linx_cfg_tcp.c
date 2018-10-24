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

/*
 * File: linx_cfg_tcp.c - This is the LINX tcp configuration command
 *
 * Mandatory options:
 * create <remote ip address> <connection name>
 * destroy <connection name>
 *
 * Extra options

 */
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linxcfg.h>
#include "db_utils.h"
#include "tcpcm_utils.h"
#include "linx_cfg.h"
#include "config.h"

#define _usage   linxcfg_usage
#define _verbose linxcfg_verbose

/* relative position of different expected arguments in the command line */
#define POS_COMMAND 0
#define POS_IP      1
#define POS_LNAME   2
#define POS_OPTIONS 3
#define POS_DESTROY_LNAME 1

static char *tcp_usage_str =
	"create <ip address> <link> [OPTIONS]\n"
	"    <ip address>  The IP address to connect to\n"
	"                  e.g.: 192.168.1.1\n"
	"    <link>        Name of the connection, as in\n"
	"                  /proc/net/linx/cm/tcp/<link>\n"
	"    OPTIONS:\n"
	"        --live_tmo=<size>\n"
	"            The live_tmo parameter is the\n"
	"            time in milliseconds between every\n"
	"            heartbeat that is used to detect if\n"
	"            the connection has gone down. The\n"
	"            default value is 1000 ms.\n"
	"        --use_nagle=<bool>\n"
	"            Set to 1 if nagle algorithm shall be used\n"
	"            on the socket for the connection.\n"
	"            Default is off.\n"
	"        --attributes=<s>\n"
	"            The attribute option gives the possibility\n"
	"            to assign an arbitrary string to the link\n"
	"            when it is created. This string is included\n"
	"            in the new_link signal, which is sent to\n"
	"            all link supervisors.\n\n"
	"     Example:\n"
	"            linxcfg -t tcp create 192.168.1.1 link_A\n"
	"            linxcfg -t tcp destroy link_A [link_B [...]]\n";

static struct cfg_template tcp_template[] = {
	CFG_PARAM_ULONG("live_tmo", NULL),
	CFG_PARAM_INT("use_nagle", NULL),
	CFG_PARAM_STRING("attributes", NULL),
	CFG_PARAM_LAST
};

int tcp_main(int, char **);
void tcp_usage(int);

linxcfg_cm_handler tcp_cm_handler_obj = {
	.name = "tcp",
	.description = "Linx TCP CM",
	.init = tcp_main,
	.help = tcp_usage,
	.t = tcp_template
};

void tcp_usage(int indent)
{
        _usage(indent, tcp_usage_str);
}

static void error_exit(void)
{
	show_help("tcp");
	exit(1);
}

static int mktcplink(char **argv)
{
        union linx_con_arg con;
        struct linx_link_arg lnk;
        union cfg_value tmp;
        char *con_name, *s;
        int status;

        con_name = mk_db_key("%s_%s", TCPCONN_PREFIX, argv[POS_LNAME]);
        if (con_name == NULL)
                return 1;

        memset(&con.tcp, 0, sizeof(con.tcp));
        memset(&lnk, 0, sizeof(lnk));

        con.tcp.name = con_name;
        con.tcp.ipaddr = argv[POS_IP];
        con.tcp.features = "";
	cfg_get_value(tcp_template, "use_nagle", &tmp);
        if (tmp.ul != 0)
                con.tcp.use_nagle = tmp.ul;
	cfg_get_value(tcp_template, "live_tmo", &tmp);

        s = NULL;
        status = linx_create_connection(LINX_CON_TCP, &con, &s);
        if (status != 0) {
                free(con_name);
                return 1;
        }

        lnk.name = argv[POS_LNAME];
        lnk.connections = s;
        lnk.features = "";
        tmp.s = NULL;
        cfg_get_value(tcp_template, "attributes", &tmp);
        lnk.attributes = (tmp.s != NULL) ? tmp.s : "";

        status = linx_create_link(&lnk);

        free(lnk.connections);
        free(con_name);
        return status;
}

int tcp_main(int argc, char **argv)
{
	int i, retval = 0;

	switch (get_command(argv[POS_COMMAND])) {
	case CMD_CREATE:
		/* requires at least 2 arguments */
		if (argc < POS_OPTIONS) {
			fprintf(stderr, "Too few arguments.\n");
			error_exit();
		}
                if (mktcplink(argv) != 0) {
                        fprintf(stderr, "Error: couldn't create link\n");
                        exit(1);
                }
		break;
	case CMD_DESTROY:
		if (argc < 2) {
			fprintf(stderr, "Too few arguments.\n");
			error_exit();
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
		show_help("tcp");
		exit(0);
	default:
		error_exit();
                break;
	}
	return retval;
}
