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
 * File: linx_cfg_eth.c - This is the LINX ethernet configuration command
 *
 * Mandatory options:
 * create <mac address> <device name> <link name>
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
#include "ethcm_utils.h"

#define _usage   linxcfg_usage
#define _verbose linxcfg_verbose

#define POS_COMMAND 0
#define POS_MAC     1
#define POS_IFACE   2
#define POS_LNAME   3
#define POS_OPTIONS 4
#define POS_DESTROY_LNAME 1

char *eth_usage_str =
"create <mac address> <interface> <link> [OPTIONS]\n"
"    <mac address> Specify the remote address to connect to.\n"
"                  Ex.: 0a:1b:2c:3d:4d:5e\n"
"    <interface>   Specify the Ethernet interface to use. Ex.: eth0\n"
"    <link>        Name of the link.\n"
"                  This will be the name used in:\n"
"                  /proc/net/linx/cm/eth/<link>\n"
"    OPTIONS for 'create':\n"
"        --window_size=<size>\n"
"            The send and receive window_size may need to be \n"
"            modified to adapt linx to really slow or really fast\n"
"            ethernet performance, the default of 128 messages\n"
"            should be sufficient in most configurations. The\n"
"            window size shall always be of a power of 2\n"
"            Size 0 means default window size\n"
"        --defer_queue_size=<size>\n"
"            The defer queue is used on the sender side When the\n"
"            send window is full, every message sent when the send\n"
"            window is full is stored in the defer queue until the\n"
"            send window has room for more messages. The defer\n"
"            queue size specifies the maximum number of messages\n"
"            that can be stored in the defer queue before the link\n"
"            is disconnected due to lack or resources. The default\n"
"            value of 2048 should be sufficient in most systems.\n"
"            Size 0 means default defer queue size\n"
"        --conn_tmo=<tmo>\n"
"            The connect timeout specifies the time, in milliseconds,\n"
"            to wait until a connection attempt fails and a new\n"
"            attempt is made. Once connected, it is used as a \n"
"            supervision time-out, i.e. every conn_tmo/3 milliseconds,\n"
"            LINX checks if any packets from the peer has been\n"
"            received. LINX disconnects the connection after four\n"
"            consequtive conn_tmo/3 timeout periods without any\n"
"            packets from the peer. Tmo 0 means to use the default\n"
"            timeout (1000ms).\n"
"        --attributes=<s>\n"
"            The attribute option gives the possibility to assign\n"
"            an arbitrary string to the link when it is created.\n"
"            This string is included in the new_link signal, which\n"
"            is sent to all link supervisors.\n"
"        --coreid=<id>\n"
"            The coreid is used in a multicore environment\n"
"            to configure the destination coreid.\n"
"    Examples:\n"
"        linxcfg -t eth create 01:23:a4:4f:b3:ac eth0 link_A\n"
"        linxcfg -t eth destroy link_A [link_B [...]]\n";

static struct cfg_template eth_template[] = {
	CFG_PARAM_ULONG("window_size", NULL),
	CFG_PARAM_ULONG("defer_queue_size", NULL),
	CFG_PARAM_ULONG("send_tmo", NULL),
	CFG_PARAM_ULONG("nack_tmo", NULL),
	CFG_PARAM_ULONG("conn_tmo", NULL),
	CFG_PARAM_ULONG("live_tmo", NULL),
	CFG_PARAM_STRING("attributes", NULL),
	CFG_PARAM_INT("coreid", NULL),
	CFG_PARAM_LAST
};

int eth_main(int argc, char **argv);
void eth_usage(int indent);

linxcfg_cm_handler eth_cm_handler_obj = {
	.name = "eth",
	.init = eth_main,
	.help = eth_usage,
	.t = eth_template,
	.description = "Linx Ethernet CM",
};

void eth_usage(int indent)
{
        _usage(indent, eth_usage_str);
}

static int option_supported(int ver, const char *opt)
{
        int major, minor, patch;

        (void)opt; /* Not used at the moment */

        major = (ver >> 24) & 0xff;
        minor = (ver >> 8) & 0xffff;
        patch = ver & 0xff;

        if (major > 2)
                return 0; /* No support */
        if (major == 2 && minor > 1)
                return 0; /* No support */
        
        return 1;
}

static int mkethlink(char **argv)
{
        union linx_con_arg con;
        struct linx_link_arg lnk;
        union cfg_value tmp;
        char *con_name, *s, version[14];
        int status, ver;

        con_name = mk_db_key("%s_%s", ETHCONN_PREFIX, argv[POS_LNAME]);
        if (con_name == NULL)
                return 1;

        ver = linx_get_version(version);
        if (ver == -1) {
                printf("WARNING: failed to retrieve LINX version\n");
                ver = 0;
                strcpy(version, "unknown");
        }

        memset(&con.eth, 0, sizeof(con.eth));
        memset(&lnk, 0, sizeof(lnk));

        con.eth.name = con_name;
        con.eth.ethif = argv[POS_IFACE];
        con.eth.mac = argv[POS_MAC];
        con.eth.features = "";
        con.eth.coreid = -1;
	cfg_get_value(eth_template, "window_size", &tmp);
        if (tmp.ul != 0)
                con.eth.window_size = tmp.ul;
        cfg_get_value(eth_template, "defer_queue_size", &tmp);
        if (tmp.ul != 0)
                con.eth.defer_queue_size = tmp.ul;
	cfg_get_value(eth_template, "send_tmo", &tmp);
        if (tmp.ul != 0) {
                con.eth.send_tmo = tmp.ul;
                if (!option_supported(ver, "--send_tmo"))
                        printf("WARNING! --send_tmo is not supported in LINX "
                               "%s. Option is ignored.\n", version);                
        }
	cfg_get_value(eth_template, "nack_tmo",& tmp);
        if (tmp.ul != 0) {
                con.eth.nack_tmo = tmp.ul;
                if (!option_supported(ver, "--nack_tmo"))
                        printf("WARNING! --nack_tmo is not supported in LINX "
                               "%s. Option is ignored.\n", version);                
        }
	cfg_get_value(eth_template, "live_tmo", &tmp);
        if (tmp.ul != 0) {
                con.eth.live_tmo = tmp.ul;
                if (!option_supported(ver, "--live_tmo"))
                        printf("WARNING! --live_tmo is not supported in LINX "
                               "%s. Option is ignored.\n", version);                
        }
	cfg_get_value(eth_template, "conn_tmo", &tmp);
        if (tmp.ul != 0)
                con.eth.conn_tmo = tmp.ul;
	if (config_option_was_set(eth_template,"coreid"))
	{
		cfg_get_value(eth_template, "coreid", &tmp);
		con.eth.coreid = (int)tmp.ul;
	}
        s = NULL;
        status = linx_create_connection(LINX_CON_ETH, &con, &s);
        if (status != 0) {
                free(con_name);
                return 1;
        }

        lnk.name = argv[POS_LNAME];
        lnk.connections = s;
        lnk.features = "";
        tmp.s = NULL;
        cfg_get_value(eth_template, "attributes", &tmp);
        lnk.attributes = (tmp.s != NULL) ? tmp.s : "";
        
        status = linx_create_link(&lnk);

        free(lnk.connections);
        free(con_name);
        return status;
}

int eth_main(int argc, char **argv)
{
	int i, retval = 0;

	switch (get_command(argv[POS_COMMAND])) {
	case CMD_CREATE:
		/* this requires at least 3 parameters */
		if (argc < POS_OPTIONS) {
			fprintf(stderr, "Error: too few arguments\n");
			show_help("eth");
			exit(1);
		} else if (argc > POS_OPTIONS) {
			fprintf(stderr, "Error: too many arguments\n");
			show_help("eth");
			exit(1);
		}
                if (mkethlink(argv) != 0) {
                        fprintf(stderr, "Error: couldn't create link\n");
                        exit(1);
                }
		break;
	case CMD_DESTROY:
		if (argc < 2) {
			fprintf(stderr, "Too few arguments.\n");
			show_help("eth");
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
		show_help("eth");
		return 0;
	default:
		printf("Unknown command %s\n", argv[POS_COMMAND]);
		return 1;
	}

	return retval;
}
