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
 * File: mkriocon.c - Command to make a Linx RapidIO connection.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linx.h>
#include <linxcfg.h>
#include "db_utils.h"
#include "riocm_utils.h"

#define OPT_MTU 263

struct option long_opts[] = {
        {"mbox", 1, NULL, (int)'m'},
        {"mtu", 1, NULL, (int)'M'},
        {"port", 1, NULL, (int)'p'},
        {"local-port", 1, NULL, (int)'l'},
        {"id", 1, NULL, (int)'I'},
        {"tmo", 1, NULL, (int)'t'},
        {"if", 1, NULL, (int)'i'},
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mkriocon [OPTIONS] <connection>\n"
"Create a Linx RapidIO connection\n"
"OPTIONS:\n"
"    -p, --port=<rio port>\n"
"        Specify the remote port to connect to,\n"
"        e.g. 1.\n"
"        Mandatory option.\n"
"\n"
"    -l, --local-port=<rio port>\n"
"        Specify the local port to connect from,\n"
"        e.g. 1.\n"
"        Mandatory option.\n"
"\n"
"    -M, --mtu=<rio mtu>\n"
"        Specify the mtu to be used. Default is fetched from the interface.\n"
"\n"
"    -m, --mbox=<rio mailbox>\n"
"        Specify the remote mailbox to connect to, e.g 0.\n"
"        Mandatory option.\n"
"\n"
"    -I, --id=<rio device id>\n"
"        Specify the remote device ID to connect to,\n"
"        e.g. 4.\n"
"        Mandatory option.\n"
"\n"
"    -t, --tmo=<interface>\n"
"        Specify the connection heartbeat timeout to use.\n"
"        The values is multiplied by 100 so a value of 5\n"
"        will yield a timeout of 500ms, which also is the\n"
"        default value in the CM\n"
"\n"
"    -i, --if=<interface>\n"
"        Specify the RapidIO interface to use, e.g. rio0.\n"
"        Mandatory option.\n"
"\n"
"Examples:\n"
"    mkriocon --port=1 --local-port=1 --mbox=2 --id=4 --if=rio0 riocon_A\n"
"    mkriocon -p 1 -l 1 -m 2 -I 4 -i rio0 riocon_A\n";

int main(int argc, char *argv[])
{
        int c, silent, status, ver;
	int port_not_set, local_port_not_set, mbox_not_set, id_not_set;
        char *s, version[14];
        union linx_con_arg con;

	port_not_set = 1;
	local_port_not_set = 1;
	mbox_not_set = 1;
	id_not_set = 1;
        memset(&con.rio, 0, sizeof(con.rio));
        silent = 0;
        ver = linx_get_version(version);
        if (ver == -1) {
                printf("WARNING: failed to retrieve LINX version\n");
                ver = 0;
                strcpy(version, "unknown");
        }

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "hl:M:m:I:i:p:t:s",
				long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
                case 's':
                        silent = 1;
                        break;
                case 'p':
			con.rio.port = (uint16_t)strtoul(optarg, &s, 0);
			port_not_set = 0;
                        break;
                case 'l':
			con.rio.my_port = (uint16_t)strtoul(optarg, &s, 0);
			local_port_not_set = 0;
                        break;
                case 'i':
                        con.rio.rioif = optarg;
                        break;
                case 'I':
                        con.rio.id = (uint16_t)strtoul(optarg, &s, 0);
			id_not_set = 0;
                        break;
                case 'm':
                        con.rio.mbox = (uint8_t)strtoul(optarg, &s, 0);
			mbox_not_set = 0;
                        break;
                case 'M':
                        con.rio.mtu = (uint16_t)strtoul(optarg, &s, 0);
                        break;
                case 't':
                        con.rio.hb = (uint8_t)strtoul(optarg, &s, 0);
                        break;
                case '?':
                        return 1;
                }
        }
        con.rio.name = argv[optind];

        if (con.rio.name == NULL) {
                printf("mkriocon: no connection specified\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }
        if (port_not_set) {
                printf("mkriocon: -p, --port is missing\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }
        if (local_port_not_set) {
                printf("mkriocon: -l, --local-port is missing\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }
        if (id_not_set) {
                printf("mkriocon: -I, --id is missing\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }
        if (mbox_not_set) {
                printf("mkriocon: -m, --mbox is missing\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }
        if (con.rio.rioif == NULL) {
                printf("mkriocon: -i, --if is missing\n"
                       "Try 'mkriocon --help' for more information\n");
                return 1;
        }

        s = NULL;
        status = linx_create_connection(LINX_CON_RIO, &con, &s);
        if (status != 0) {
                printf("mkriocon: couldn't create connection '%s': %s\n",
                       con.rio.name, strerror(status));
                return 1;
        }
        
        if (!silent)
                printf("mkriocon: created connection '%s'.\n"
                       "Now use 'mklink -c %s ...' to create a link.\n",
                       s, s);
        free(s);
        return 0;
}
