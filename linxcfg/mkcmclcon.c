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
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linxcfg.h>

#include "db_utils.h"
#include "cmcl_utils.h"

#define STR(s) #s
#define STRSTR(s) STR(s)

#define DEF_CON_TMO 300

struct option long_opts[] = {
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {"con_tmo", 1, NULL, (int)'t'},
        {"connection", 1, NULL, (int)'c'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mkcmclcon [OPTIONS] <connection>\n"
"Create a CMCL connection.\n"
"OPTIONS:\n"
"    -h, --help\n"
"        Print this text.\n"
"    -c, --connection\n"
"        connection to use for the cmcl connection.\n"
"    -s, --silent\n"
"        Only error messages are printed to stdout.\n"
"    -t, --con_tmo\n"
"        Time-out value in milli-sec for the alive packet.\n"
"        Default is " STRSTR(DEF_CON_TMO) " millisec.\n"
"Example:\n"
"    mkcmclcon -c ethcm/conn_b node_b\n";

static uint32_t get_u32(const char *opt, const char *arg)
{        
        char *end;
        uint32_t u32;

        u32 = (uint32_t)strtoul(arg, &end, 0);
        if (*end != '\0') {
                printf("mkshmcon: error in %s\n"
                       "Try 'mkshmcon --help' for more information\n",
                       opt);
                exit(1);
        }
        return u32;
}

int main(int argc, char *argv[])
{
        int c, status, silent;
        char *s;
        union linx_con_arg con;

        memset(&con.cmcl, 0, sizeof(con.cmcl));
        con.cmcl.con_tmo = DEF_CON_TMO; 
        silent = 0;

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "hst:c:", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
		case 'c':
			con.cmcl.con_name = optarg;
			break;
                case 's':
                        silent = 1;
                        break;
                case 't':
                        con.cmcl.con_tmo = get_u32("--con_tmo", optarg);
                        break;
                case '?':
                        return 1;
                }
        }
        if (argv[optind] == NULL) {
                printf("mkcmclcon: connection name missing\n");
                return 1;
        }

        con.cmcl.name = argv[optind];

        s = NULL;
        status = linx_create_connection(LINX_CON_CMCL, &con, &s);
        if (status != 0) {
                printf("mkcmclcon: couldn't create connection '%s': %s\n",
                       con.cmcl.name, strerror(status));
                return 1;
        }
        
        if (!silent)
                printf("mkcmclcon: created connection '%s'.\n"
                       "Now use 'mklink -c %s ...' to create a link.\n",
                       s, s);
        free(s);
        return 0;
}
