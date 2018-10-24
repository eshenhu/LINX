/*
 * Copyright (c) 2006-2011, Enea Software AB
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
 * File: mktcpcon.c - Command to make a Linx TCP connection.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linxcfg.h>

#include "db_utils.h"
#include "tcpcm_utils.h"

struct option long_opts[] = {
        {"ipaddr", 1, NULL, (int)'i'},
        {"ipv6addr", 1, NULL, (int)'I'},
        {"live_tmo", 1, NULL, (int)'t'},
        {"use_nagle", 1, NULL, (int)'n'},
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mktcpcon [OPTIONS] <connection>\n"
"Create a Linx TCP/IP connection.\n"
"OPTIONS:\n"
"    -h, --help\n"
"        Print this text.\n"
"    -i, --ipaddr=<IP address>\n"
"        The IP address to connect to, e.g. 192.168.0.12\n"
"    -I, --ipv6addr=<IPv6 address>%<iface>\n"
"        The IPv6 address to connect to, e.g. fe80::218:8bff:fe1e:2eef%eth0\n"
"    -t, --live_tmo=<ms>\n"
"        The live_tmo parameter is the time in milliseconds\n"
"        between every heartbeat that is used to detect if\n"
"        the connection has gone down.\n"
"        Default is 1000 ms.\n"
"    -n, --use_nagle=<bool>\n"
"        Set to 1 if nagle algorithm shall be used\n"
"        on the socket for the connection.\n"
"        Default is off.\n"
"    -s, --silent\n"
"        Silent mode\n"
"Example:\n"
"    mktcpcon --ipaddr=192.168.0.12 tcpcon_A\n"
"    mktcpcon --ipv6addr=x:x:x:x:x:x:x:x%eth1 tcpcon_A\n"
"    mktcpcon -i 192.168.0.12 tcpcon_A\n"
"    mktcpcon -I x::x.x.x.x.x%eth0 tcpcon_A\n";

int main(int argc, char *argv[])
{
        int c, status, silent;
        char *s;
        union linx_con_arg con;

        memset(&con.tcp, 0, sizeof(con.tcp));
        silent = 0;

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "hI:i:t:n:s", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
                case 'i':
                        con.tcp.ipaddr = optarg;
                        break;
                case 'I':
                        con.tcp.ipv6addr = optarg;
                        break;
                case 't':
                        con.tcp.live_tmo = (uint32_t)strtoul(optarg, &s, 0);
                        if (*s != '\0') {
                                printf("mktcpcon: error in -t, --live_tmo\n"
                                       "Try 'mktcpcon --help' for more information\n");
                                return 1;
                        }
                        break;
                case 'n':
                        con.tcp.use_nagle = (uint32_t)strtoul(optarg, &s, 0);
                        if (*s != '\0') {
                                printf("mktcpcon: error in -n, --use_nagle\n"
                                       "Try 'mktcpcon --help' for more information\n");
                                return 1;
                        }
                        break;
                case 's':
                        silent = 1;
                        break;
                case '?':
                        return 1;
                }
        }
        con.tcp.name = argv[optind];
        con.tcp.features = "";

        if (con.tcp.ipaddr == NULL && con.tcp.ipv6addr == NULL) {
                printf("mktcpcon: -i, --ipaddr or -I, --ipv6addr missing\n");
                return 1;
        }
        if (con.tcp.name == NULL) {
                printf("mktcpcon: connection name missing\n");
                return 1;
        }

        s = NULL;
        status = linx_create_connection(LINX_CON_TCP, &con, &s);
        if (status != 0) {
                printf("mktcpcon: couldn't create connection '%s': %s\n",
                       con.tcp.name, strerror(status));
                return 1;
        }
        
        if (!silent)
                printf("mktcpcon: created connection '%s'.\n"
                       "Now use 'mklink -c %s ...' to create a link.\n",
                       s, s);
        free(s);
        return 0;
}
