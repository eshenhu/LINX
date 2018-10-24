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
 * File: mkethcon.c - Command to make a Linx Ethernet connection.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linx.h>
#include <linxcfg.h>
#include "db_utils.h"
#include "ethcm_utils.h"

#define OPT_WINDOW_SIZE 256
#define OPT_DEFER_QUEUE_SIZE 257
#define OPT_SEND_TMO 258
#define OPT_NACK_TMO 259
#define OPT_CONN_TMO 260
#define OPT_LIVE_TMO 261
#define OPT_MTU 262
#define OPT_COREID 263

struct option long_opts[] = {
        {"mac", 1, NULL, (int)'m'},
        {"if", 1, NULL, (int)'i'},
        {"window_size", 1, NULL, OPT_WINDOW_SIZE},
        {"defer_queue_size", 1, NULL, OPT_DEFER_QUEUE_SIZE},
        {"send_tmo", 1, NULL, OPT_SEND_TMO},
        {"nack_tmo", 1, NULL, OPT_NACK_TMO},
        {"conn_tmo", 1, NULL, OPT_CONN_TMO},
        {"live_tmo", 1, NULL, OPT_LIVE_TMO},
        {"mtu", 1, NULL, OPT_MTU},
        {"coreid", 1, NULL, OPT_COREID},
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mkethcon [OPTIONS] <connection>\n"
"Create a Linx Ethernet connection\n"
"OPTIONS:\n"
"    -m, --mac=<mac address>\n"
"        Specify the remote address to connect to,\n"
"        e.g. 0a:1b:2c:3d:4d:5e.\n"
"        Mandatory option.\n"
"\n"
"    -i, --if=<interface>\n"
"        Specify the Ethernet interface to use, e.g. eth0.\n"
"        Mandatory option.\n"
"\n"
"    --mtu=<size>\n"
"        The MTU (Maximum Transmission Unit) specifies the size\n"
"        in bytes of the largets packet that the Ethernet protocol\n"
"        can pass onwards (this excludes the size of the Ethernet\n"
"        header). If not set the MTU is fetched from the interface.\n"
"        Typcially a MTU of 1500 bytes is used for Ethernet.\n"
"\n"
"    --window_size=<size>\n"
"        The send and receive window_size may need to be \n"
"        modified to adapt linx to really slow or really fast\n"
"        ethernet performance, the default of 128 messages\n"
"        should be sufficient in most configurations. The\n"
"        window size shall always be of a power of 2\n"
"        Size 0 means default window size\n"
"\n"
"    --defer_queue_size=<size>\n"
"        The defer queue is used on the sender side When the\n"
"        send window is full, every message sent when the send\n"
"        window is full is stored in the defer queue until the\n"
"        send window has room for more messages. The defer\n"
"        queue size specifies the maximum number of messages\n"
"        that can be stored in the defer queue before the link\n"
"        is disconnected due to lack or resources. The default\n"
"        value of 2048 should be sufficient in most systems.\n"
"        Size 0 means default defer queue size\n"
"\n"
"    --conn_tmo=<tmo>\n"
"        The connect timeout specifies the time, in milliseconds,\n"
"        to wait until a connection attempt fails and a new\n"
"        attempt is made. Once connected, it is used as a \n"
"        supervision time-out, i.e. every conn_tmo/3 milliseconds,\n"
"        LINX checks if any packets from the peer has been\n"
"        received. LINX disconnects the connection after four\n"
"        consequtive conn_tmo/3 timeout periods without any\n"
"        packets from the peer. Tmo 0 means to use the default\n"
"        timeout (1000ms).\n"
"\n"
"     --coreid=<id>\n"
"        The coreid is used in a multicore environment \n"
"        to configure the destination coreid.\n"
"\n"
"Examples:\n"
"    mkethcon --mac=01:23:a4:4f:b3:ac --if=eth0 ethcon_A\n"
"    mkethcon -m 01:23:a4:4f:b3:ac -i eth0 ethcon_A\n";

static uint32_t get_u32(const char *opt, const char *arg)
{        
        char *end;
        uint32_t u32;

        u32 = (uint32_t)strtoul(arg, &end, 0);
        if (*end != '\0') {
                printf("mkethcon: error in %s\n"
                       "Try 'mkethcon --help' for more information\n",
                       opt);
                exit(1);
        }
        return u32;
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

int main(int argc, char *argv[])
{
        int c, silent, status, ver;
        char *s, version[14];
        union linx_con_arg con;

        memset(&con.eth, 0, sizeof(con.eth));
        silent = 0;
        con.eth.coreid = -1;
        ver = linx_get_version(version);
        if (ver == -1) {
                printf("WARNING: failed to retrieve LINX version\n");
                ver = 0;
                strcpy(version, "unknown");
        }

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "hi:m:s", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
                case 's':
                        silent = 1;
                        break;
                case 'm':
                        con.eth.mac = optarg;
                        break;
                case 'i':
                        con.eth.ethif = optarg;
                        break;
                case OPT_MTU:
                        con.eth.mtu = get_u32("--mtu", optarg);
                        break;
                case OPT_WINDOW_SIZE:
                        con.eth.window_size = get_u32("--window_size", optarg);
                        if ((con.eth.window_size & (con.eth.window_size - 1)) != 0) {
                                printf("mkethcon: error in --window_size: "
                                       "Not power of 2\n"
                                       "Try 'mkethcon --help' for more information\n");
                                return 1;
                        }
                        break;
                case OPT_DEFER_QUEUE_SIZE:
                        con.eth.defer_queue_size = get_u32("--defer_queue_size", optarg);
                        break;
                case OPT_SEND_TMO:
                        con.eth.send_tmo = get_u32("--send_tmo", optarg);
                        if (!option_supported(ver, "--send_tmo")) {
                                printf("WARNING! --send_tmo is not supported in "
                                       "LINX %s. Option is ignored.\n", version);
                        }
                        break;
                case OPT_NACK_TMO:
                        con.eth.nack_tmo = get_u32("--nack_tmo", optarg);
                        if (!option_supported(ver, "--nack_tmo")) {
                                printf("WARNING! --nack_tmo is not supported in "
                                       "LINX %s. Option is ignored.\n", version);
                        }
                        break;
                case OPT_CONN_TMO:
                        con.eth.conn_tmo = get_u32("--conn_tmo", optarg);
                        break;
                case OPT_LIVE_TMO:
                        con.eth.live_tmo = get_u32("--live_tmo", optarg);
                        if (!option_supported(ver, "--live_tmo")) {
                                printf("WARNING! --live_tmo is not supported in "
                                       "LINX %s. Option is ignored.\n", version);
                        }
                        break;
                case OPT_COREID:
                       con.eth.coreid = get_u32("--coreid", optarg);
                       break;
                case '?':
                        return 1;
                }
        }
        con.eth.name = argv[optind];
        con.eth.features = "";

        if (con.eth.name == NULL) {
                printf("mkethcon: no connection specified\n"
                       "Try 'mkethcon --help' for more information\n");
                return 1;
        }
        if (con.eth.mac == NULL) {
                printf("mkethcon: -m, --mac is missing\n"
                       "Try 'mkethcon --help' for more information\n");
                return 1;
        }
        if (con.eth.ethif == NULL) {
                printf("mkethcon: -i, --if is missing\n"
                       "Try 'mkethcon --help' for more information\n");
                return 1;
        }

        s = NULL;
        status = linx_create_connection(LINX_CON_ETH, &con, &s);
        if (status != 0) {
                printf("mkethcon: couldn't create connection '%s': %s\n",
                       con.eth.name, strerror(status));
                return 1;
        }
        
        if (!silent)
                printf("mkethcon: created connection '%s'.\n"
                       "Now use 'mklink -c %s ...' to create a link.\n",
                       s, s);
        free(s);
        return 0;
}
