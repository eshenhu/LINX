/*
 * Copyright (c) 2006-2009, Enea Software AB
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
#include "shmcm_utils.h"

#define STR(s) #s
#define STRSTR(s) STR(s)

#define DEF_CON_TMO 1000
#define DEF_MTU 120
#define DEF_SLOTS 16
#define ILLEGAL_MBOX -1

struct option long_opts[] = {
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {"con_tmo", 1, NULL, (int)'t'},
        {"mtu", 1, NULL, (int)'m'},
        {"mbox", 1, NULL, (int)'b'},
        {"slots", 1, NULL, (int)'n'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mkshmcon [OPTIONS] <connection>\n"
"Create a Linx shared memory connection.\n"
"OPTIONS:\n"
"    -h, --help\n"
"        Print this text.\n"
"    -s, --silent\n"
"        Only error messages are printed to stdout.\n"
"    -t, --con_tmo\n"
"        Time-out value in milli-sec for the alive packet.\n"
"        Default is " STRSTR(DEF_CON_TMO) " millisec.\n"
"    -m, --mtu\n"
"        Maximum transfer unit (also used as MRU).\n"
"        Default is " STRSTR(DEF_MTU) " bytes.\n"
"    -b, --mbox\n"
"        Mailbox number, both sides of a connection must use\n"
"        the same number.\n"
"    -n, --slots\n"
"        Number of slots per mailbox.\n"
"        Default is " STRSTR(DEF_SLOTS) " slots.\n"
"Example:\n"
"    On CPU A: mkshmcon -b 1 cpu_b\n"
"    On CPU B: mkshmcon -b 1 cpu_a\n";

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
        int c, status, silent, mbox, slots;
        char *s;
        union linx_con_arg con;

        memset(&con.shm, 0, sizeof(con.shm));
        con.shm.con_tmo = DEF_CON_TMO; 
        con.shm.mtu = DEF_MTU;
        con.shm.mru = con.shm.mtu;
        silent = 0;
        mbox = ILLEGAL_MBOX;
        slots = DEF_SLOTS;

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "hst:m:b:n:", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
                case 's':
                        silent = 1;
                        break;
                case 't':
                        con.shm.con_tmo = get_u32("--con_tmo", optarg);
                        break;
                case 'b':
                        mbox = (int)get_u32("--mbox", optarg);
                        break;
                case 'm':
                        con.shm.mtu = get_u32("--mtu", optarg);
                        con.shm.mru = con.shm.mtu;
                        break;
                case 'n':
                        slots = (int)get_u32("--slots", optarg);
                        break;
                case '?':
                        return 1;
                }
        }
        if (argv[optind] == NULL) {
                printf("mkshmcon: connection name missing\n");
                return 1;
        }

        con.shm.name = argv[optind];
        con.shm.mbox = (uint32_t)mbox;
        con.shm.tx_nslot = (uint32_t)slots;
        con.shm.rx_nslot = (uint32_t)slots;

        s = NULL;
        status = linx_create_connection(LINX_CON_SHM, &con, &s);
        if (status != 0) {
                printf("mkshmcon: couldn't create connection '%s': %s\n",
                       con.shm.name, strerror(status));
                return 1;
        }
        
        if (!silent)
                printf("mkshmcon: created connection '%s'.\n"
                       "Now use 'mklink -c %s ...' to create a link.\n",
                       s, s);
        free(s);
        return 0;
}
