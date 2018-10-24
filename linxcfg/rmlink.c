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
 * File: rmlink.c - Command to remove Linx links.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <linxcfg.h>

struct option long_opts[] = {
        {"all", 0, NULL, (int)'a'},
        {"help", 0, NULL, (int)'h'},
        {"silent", 0, NULL, (int)'s'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"rmlink [OPTIONS] <link>...\n"
"Remove Linx links and optionally their connection(s).\n"
"OPTIONS:\n"
"    -a, --all\n"
"        Remove all, i.e. both link and its connection(s) are\n"
"        removed. This is the preferred method.\n"
"        If this option isn't used, the connection(s) must be\n"
"        separately removed, using e.g. rmethcon, etc.\n"
"    -h, --help\n"
"        Print this text.\n"
"    -s, --silent\n"
"        Silent mode.\n"
"Examples:\n"
"    Remove the Linx link LNK_A, which uses the Linx Ethernet\n"
"    connection ETHCON_A.\n"
"    alt1. rmlink -a LNK_A\n"
"    alt2. rmlink -s LNK_A && rmethcon ETHCON_A\n";

int main(int argc, char *argv[])
{
        char **lnk, *con, *s;
        int c, rm_all, silent, status;

        rm_all = 0;
        silent = 0;

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "has", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s", usage);
                        return 0;
                case 'a':
                        rm_all = 1;
                        break;
                case 's':
                        silent = 1;
                        break;
                case '?':
                        return 1;
                }
        }

        lnk = &argv[optind];

        if (*lnk == NULL) {
                printf("rmlink: missing operand\n"
                       "Try 'rmlink --help' for more information.\n");
                return 1;
        }

        for (; *lnk != NULL; lnk++) {
                if (rm_all) {
                        status = linx_remove_link_and_connections(*lnk);
                        if (status != 0) {
                                printf("rmlink: "
                                       "couldn't remove link '%s': %s\n",
                                       *lnk, strerror(status));
                                return 1;
                        }
                } else {
                        status = linx_remove_link(*lnk, &con);
                        if (status != 0) {
                                printf("rmlink: "
                                       "couldn't remove link '%s': %s\n",
                                       *lnk, strerror(status));
                                return 1;
                        }

                        if (!silent) {
                                printf("rmlink: now it's safe to remove "
                                       "the following connections:\n");
                                for (s = con; *s != '\0'; s += strlen(s) + 1) {
                                        printf("%s\n", s);
                                }
                        }
                        free(con);
                }
        }

        return 0;
}
