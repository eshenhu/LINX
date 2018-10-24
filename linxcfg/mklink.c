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
 * File: mklink.c - Command to make a Linx link.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <linxcfg.h>

#include "rlnh_utils.h"

struct option long_opts[] = {
        {"connection", 1, NULL, (int)'c'},
        {"attributes", 1, NULL, (int)'a'},
        {"help", 0, NULL, (int)'h'},
        {NULL, 0, NULL, 0}
};

static char *usage =
"mklink [OPTIONS] <link>\n"
"Create a Linx link and assign one or more connections to it.\n"
"OPTIONS:\n"
"    --attributes=<attributes>\n"
"        Specify a cookie that is returned unmodified in\n"
"        the new_link signal. The new_link signal is sent\n"
"        to link supervisor(s) when the link is available.\n"
"    --connection=<connection name>\n"
"        Specify the connection(s) that this link should use.\n"
"        This option can be repeated if a link should use more\n"
"        than one connection. Note that the connection(s) must\n"
"        be created before they can be assigned to a link.\n"
"        The connection name is made up of two parts, see example,\n"
"        the first part identifies the CM and the second part is\n"
"        the name that was used in the CM specific create command.\n"
"Examples:\n"
"    mkethcon --mac=01:23:a4:4f:b3:ac --if=eth0 ethcon_A\n"
"    mklink --connection=ethcm/ethcon_A link_A\n"
"    \n"
"    mkethcon --mac=01:23:a4:4f:b3:ac --if=eth0 ethcon_A\n"
"    mktcpcon tcpcon_A\n"
"    mklink -c ethcm/ethcon_A -c tcpcm/tcpcon_A link_A\n";

static size_t con_strlen(char *s)
{
        size_t len, n;

        if (s == NULL)
                return 0;

        /* E.g. s = ethcm/a\0ethcm/b\0\0 should result in len = 16. */
        for (len = 0; *s != '\0'; len += n, s += n)
                n = strlen(s) + 1;

        return len; /* Last '\0' is not included. */
}

static char *con_strcat(char *s1, const char *s2)
{
        size_t l1, l2;

        l1 = con_strlen(s1);
        l2 = strlen(s2) + 1;
        s1 = realloc(s1, l1 + l2 + 1);
        if (s1 != NULL) {
                memcpy(s1 + l1, s2, l2);
                *(s1 + l1 + l2) = '\0'; /* Extra '\0' at the end. */
        }
        return s1;
}

int main(int argc, char *argv[])
{
        struct linx_link_arg lnk;
        int c, status;
        char *a, *s, *t;

        a = NULL;
        s = NULL;

        for (c = 0; c != -1;) {
                c = getopt_long(argc, argv, "a:c:h", long_opts, NULL);
                switch (c) {
                case 'h':
                        printf("Usage: %s\n", usage);
                        return 0;
                case 'a':
                        a = optarg;
                        break;
                case 'c':
                        t = con_strcat(s, optarg);
                        if (t == NULL) {
                                free(s);
                                printf("mklink: out of memory\n");
                                return 1;
                        }
                        s = t;
                        break;
                case '?':
                        return 1;
                }
        }

        memset(&lnk, 0, sizeof(lnk));
        lnk.name = argv[optind];
        lnk.connections = s;
        lnk.attributes = a;
        lnk.features = "";

        if (lnk.attributes == NULL)
                lnk.attributes = "";
        if (lnk.connections == NULL) {
                printf("mklink: no connection(s) specified\n"
                       "Try 'mklink --help' for more information\n");
                return 1;
        }
        if (lnk.name == NULL) {
                printf("mklink: link is missing\n"
                       "Try 'mklink --help' for more information\n");
                free(lnk.connections);
                return 1;
        }

        status = linx_create_link(&lnk);
        if (status != 0) {
                printf("mklink: couldn't create link '%s': ", lnk.name);
                if (status == ENOENT)
                        printf("No such connection\n"
                               "Try 'mklink --help' for more information\n");
                else
                        printf("%s\n"
                               "Try 'mklink --help' for more information\n",
                               strerror(status));
                free(lnk.connections);
                return 1;
        }
        free(lnk.connections);

        return 0;
}
