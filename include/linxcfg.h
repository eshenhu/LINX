/*
 * Copyright (c) 2006-2008, Enea Software AB
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

#ifndef _LINX_CFG_H
#define _LINX_CFG_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */	

#include <stdint.h>

/*
 * Howto add add links and connections:
 * ------------------------------------
 *
 * The following pseudo code tries to illustrate how to create/delete
 * a link that uses two Ethernet connections.
 *
 *     union linx_con_arg con;
 *     struct linx_link_arg lnk;
 *     char *tmp;
 *     int status;
 *     ...
 *     memset(&con.eth, 0, sizeof(con.eth));
 *     con.eth.name = "eth_con_1";
 *     con.eth.ethif = "eth1";
 *     ...
 *     tmp = NULL; // Important! Must be cleared before
 *                 // the 1:st linx_create_connection() call.
 *     status = linx_create_connection(LINX_CON_ETH, &con, &tmp);
 *     if (status != 0) {
 *             free(tmp);
 *             return status;
 *     }
 *     memset(&con.eth, 0, sizeof(con.eth));
 *     con.eth.name = "eth_con_2";
 *     ...
 *     status = linx_create_connection(LINX_CON_ETH, &con, &tmp);
 *     if (status != 0) {
 *             free(tmp);
 *             return status;
 *     }
 *     
 *     memset(&lnk, 0, sizeof(lnk));
 *     lnk.name = "my_link";
 *     lnk.connections = tmp; // Built by linx_create_connection() calls.
 *     ...
 *     status = linx_create_link(&lnk);
 *     free(tmp);
 *     return status;
 *
 * Howto remove links and connections:
 * -----------------------------------
 *
 * The simplest way to remove a link and its connections is to call
 * linx_remove_link_and_connections("my_link").
 *
 * It is also possible to separately remove links and its connections.
 * First call linx_remove_link("my_link", &con_names), this functions
 * returns the connection names used by the link. Then go through
 * the list of connections and remove them with linx_remove_connection.
 *
 *     linx_remove_link("my_link", &con_names);
 *     for (s = con_names; *s != '\0'; s += strlen(s) + 1)
 *             linx_remove_connection(s);
 *     free(con_names);
 *
 * Howto add support for a new connection type:
 * --------------------------------------------
 *
 * This is more or less a copy-paste exercise, for example use Ethernet
 * implementation as a template.
 *
 * 1. Define a new struct linx_con_arg_<x>, which contains the parameters
 *    that a user should be able to set (char *name is manadtory and must be
 *    the first member).
 *    Add the new struct to the union linx_con_arg.
 *    Define a LINX_CON_<x> macro.
 *
 * 2. Add support for <x> in linx_create_connection().
 *
 * 3. Implement a function that takes the struct linx_con_arg_<x> as input
 *    and returns <x>'s ioctl struct, see mk_ethcm_db_ioctl().
 */

#define LINX_CON_ETH 1
struct linx_con_arg_eth {
        char *name;
        char *ethif;
        char *mac;
        char *features;
        uint32_t mtu;
        uint32_t window_size;
        uint32_t defer_queue_size;
        uint32_t send_tmo;
        uint32_t nack_tmo;
        uint32_t conn_tmo;
        uint32_t live_tmo;
        int coreid;
};

#define LINX_CON_TCP 2
struct linx_con_arg_tcp {
        char *name;
        char *ipaddr;
	char *ipv6addr;
        char *features;
        uint32_t live_tmo;
        uint32_t use_nagle;
};

#define LINX_CON_SHM 3
struct linx_con_arg_shm {
        char *name;
        uint32_t con_tmo;
        uint32_t mtu;
        uint32_t mru;
        uint32_t mbox;
        uint32_t tx_nslot;
        uint32_t rx_nslot;
};

#define LINX_CON_RIO 4
struct linx_con_arg_rio {
        char *name;
        char *rioif;
        uint16_t port;
        uint16_t id;
        uint16_t my_port;
        uint16_t mtu;
	uint8_t  mbox;
	uint8_t  hb;
};

#define LINX_CON_CMCL 5
struct linx_con_arg_cmcl {
        char *name;
	char *con_name;
	uint32_t con_tmo;
};

union linx_con_arg {
        char *name;
        struct linx_con_arg_eth eth;
        struct linx_con_arg_tcp tcp;
        struct linx_con_arg_shm shm;
        struct linx_con_arg_rio rio;
	struct linx_con_arg_cmcl cmcl;
};

struct linx_link_arg {
        char *name;
        char *features;
        char *attributes;
        /*
         * String table, which holds the connection names,
         * e.g. connections -> 'ethcm/con_A\0ethcm/con_B\0\0'
         * An extra '\0' is added at the end to indicate
         * 'no-more-connection-names'.
         */
        char *connections;
};

extern int
linx_create_connection(int ctype, union linx_con_arg *arg, char **con_names);

extern int
linx_create_link(struct linx_link_arg *arg);

extern int
linx_remove_link(const char *link_name, char **con_names);

extern int
linx_remove_connection(const char *con_names);

extern int
linx_remove_link_and_connections(const char *link_name);

/* *INDENT-OFF* */	
#ifdef __cplusplus
}				/* extern "C" */
#endif
/* *INDENT-ON* */

#endif
