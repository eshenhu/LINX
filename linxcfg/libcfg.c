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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <ethcm_db_ioctl.h>
#include <riocm_db_ioctl.h>
#include <shmcm_db_ioctl.h>
#include <tcpcm_db_ioctl.h>
#include <cmcl_db_ioctl.h>
#include <rlnh_db_ioctl.h>
#include <linxcfg.h>

#include "db_utils.h"
#include "ethcm_utils.h"
#include "riocm_utils.h"
#include "rlnh_utils.h"
#include "shmcm_utils.h"
#include "tcpcm_utils.h"
#include "cmcl_utils.h"

#define foreach_db_string(s, strings) \
        for ((s) = (strings); *(s) != '\0'; (s) += strlen(s) + 1)

static size_t con_strlen(char *s)
{
        size_t len, n;

        if (s == NULL)
                return 0;

        /*
         * E.g. s = ethcm/a\0ethcm/b\0\0 should result in len = 16.
         */
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

int connection_in_use(const char *con_name)
{
        char *items, *key, *lnk_name;
        struct db_var *v;
        int status, n;

        /*
         * Get a list of all links...
         */
        status = db_list(DB_KEY_RLNH, DB_LIST_ITEMS, &items);
        if (status != 0)
                return status;

        /*
         * Go through all links and check if anyone uses the connections. This
         * check and the delete is not atomic, so there is a risk that remove
         * a connection before the link that uses the connection is removed, but
         * good enough as long as make/remove is not made from different
         * processes/threads.
         */
        foreach_db_string(lnk_name, items) {
                key = mk_db_key(DB_KEY_RLNH "/%s/con_name", lnk_name);
                if (key == NULL) {
                        status = ENOMEM;
                        goto out;
                }

                status = db_get(key, 2048, &v); /* 2K should be enough... */
                free(key);
                if (status != 0)
                        goto out;

                key = (char *)v->buf;
                for (n = 0; n < (int)v->nobj; n++) {
                        if (strcmp(con_name, key) == 0) {
                                status = EBUSY;
                                free(v);
                                goto out;
                        }
                        key += strlen(key);
                }
                free(v);
        }

	/*
	 * Need to go through cmcl connections too.
	 */
        status = db_list(DB_KEY_CMCL, DB_LIST_ITEMS, &items);
        if (status != 0) /* no cmcl keys, cmcl not present. continue */
                goto done;
        foreach_db_string(lnk_name, items) {
                key = mk_db_key(DB_KEY_CMCL "/%s/dc_name", lnk_name);
                if (key == NULL) {
                        status = ENOMEM;
                        goto out;
                }

                status = db_get(key, 2048, &v); /* 2K should be enough... */
                free(key);
                if (status != 0)
                        goto out;

                key = (char *)v->buf;
                for (n = 0; n < (int)v->nobj; n++) {
                        if (strcmp(con_name, key) == 0) {
                                status = EBUSY;
                                free(v);
                                goto out;
                        }
                        key += strlen(key);
                }
                free(v);
        }
  done:
        status = 0;
  out:
        free(items);
        return status;
}

/*
 * Create a connection.
 *
 * Note: The con_names parameter is used to build a list of connections
 *       that should be passed in the linx_create_link call.
 *
 * Example: Create a link that uses two ETH connections.
 *
 *          struct linx_con_arg_eth eth_1, eth_2;
 *          struct linx_link_arg lnk;
 *          char *con_names = NULL;
 *          ...
 *          linx_create_connection(LINX_CON_ETH, &eth_1, &con_names);
 *          linx_create_connection(LINX_CON_ETH, &eth_2, &con_names);
 *          lnk.connections = con_names;
 *          linx_create_link(&lnk);
 *          free(con_names);
 *          ...
 */
int linx_create_connection(int ctype, union linx_con_arg *arg, char **con_names)
{
        char *key, *db_key_cm, *s;
        void *p;
        size_t sizeof_p;
        int status;

        switch (ctype) {
        case LINX_CON_ETH:
                db_key_cm = DB_KEY_ETHCM;
                status = mk_ethcm_ioctl_create(&arg->eth, &p, &sizeof_p);
                break;
        case LINX_CON_RIO:
                db_key_cm = DB_KEY_RIOCM;
                status = mk_riocm_ioctl_create(&arg->rio, &p, &sizeof_p);
                break;
        case LINX_CON_TCP:
                db_key_cm = DB_KEY_TCPCM;
                status = mk_tcpcm_ioctl_create(&arg->tcp, &p, &sizeof_p);
                break;
        case LINX_CON_SHM:
                db_key_cm = DB_KEY_SHMCM;
                status = mk_shmcm_ioctl_create(&arg->shm, &p, &sizeof_p);
                break;
        case LINX_CON_CMCL:
                db_key_cm = DB_KEY_CMCL;
		status = connection_in_use(arg->cmcl.con_name);
		if (status != 0)
			return EACCES;
                status = mk_cmcl_ioctl_create(&arg->cmcl, &p, &sizeof_p);
                break;
        default:
                db_key_cm = "";
                status = EINVAL;
                break;
        }
        if (status != 0)
                return status;

        key = mk_db_key("%s/%s", db_key_cm, arg->name);
        if (key == NULL) {
		free(p);
                return ENOMEM;
	}

        status = db_create(key, p, sizeof_p);
        if (status != 0) {
		free(p);
                free(key);
                return status;
        }

        free(p); 

        s = con_strcat(*con_names, key);
        if (s == NULL) {
		db_delete(key, NULL, 0);
                free(key);
                return ENOMEM;
        }

        free(key); 
        
        *con_names = s;

        return 0;
}

/*
 * Create a link.
 */
int linx_create_link(struct linx_link_arg *arg)
{
        void *p;
        int status;
        char *key;
        size_t sizeof_p;
	char *con_name;
	
	con_name = arg->connections;
	do {
		status = connection_in_use(con_name);
		if(status)
			return EACCES;
		con_name = con_name + strlen(con_name) + 1;
	} while (con_name[0] != '\0');

        status = mk_rlnh_ioctl_create(arg, &p, &sizeof_p);
        if (status != 0)
                return status;

        key = mk_db_key(DB_KEY_RLNH "/%s", arg->name);
        if (key == NULL) {
		free(p);
                return ENOMEM;
	}
        status = db_create(key, p, sizeof_p);
        free(key);
        free(p); 
        return status;
}

/*
 * Remove a link.
 *
 * Note: The connections used by the link are returned in a string table,
 * which is terminated with an extra '\0',
 * e.g. con_names -> 'ethcm/con_A\0ethcm/con_B\0\0'.
 */
int linx_remove_link(const char *link_name, char **con_names)
{
        struct db_var *v;
        char *p, *tmp, *key;
        int n, status;

        key = mk_db_key(DB_KEY_RLNH "/%s/con_name", link_name);
        status = db_get(key, 512, &v); /* 512 is big enough... */
        free(key);
        if (status != 0)
                return status;

        key = mk_db_key(DB_KEY_RLNH "/%s", link_name);
        status = db_delete(key, NULL, 0);
        free(key);
        if (status != 0) {
                free(v);
                return status;
        }

        tmp = NULL;
        key = (char *)&v->buf[0];
        for (n = 0; n < v->nobj; n++) {
                p = con_strcat(tmp, key);
                if (p == NULL) {
                        free(tmp);
                        free(v);
                        return ENOMEM;
                }
                tmp = p;
                key += strlen(key) + 1;
        }
        *con_names = tmp;
        free(v);
        return 0;
}

/*
 * Remove a connection.
 *
 * Note: if the connection is used by a link or cmcl conn, the link/cmcl MUST BE
 *       removed first!
 */
int linx_remove_connection(const char *con_name)
{
	int status;

	status = connection_in_use(con_name);
	if (status == 0)
		status = db_delete(con_name, NULL, 0);

        return status;
}

/*
 * Remove a link and its connections.
 */
int linx_remove_link_and_connections(const char *link_name)
{
        char *con_names, *s;
        int status, tmp;

        status = linx_remove_link(link_name, &con_names);
        if (status != 0)
                return status;

        /*
         * Don't use linx_remove_connection() here, since it does
         * a lot of unnecessary stuff...
         */
        status = 0;
        for (s = con_names; *s != '\0'; s += strlen(s) + 1) {
                /*
                 * Try to delete as much as possible and report an error
                 * (the last one) once we are done...
                 */
                tmp = db_delete(s, NULL, 0);
                if (tmp != 0)
                        status = tmp;
        }

        free(con_names);
        return status;
}
