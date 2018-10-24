/*
 * Copyright (c) 2009, Enea Software AB
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

/***********************************************************************
 * This small "OSE Gateway Command" tool example can be used to find
 * and test gateway servers on a network.
 *
 * Written by: Fredrik Bredberg, frbr@enea.se
 *
 ***********************************************************************
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#ifdef _WIN32
#include <winsock.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "ose_gw.h"

#define TRUE  1
#define FALSE 0

static const OSEGW_SIGSELECT any_sig[] = { 0 };

struct ClientState
{
   struct OSEGW   *chd;
   int             argc;
   char          **argv;
   char           *brc_addr;
   char           *server_url;
   char           *client_name;
   char           *auth_str;
   char           *hunt_path;
   OSEGW_OSUSER    user;
   int             list_servers;
   unsigned long   list_timeout;
   unsigned long   list_max;
   int             echo_test;
   unsigned long   echo_cnt;
   OSEGW_OSBUFSIZE echo_chunk;
   size_t          url_width;
   int             found_cnt;
};

union OSEGW_SIGNAL
{
   OSEGW_SIGSELECT sig_no;
};

static OSEGW_BOOLEAN
gw_err_hnd(void            *usr_hd,
	   struct OSEGW    *ose_gw,
	   OSEGW_OSERRCODE  ecode,
	   OSEGW_OSERRCODE  extra)
{
   printf("**ERROR** ecode: %#lx\n", ecode);
   printf("**ERROR** extra: %#lx\n", extra);
   exit(1);
   /*NOTREACHED*/
   return OSEGW_FALSE;
} /* gw_err_hnd */

static char *
gw_host_name(const char *gw_address)
{
   char *host_name = NULL;
   size_t adr_len = strlen(gw_address) + 1;
   char *url;
   char *cp;

   if (strncmp(gw_address, "tcp://", 6) != 0)
      return NULL;
   url = (char *)malloc(adr_len);
   if (url == NULL)
      return NULL;
   strcpy(url, gw_address);
   cp = strchr(&url[6], ':');
   if (cp != NULL)
   {
      unsigned long   addr;

      *cp = '\0';
      ++cp;
      if ((int)(addr = inet_addr(&url[6])) != -1)
      {
	 struct hostent *hp;

	 hp = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
	 if (hp != NULL && hp->h_addr_list != NULL)
	 {
	    host_name = malloc(strlen(hp->h_name) + adr_len);

	    if (host_name != NULL)
	       sprintf(host_name, "tcp://%s:%s", hp->h_name, cp);
	 }
      }
   }
   free(url);
   return host_name;
} /* gw_host_name */

static OSEGW_BOOLEAN
gw_found(void       *usr_hd,
	 const char *gw_address,
	 const char *gw_name)
{
   struct ClientState *cs    = (struct ClientState *)usr_hd;
   OSEGW_BOOLEAN       found = OSEGW_FALSE;
   char          *host_name  = gw_host_name(gw_address);

   if (host_name != NULL)
      gw_address = host_name;
   if (cs->list_servers)
   {
      if (++cs->found_cnt == 1)
      {
	 size_t url_width = strlen(gw_address);
	 url_width += 10 - (url_width % 10);
	 cs->url_width = url_width;

	 printf("NUM %-*s %s\n", (int)url_width, "SERVER URL", "NAME");
      }
      printf("%3d %-*s %s\n", cs->found_cnt,
	     (int)cs->url_width, gw_address, gw_name);
      if (cs->found_cnt >= cs->list_max)
	 found = OSEGW_TRUE;
   }

   if ((cs->server_url != NULL) &&
       ((strcmp(cs->server_url, gw_address) == 0) ||
	(strcmp(cs->server_url, gw_name) == 0)))

   {
      printf("Connecting to: %s at %s\n", gw_name, gw_address);
      cs->chd = osegw_create(cs->client_name, 0,
			     gw_address,
			     cs->auth_str,
			     gw_err_hnd,
			     NULL);
      found = OSEGW_TRUE;
   }
   if (host_name != NULL)
      free(host_name);
   return found;
} /* gw_found */

static unsigned long
real_clock(void)
{
#ifdef _WIN32
   return GetTickCount();
#else
   static int            initialized = 0;
   static struct timeval sys_start;
   struct timeval        now;

   if (!initialized)
   {
      gettimeofday(&sys_start, NULL);
      initialized = 1;
   }

   gettimeofday(&now, NULL);
   return (now.tv_sec - sys_start.tv_sec) * 1000 + (now.tv_usec / 1000);
#endif
}

static void
echo_test(struct ClientState *cs, unsigned long cnt, OSEGW_OSBUFSIZE bz)
{
   struct OSEGW  *c1, *c2;
   OSEGW_PROCESS  c2_pid;
   unsigned long  loop;

   if (cs->server_url == NULL)
      return;

   c1 = osegw_create("gw_perftest_c1",
		     cs->user,
		     cs->server_url,
		     cs->auth_str,
		     gw_err_hnd,
		     NULL);

   if (c1 == NULL)
      return;

   c2 = osegw_create("gw_perftest_c2",
		     cs->user,
		     cs->server_url,
		     cs->auth_str,
		     gw_err_hnd,
		     NULL);

   if (c2 == NULL)
   {
      osegw_destroy(c1);
      return;
   }
   else
   {
      union OSEGW_SIGNAL *sig = osegw_alloc(c2, sizeof(OSEGW_SIGSELECT), 0);
      c2_pid = osegw_sender(c2, &sig);
      osegw_free_buf(c2, &sig);
   }


   {
      unsigned long t0,  t1;
      long          sec, msec;

      if (bz < sizeof(OSEGW_SIGSELECT))
	 bz = sizeof(OSEGW_SIGSELECT);

      t0 = real_clock();
      for (loop = 0 ; loop < cnt ; ++loop)
      {
	 OSEGW_SIGSELECT     any_sig[] = { 0 };
	 union OSEGW_SIGNAL *sig = osegw_alloc(c1, bz, 0x05E0FEED);
	 osegw_send(c1, &sig, c2_pid);
	 sig = osegw_receive(c2, any_sig);
	 osegw_free_buf(c2, &sig);
      }
      t1 = real_clock();
      sec  = t1 / 1000 - t0 / 1000;
      msec = t1 % 1000 - t0 % 1000;
      if (msec < 0)
      {
	 --sec;
	 msec += 1000;
      }
      printf("%lu sigs, size %u, %ld.%03ld sec, "
	     "%.0f sigs/sec, %.2f bytes/sec\n",
	     cnt, bz, sec, msec,
	     (double)cnt / ((double)sec + ((double)msec / 1000)),
	     ((double)cnt * (double)bz) /
	     ((double)sec + ((double)msec / 1000)));
   }
   osegw_destroy(c1);
   osegw_destroy(c2);
} /* echo_test */

int
main(int argc, char *argv[])
{
#ifdef EXEWHAT
  EXEWHAT
#endif
   struct ClientState   cs;

   memset(&cs, 0, sizeof(cs));

   cs.argc = argc;
   cs.argv = argv;
   cs.brc_addr     = OSEGW_STD_BRC_ADDR;
   cs.client_name  = "gw_client";
   cs.list_timeout = 5000;
   cs.list_max     = ~0UL;

   if (argc > 1)
   {
      int ac;
      char *av;

      for (ac = 1 ; ac < argc ; ac++)
      {
	 av = argv[ac];
	 if (*av == '-')
	 {
	    while (av != NULL && *++av != '\0')
	    {
	       switch (*av)
	       {
		  case 'a':
		     av = argv[++ac];
		     if (av && *av)
		     {
			cs.auth_str = av;
			av = NULL;
		     }
		     else
		     {
			(void)fprintf(stderr, "No auth string followed -a\n");
			exit(1);
		     }
		     break;

		  case 'b':
		     av = argv[++ac];
		     if (av && *av)
		     {
			cs.brc_addr = av;
			av = NULL;
		     }
		     else
		     {
			(void)fprintf(stderr,
				      "No broadcast address followed -b\n");
			exit(1);
		     }
		     break;

		  case 'c':
		     av = argv[++ac];
		     if (av && *av)
		     {
			cs.client_name = av;
			av = NULL;
		     }
		     else
		     {
			(void)fprintf(stderr, "No client name followed -c\n");
			exit(1);
		     }
		     break;

		  case 'e':
		     cs.echo_test = TRUE;
		     if (av[1] >= '0' && av[1] <= '9')
		     {
			cs.echo_cnt = strtoul(&av[1], &av, 10);
			--av;
		     }
		     if (av[1] == ',')
		     {
			if (av[2] >= '0' && av[2] <= '9')
			{
			   cs.echo_chunk = strtoul(&av[2], &av, 10);
			   --av;
			}
			else
			{
			   cs.echo_chunk = sizeof(OSEGW_SIGSELECT);
			   ++av;
			}
		     }
		     if (cs.echo_cnt == 0)
			cs.echo_cnt = 10;
		     if (cs.echo_chunk == 0)
			cs.echo_cnt = sizeof(OSEGW_OSBUFSIZE);
		     break;

		  case 'h':
		     goto Usage;

		  case 'l':
		     cs.list_servers = TRUE;
		     if (av[1] >= '0' && av[1] <= '9')
		     {
			cs.list_timeout = strtoul(&av[1], &av, 10);
			cs.list_timeout *= 1000;
			--av;
		     }
		     if (av[1] == ',')
		     {
			if (av[2] >= '0' && av[2] <= '9')
			{
			   cs.list_max = strtoul(&av[2], &av, 10);
			   --av;
			}
			else
			{
			   cs.list_max = 1;
			   ++av;
			}
		     }
		     break;

		  case 'p':
		     av = argv[++ac];
		     if (av && *av)
		     {
			cs.hunt_path = av;
			av = NULL;
		     }
		     else
		     {
			(void)fprintf(stderr, "No hunt path followed -p\n");
			exit(1);
		     }
		     break;

		  case 's':
		     av = argv[++ac];
		     if (av && *av)
		     {
			cs.server_url = av;
			av = NULL;
		     }
		     else
		     {
			(void)fprintf(stderr, "No server URL followed -s\n");
			exit(1);
		     }
		     break;

		  default:
		     (void)fprintf(stderr, "Unknown flag \"-%c\"\n", *av);
		     exit(1);
	       }
	    }
	 }
	 else
	 {
	    (void)fprintf(stderr, "Unknown argument: \"%s\"\n", av);
	    goto Usage;
	 }
      }
   }
   else
   {
     Usage:
      (void)fprintf(stderr,"OSE Gateway Command tool example, can be used to\n"
                             "find and test gateway servers on a network.\n");
      (void)fprintf(stderr,
	    "Usage: %s [FLAGS]...\n", argv[0]);
      (void)fprintf(stderr,
	    "   -a <auth>     Use <auth> as authentication string,\n");
      (void)fprintf(stderr,
	    "                 which should be in \"user:passwd\" form\n");
      (void)fprintf(stderr,
	    "   -b <brc_addr> Use <brc_addr> as broadcast string,\n");
      (void)fprintf(stderr,
	    "                 which should be in \"udp://*:<port>\" form,\n");
      (void)fprintf(stderr,
	    "                 where <port> should be the port number\n");
      (void)fprintf(stderr,
	    "                 Default broadcast string is \"%s\"\n",
		    OSEGW_STD_BRC_ADDR);
      (void)fprintf(stderr,
	    "   -c <name>     Use <name> as the client's name (default\n");
      (void)fprintf(stderr,
	    "                 \"gw_client\")\n");
      (void)fprintf(stderr,
	    "   -e[<n>][,<b>] Echo test to an OSE Gateway\n");
      (void)fprintf(stderr,
	    "                 use <n> as number of loops (default 10) and\n");
      (void)fprintf(stderr,
	    "                 <b> for number of bytes/chunk (default 4)\n");
      (void)fprintf(stderr,
	    "   -h            Print this usage message\n");
      (void)fprintf(stderr,
	    "   -l[<t>][,<n>] List OSE GateWays\n");
      (void)fprintf(stderr,
	    "                 use <t> as timeout value (default is 5 secs)\n");
      (void)fprintf(stderr,
	    "                 and <n> for max items (default lists all)\n");
      (void)fprintf(stderr,
	    "                 -l25,1 => look for Gateways in 25 secs and\n");
      (void)fprintf(stderr,
            "                 list only the first found\n");
      (void)fprintf(stderr,
	    "   -p <proc>     Hunt for process <proc>\n");
      (void)fprintf(stderr,
	    "   -s <url/name> Connect to a OSE GateWay server using either\n");
      (void)fprintf(stderr,
	    "                 the servers url or its name\n");
      exit(1);
   }

   if (cs.echo_test)
   {
      echo_test(&cs, cs.echo_cnt, cs.echo_chunk);
   }
   else if (cs.server_url != NULL &&
	    (strncmp(cs.server_url, "tcp://", 6) == 0) &&
	    !cs.list_servers)
   {
      printf("Connecting to: '%s'\n", cs.server_url);
      cs.chd = osegw_create(cs.client_name,
			    cs.user,
			    cs.server_url,
			    cs.auth_str,
			    gw_err_hnd,
			    NULL);
      if (cs.chd == NULL)
      {
	 fprintf(stderr,
		 "Could not connect to GateWay at \"%s\"",
		 cs.server_url);
	 return 1;
      }
   }
   else
   {
      if (cs.list_servers)
	 printf("List gateways (timeout %lu):\n", cs.list_timeout);
      if (!osegw_find_gw(cs.brc_addr,        /* broadcast_address  */
			 cs.list_timeout,    /* timeout            */
			 gw_found,           /* Call back function */
			 &cs))               /* usr_hd             */
      {
	 return 0;
      }
   }

   if (cs.chd != NULL && cs.hunt_path != NULL)
   {
      union OSEGW_SIGNAL  *hsig, *rsig;

      hsig = osegw_alloc(cs.chd, sizeof(OSEGW_SIGSELECT), 0xF00DF00D);
      printf("Client process '%s' is hunting for: '%s'\n",
	     cs.client_name, cs.hunt_path);
      (void)osegw_hunt(cs.chd,
		       cs.hunt_path,
		       0,
		       NULL,
		       &hsig);
      rsig = osegw_receive(cs.chd, any_sig);
      if (rsig != OSEGW_NIL)
      {
	 printf("Found: '%s' @ %#010x\n",
		cs.hunt_path,
		osegw_sender(cs.chd, &rsig));
	 osegw_free_buf(cs.chd, &rsig);
      }
   }

   if (cs.chd != NULL)
      osegw_destroy(cs.chd);
   return 0;
} /* main */
