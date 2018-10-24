/*
 *  Copyright (c) 2006-2007, Enea Software AB .
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/linx_ioctl.h>
#include <linux/linx_types.h>
#include <linux/linx_socket.h>
#include <af_linx.h>
#include <rlnh.h>
#include <linx_trace.h>
#include <cfg/db.h>
#include <cfg/db_proc.h>

extern int linx_is_argument_power_of_two(int a, char *string);
static int linx_is_module_parameter_in_range(int par, int min, int max);

MODULE_AUTHOR("ENEA");
MODULE_DESCRIPTION("LINX: A transparent IPC mechanism based on sockets");
MODULE_LICENSE("GPL");
MODULE_VERSION(LINX_VERSION);
MODULE_ALIAS_NETPROTO(PF_LINX);

/*
 * Module arguments.
 */

int linx_mem_frag = 0;
static char *linx_mem_fragmentation = "no";
module_param(linx_mem_fragmentation, charp, S_IRUGO);
MODULE_PARM_DESC(linx_mem_fragmentation, "Memory fragmentation support");


int linx_max_spids = LINX_MAX_SPIDS_DEFAULT;
module_param(linx_max_spids, int, S_IRUGO);
MODULE_PARM_DESC(linx_max_spids, "Maximum number of LINX sockets");
static int __init check_linx_max_spids(void)
{
	if (!linx_is_module_parameter_in_range(linx_max_spids,
					       LINX_MAX_SPIDS_DEFAULT,
					       LINX_MAX_SPIDS_ALLOWED)) {
		linx_err("linx_max_spids outside allowed range.");
		return -EINVAL;
	}
	if (!linx_is_argument_power_of_two(linx_max_spids, "linx_max_spids"))
		return -EINVAL;
        return 0;
}

int linx_max_attrefs = LINX_MAX_ATTREFS_DEFAULT;
module_param(linx_max_attrefs, int, S_IRUGO);
MODULE_PARM_DESC(linx_max_attrefs, "Maximum number of attach references");
static int __init check_linx_max_attrefs(void)
{
	if (!linx_is_module_parameter_in_range(linx_max_attrefs,
					       LINX_MAX_ATTREFS_DEFAULT,
					       LINX_MAX_ATTREFS_ALLOWED)) {
		linx_err("linx_max_attrefs outside allowed range.");
		return -EINVAL;
	}
	if (!linx_is_argument_power_of_two(linx_max_attrefs,
					   "linx_max_attrefs"))
		return -EINVAL;
        return 0;
}

int linx_max_links = LINX_MAX_LINKS_DEFAULT;
module_param(linx_max_links, int, S_IRUGO);
MODULE_PARM_DESC(linx_max_links, "Maximum number of external links");
static int __init check_linx_max_links(void)
{
	if (!linx_is_module_parameter_in_range(linx_max_links,
					       LINX_MAX_LINKS_DEFAULT,
					       LINX_MAX_LINKS_ALLOWED)) {
		linx_err("linx_max_links outside allowed range.");
		return -EINVAL;
	}
        return 0;
}

int linx_max_sockets_per_link = LINX_MAX_SOCKETS_PER_LINK_DEFAULT;
module_param(linx_max_sockets_per_link, int, S_IRUGO);
MODULE_PARM_DESC(linx_max_sockets_per_link, "Maximum number of communicating "
		 "sockets over a link");
static int __init check_linx_max_sockets_per_link(void)
{
	if (!linx_is_module_parameter_in_range(linx_max_sockets_per_link,
					       LINX_MAX_SOCKETS_PER_LINK_MIN,
					       LINX_MAX_SOCKETS_PER_LINK_ALLOWED))
	{
		linx_err("linx_max_sockets_per_link outside allowed range.");
		return -EINVAL;
	}
	if (!linx_is_argument_power_of_two(linx_max_sockets_per_link,
					   "linx_max_sockets_per_link"))
		return -EINVAL;
        return 0;
}

int linx_max_tmorefs = LINX_MAX_TMOREFS_DEFAULT;
module_param(linx_max_tmorefs, int, S_IRUGO);
MODULE_PARM_DESC(linx_max_tmorefs, "Maximum number of timeout references");
static int __init check_linx_max_tmorefs(void)
{
	if (!linx_is_module_parameter_in_range(linx_max_tmorefs,
					       LINX_MAX_TMOREFS_DEFAULT,
					       LINX_MAX_TMOREFS_ALLOWED)) {
		linx_err("linx_max_tmorefs outside allowed range.");
		return -EINVAL;
	}
	if (!linx_is_argument_power_of_two(linx_max_tmorefs,
					   "linx_max_tmorefs"))
		return -EINVAL;
        return 0;
}

unsigned int linx_version(void)
{
	unsigned int major, minor, patch;
	unsigned int version;
	char *end;

	major = simple_strtoul(LINX_VERSION, &end, 0);
	minor = simple_strtoul(end + 1, &end, 0);
	patch = simple_strtoul(end + 1, NULL, 0);

	version = (((major << 16) + (minor)) << 8) + patch;

	return version;
}

int linx_is_argument_power_of_two(int a, char *string)
{
	if ((a & (a - 1)) || a < 2) {
		printk("LINX Error: Argument %s must be power of two."
		       " Value %d\n", string, a);
		return 0;
	}
	return 1;
}

static int linx_is_module_parameter_in_range(int par, int min, int max)
{
	if (par < min)
		return 0;
	if (par > max)
		return 0;
	return 1;
}

static int __init check_module_parameters(void)
{
        int status;

        if ((status = check_linx_max_spids()) != 0)
                return status;

        if ((status = check_linx_max_attrefs()) != 0)
                return status;

        if ((status = check_linx_max_links()) != 0)
                return status;

        if ((status = check_linx_max_sockets_per_link()) != 0)
                return status;

        if ((status = check_linx_max_tmorefs()) != 0)
                return status;

        return 0;
}

static void __init print_module_info(void)
{
	printk(KERN_INFO "LINX: version %s\n", LINX_VERSION);
	printk(KERN_INFO "LINX: Compile-time configuration:\n");
	printk(KERN_INFO "LINX: Max number of LINX sockets %d\n",
	       linx_max_spids);
	printk(KERN_INFO "LINX: Max number of attach references %d\n",
	       linx_max_attrefs);
	printk(KERN_INFO "LINX: Max number of remote links %d\n",
	       linx_max_links);
	printk(KERN_INFO "LINX: Max number of communicating sockets over a "
	       "link %d\n", linx_max_sockets_per_link);
	printk(KERN_INFO "LINX: Max number of timeout references %d\n",
	       linx_max_tmorefs);
#ifdef TRACE
	printk(KERN_INFO "LINX: Trace enabled.\n");
#endif
#ifdef ERRORCHECKS
	printk(KERN_INFO "LINX: Errorchecks enabled.\n");
#endif
#ifdef ERRORCHECKS_MEM
	printk(KERN_INFO "LINX: Malloc/free errorchecks enabled.\n");
#endif
#ifdef STATISTICS
	printk(KERN_INFO "LINX: Statistics enabled.\n");
#endif
        if (linx_mem_frag == 1)
		printk(KERN_INFO "LINX: Memory fragmentation enabled.\n");
	}

/*
 * This function is called when insmod is called to load the linx.ko
 * kernel module.  The responsibility of this function is to fully
 * initialize the linx.ko kernel module.
 */
static int __init linx_init(void)
{
        int status;

#ifdef TRACE
	linx_trace_enable(LINX_TRACEGROUP_GENERAL, LINX_TRACE_DEBUG);
	linx_trace_enable(LINX_TRACEGROUP_AF_LINX, LINX_TRACE_DEBUG);
	linx_trace_enable(LINX_TRACEGROUP_IPC, LINX_TRACE_DEBUG);
	linx_trace_enable(LINX_TRACEGROUP_ETH_CM, LINX_TRACE_DEBUG);
	linx_trace_enable(LINX_TRACEGROUP_RLNH, LINX_TRACE_DEBUG);
	linx_trace_enable(LINX_TRACEGROUP_TCP_CM, LINX_TRACE_DEBUG);
#endif
	linx_trace_enter(LINX_TRACEGROUP_GENERAL, "");

        if ((status = check_module_parameters()) != 0)
                return status;

	if (strcmp("yes", linx_mem_fragmentation) == 0)
		linx_mem_frag = 1;
        else
                linx_mem_frag = 0;

        print_module_info();

        if ((status = db_proc_init("linx")) != 0) {
                linx_err("Failed to create LINX procfs directory.");
                return status;
        }

        if ((status = linx_sock_stats_init()) != 0) {
                linx_err("Failed to initialize LINX socket statistics.");
                goto out_20;
        }

	if ((status = af_linx_init()) != 0) {
		linx_err("Failed to initialize LINX socket layer.");
		goto out_10;
	}

	if ((status = rlnh_init()) != 0) {
		linx_err("Failed to initialize RLNH.");
		goto out_10;
	}

	linx_trace_exit(LINX_TRACEGROUP_GENERAL, "");
	return 0;

  out_10:
        linx_sock_stats_cleanup();
  out_20:
        db_proc_cleanup("linx");
	linx_trace_exit(LINX_TRACEGROUP_GENERAL, "");
        return status;
}
module_init(linx_init);

/*
 * This function is called when rmmod is called to unload the linx.ko
 * kernel module.  The responsibility of this function is to fully
 * remove the linx.ko kernel module.
 */
static void __exit linx_exit(void)
{
	linx_trace_enter(LINX_TRACEGROUP_GENERAL, "");

        /*
         * On error: don't return, try to remove as much as possible.
         */
        linx_sock_stats_cleanup();

	if (rlnh_finalize() != 0)
		linx_warn("Failed to finalize RLNH.");

	if (af_linx_exit() != 0)
		linx_warn("Failed to finalize LINX socket layer.");

        db_proc_cleanup("linx");

	linx_trace_exit(LINX_TRACEGROUP_GENERAL, "");
}
module_exit(linx_exit);
