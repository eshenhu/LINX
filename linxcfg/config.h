/*
 * Copyright (c) 2007, Enea Software AB
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
#ifndef CONFIG_H
#define CONFIG_H

#include <getopt.h>

#define uint  unsigned int
#define ulong unsigned long

enum cfg_type {
	CONFIG_TYPE_NONE = 0,	/* not used, do ignore it, really! */
	CONFIG_TYPE_STRING = 1,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_UINT,
	CONFIG_TYPE_LONG,
	CONFIG_TYPE_ULONG,
	CONFIG_TYPE_DOUBLE,
	CONFIG_TYPE_LAST	/* always the last member of the enumeration */
};

typedef int (*cfg_range_function) (const char *str);

union cfg_range {
	struct {
		int min;
		int max;
	} i;
	struct {
		uint min;
		uint max;
	} u;
	struct {
		long min;
		long max;
	} l;
	struct {
		ulong min;
		ulong max;
	} ul;
	struct {
		double min;
		double max;
	} d;
	struct {
		int (*check) (const char *str);
	} s;
/*	cfg_range_function check;*/
};

union cfg_value {
	int i;
	uint u;
	long l;
	ulong ul;
	double d;
	char *s;
};

struct cfg_template {
	struct option op;	/* getopt long structure        */
	enum cfg_type type;	/* parameter type               */
	union cfg_range range;	/* the range of allowed values  */
	union cfg_value def;	/* the default value, if any    */
	union cfg_value *value;	/* the value given              */
	unsigned int flags;	/* flags for this template      */
	char *desc;		/* a description for this       */
};

/* template flags */
#define CONFIG_FLAG_PARAMETER 0x01
#define CONFIG_FLAG_FEATURE   0x02
#define CONFIG_FLAG_LIST      0x04
#define CONFIG_FLAG_ALLOCATED 0x08
#define CONFIG_FLAG_SET       0x10
#define CONFIG_FLAG_LAST      0x20

/* convenience macros */
#define CFG_OPT_NAME(name)   {(name), 1, NULL, 0}
#define CFG_OPT_NOARG(name)  {(name), 0, NULL, 0}
#define CFG_OPT_LAST         {NULL,   0, NULL, 0}

#define CFG_RANGE_INT(min, max)    {.i={(int)(min),(int)(max)}}
#define CFG_RANGE_INT_DEFAULT      {.i={(int)0,(int)0}}
#define CFG_RANGE_UINT(min, max)   {.u={(uint)(min),(uint)(max)}}
#define CFG_RANGE_UINT_DEFAULT     {.u={(uint)0,(uint)0}}
#define CFG_RANGE_LONG(min, max)   {.l={(long)(min),(long)(max)}}
#define CFG_RANGE_LONG_DEFAULT     {.l={(long)0,(long)0}}
#define CFG_RANGE_ULONG(min, max)  {.ul={(ulong)(min),(ulong)(max)}}
#define CFG_RANGE_ULONG_DEFAULT    {.ul={(ulong)0,(ulong)0}}
#define CFG_RANGE_DOUBLE(min, max) {.d={(double)(min),(double)(max)}}
#define CFG_RANGE_DOUBLE_DEFAULT   {.d={(double)0.0,(double)0.0}}
#define CFG_RANGE_STRING(func)     {.s={func}}
#define CFG_RANGE_STRING_DEFAULT   {.s={NULL}}

#define CFG_DEFAULT_INT(a)       {.i=(int)(a)}
#define CFG_DEFAULT_UINT(a)      {.u=(uint)(a)}
#define CFG_DEFAULT_LONG(a)      {.l=(long)(a)}
#define CFG_DEFAULT_ULONG(a)     {.ul=(ulong)(a)}
#define CFG_DEFAULT_DOUBLE(a)    {.d=(double)(a)}
#define CFG_DEFAULT_STRING(a)    {.s=(char *)(a)}

#define CFG_VALUE(value)         {value}
#define CFG_VALUE_PTR(ptr)       (union cfg_value *)(ptr)

#define CFG_VALUE_INT(a)          CFG_VALUE(.i=(int)a)
#define CFG_VALUE_UINT(a)         CFG_VALUE(.u=(uint)a)
#define CFG_VALUE_LONG(a)         CFG_VALUE(.l=(long)a)
#define CFG_VALUE_ULONG(a)        CFG_VALUE(.ul=(ulong)a)
#define CFG_VALUE_DOUBLE(a)       CFG_VALUE(.d=(double)a)
#define CFG_VALUE_STRING(a)       CFG_VALUE(.s=(char *)a)

#define CFG_VALUE_INT_DEFAULT     CFG_VALUE_INT(0)
#define CFG_VALUE_UINT_DEFAULT    CFG_VALUE_UINT(0)
#define CFG_VALUE_LONG_DEFAULT    CFG_VALUE_LONG(0)
#define CFG_VALUE_ULONG_DEFAULT   CFG_VALUE_ULONG(0)
#define CFG_VALUE_DOUBLE_DEFAULT  CFG_VALUE_DOUBLE(0)
#define CFG_VALUE_STRING_DEFAULT  CFG_VALUE_STRING(NULL)

#define CFG_ENTRY(name, type, val_ptr, flags) \
{                                             \
	CFG_OPT_NAME(name),                   \
	CONFIG_TYPE_ ## type ,                \
	CFG_RANGE_ ## type ## _DEFAULT,       \
	CFG_VALUE_ ## type ## _DEFAULT,       \
	CFG_VALUE_PTR(val_ptr),               \
	flags,                                \
	NULL                                  \
}

#define CFG_PARAMETER(name, type, range, def, value, description) \
{                              \
	CFG_OPT_NAME(name),    \
	type,                  \
	range,                 \
	def,                   \
	CFG_VALUE_PTR(value),  \
	CONFIG_FLAG_PARAMETER, \
	description            \
}

#define CFG_FEATURE(name, type, range, def, value, description) \
{                            \
	CFG_OPT_NAME(name),  \
	type,                \
	range,               \
	def,                 \
	CFG_VALUE_PTR(value),\
	CONFIG_FLAG_FEATURE, \
	description          \
}

/* 
 * STRING
 */
#define CFG_STRING(name, val_ptr, flags)  \
	CFG_ENTRY(name, STRING, val_ptr, flags)
#define CFG_PARAM_STRING(name, val_ptr)   \
	CFG_STRING(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_STRING(name, val_ptr) \
	CFG_STRING(name, val_ptr, CONFIG_FLAG_FEATURE)

/*
 * INT
 */
#define CFG_INT(name, val_ptr, flags)  \
	CFG_ENTRY(name, INT, val_ptr, flags)
#define CFG_PARAM_INT(name, val_ptr)   \
	CFG_INT(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_INT(name, val_ptr) \
	CFG_INT(name, val_ptr, CONFIG_FLAG_FEATURE)

/*
 * UINT
 */
#define CFG_UINT(name, val_ptr, flags)  \
	CFG_ENTRY(name, UINT, val_ptr, flags)
#define CFG_PARAM_UINT(name, val_ptr)   \
	CFG_UINT(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_UINT(name, val_ptr) \
	CFG_UINT(name, val_ptr, CONFIG_FLAG_FEATURE)

/*
 * LONG
 */
#define CFG_LONG(name, val_ptr, flags)  \
	CFG_ENTRY(name, LONG, val_ptr, flags)
#define CFG_PARAM_LONG(name, val_ptr)   \
	CFG_LONG(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_LONG(name, val_ptr) \
	CFG_LONG(name, val_ptr, CONFIG_FLAG_FEATURE)

/*
 * ULONG
 */
#define CFG_ULONG(name, val_ptr, flags)  \
	CFG_ENTRY(name, ULONG, val_ptr, flags)
#define CFG_PARAM_ULONG(name, val_ptr)   \
	CFG_ULONG(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_ULONG(name, val_ptr) \
	CFG_ULONG(name, val_ptr, CONFIG_FLAG_FEATURE)

/*
 * DOUBLE
 */
#define CFG_DOUBLE(name, val_ptr, flags)  \
	CFG_ENTRY(name, DOUBLE, val_ptr, flags)
#define CFG_PARAM_DOUBLE(name, val_ptr)   \
	CFG_DOUBLE(name, val_ptr, CONFIG_FLAG_PARAMETER)
#define CFG_FEATURE_DOUBLE(name, val_ptr) \
	CFG_DOUBLE(name, val_ptr, CONFIG_FLAG_FEATURE)

#define CFG_PARAM_LAST              \
{                                   \
	  CFG_OPT_LAST,             \
	  CONFIG_TYPE_LAST,         \
	  CFG_RANGE_INT_DEFAULT,    \
	  CFG_VALUE_INT_DEFAULT,    \
	  NULL,                     \
	  CONFIG_FLAG_LAST,         \
	  NULL                      \
}

#define CFG_FEATURE_LAST CFG_PARAM_LAST

#ifdef DEBUG
void print_template_element(struct cfg_template *t);
void print_template(struct cfg_template t[]);
void print_long_option(struct option *op);
void print_longopt(struct option *op);
#endif

struct option *get_long_options(struct cfg_template *template);

void config_init_getopt(struct cfg_template *template,
			int argc, char *const argv[]);

int config_set_value(struct cfg_template *template,
		     const char *name, char *str);

int config_option_was_set(struct cfg_template *template, const char *name);

void config_init(struct cfg_template *template, int argc, char *const argv[]);

void config_parse_noops(struct cfg_template *template, int argc, char *argv[]);

int config_get_value(struct cfg_template *template,
		     const char *name, union cfg_value *retval);

void config_cleanup(struct cfg_template *template);

int config_get_option_list(struct cfg_template *t,
			   char ***retval, unsigned int flags);

#define cfg_get_value(t, n, r) \
	config_get_value((t), (n), CFG_VALUE_PTR(r))

#endif
