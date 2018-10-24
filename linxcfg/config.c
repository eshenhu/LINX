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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "config.h"

#ifdef DEBUG
void print_template_element(struct cfg_template *t)
{
	printf("Name: %s\n", t->op.name);
	printf("\tType: ");
	switch (t->type) {
	case CONFIG_TYPE_NONE:
		printf("NONE\n");
		break;
	case CONFIG_TYPE_STRING:
		printf("STRING\n");
		printf("\tDefault: %s\n", t->def.s);
		break;
	case CONFIG_TYPE_INT:
		printf("INT\n");
		printf("\tRANGE: from %d to %d\n",
		       t->range.i.min, t->range.i.max);
		printf("\tDefault: %d\n", t->def.i);
		printf("\tValue: ");
		if (t->value != NULL) {
			printf("%d\n", t->value->i);
		} else {
			printf("NULL\n");
		}
		printf("\tFlags: 0x%08X\n", t->flags);
		break;
	case CONFIG_TYPE_UINT:
		printf("UNSIGNED INT\n");
		printf("\tRANGE: from %u to %u\n",
		       t->range.u.min, t->range.u.max);
		printf("\tDefault: %u\n", t->def.u);
		printf("\tValue: ");
		if (t->value != NULL) {
			printf("%u\n", t->value->u);
		} else {
			printf("NULL\n");
		}
		printf("\tFlags: 0x%08X\n", t->flags);
		break;
	case CONFIG_TYPE_LONG:
		printf("LONG\n");
		printf("\tRANGE: from %ld to %ld\n",
		       t->range.l.min, t->range.l.max);
		printf("\tDefault: %ld\n", t->def.l);
		printf("\tValue: ");
		if (t->value != NULL) {
			printf("%ld\n", t->value->l);
		} else {
			printf("NULL\n");
		}
		printf("\tFlags: 0x%08X\n", t->flags);
		break;
	case CONFIG_TYPE_ULONG:
		printf("UNSIGNED LONG\n");
		printf("\tRANGE: from %lu to %lu\n",
		       t->range.ul.min, t->range.ul.max);
		printf("\tDefault: %lu\n", t->def.ul);
		printf("\tValue: ");
		if (t->value != NULL) {
			printf("%lu\n", t->value->ul);
		} else {
			printf("NULL\n");
		}
		printf("\tFlags: 0x%08X\n", t->flags);
		break;
	case CONFIG_TYPE_DOUBLE:
		printf("DOUBLE\n");
		printf("\tRANGE: from %f to %f\n",
		       t->range.d.min, t->range.d.max);
		printf("\tDefault: %f\n", t->def.d);
		printf("\tValue: ");
		if (t->value != NULL) {
			printf("%f\n", t->value->d);
		} else {
			printf("NULL\n");
		}
		break;
	default:
		printf("\tUNKNOWN (%d)\n", t->type);
	}
	printf("\tDescription: %s\n", t->desc);
}

void print_template(struct cfg_template t[])
{
	while (t->type != CONFIG_TYPE_LAST)
		print_template_element(t++);
}

void print_long_option(struct option *op)
{
	printf("\tNAME:    %s\n", op->name);
	printf("\tHAS ARG: %s\n", op->has_arg ? "TRUE" : "FALSE");
	printf("\tFLAG:    %p\n", op->flag);
	printf("\tVAL:     %d\n", op->val);
}

void print_longopt(struct option *op)
{
	int x = 1;
	if (op == NULL)
		return;
	do {
		printf("---[ (%d) %s (at %p)]---\n", x++, op->name, op);
		print_long_option(op);
		op++;
	} while (op->name != NULL);
}
#endif

inline static void *Malloc(size_t size)
{
	void *ret;

	if ((ret = malloc(size)) == NULL) {
		perror("malloc");
		exit(1);
	}

	return ret;
}

struct option *get_long_options(struct cfg_template *template)
{
	int n = 1;
	struct cfg_template *t;
	struct option *retval, *ptr;

	if (template == NULL)
		return NULL;
	t = template;

	/* get the amount of options we have */
	while (t->type != CONFIG_TYPE_LAST) {
		n++;
		t++;
	}

	retval = (struct option *)(Malloc(sizeof(struct option) * n));

	ptr = retval;
	t = template;
	do {
		memcpy(ptr, &(t->op), sizeof(struct option));
		ptr++;
		t++;
	} while (t->type != CONFIG_TYPE_LAST);

	ptr->name = NULL;
	ptr->has_arg = 0;
	ptr->flag = 0;
	ptr->val = 0;

	return retval;
}

static int get_index(struct cfg_template *template, const char *name,
		     struct cfg_template **ptr)
{
	int num = 0;

	if (template == NULL)
		return -1;

	while (template->op.name != NULL) {
		if (strcmp(template->op.name, name) == 0) {
			if (ptr != NULL) {
				*ptr = template;
			}
			return num;
		}
		template++;
		num++;
	}

	return -1;
}

int config_get_value(struct cfg_template *template, const char *name,
		     union cfg_value *retval)
{
	char *str;

	if (get_index(template, name, &template) < 0)
		return 1;	/* error */

	switch (template->type) {
	case CONFIG_TYPE_INT:
		if (template->value != NULL)
			retval->i = template->value->i;
		else
			retval->i = template->def.i;
		break;
	case CONFIG_TYPE_UINT:
		if (template->value != NULL)
			retval->u = template->value->u;
		else
			retval->u = template->def.u;
		break;
	case CONFIG_TYPE_LONG:
		if (template->value != NULL)
			retval->l = template->value->l;
		else
			retval->l = template->def.l;
		break;
	case CONFIG_TYPE_ULONG:
		if (template->value != NULL)
			retval->ul = template->value->ul;
		else
			retval->ul = template->def.ul;
		break;
	case CONFIG_TYPE_DOUBLE:
		if (template->value != NULL)
			retval->d = template->value->d;
		else
			retval->d = template->def.d;
		break;
	case CONFIG_TYPE_STRING:
		if (template->value != NULL) {
			str = template->value->s;
		} else {
			str = template->def.s;
		}
		if (str != NULL) {
			retval->s = Malloc(strlen(str) + 1);
			strncpy(retval->s, str, strlen(str) + 1);
		} else {
			retval->s = NULL;
		}
		break;
	default:
		return 2;
	}

	return 0;
}

static int config_value_in_range(const struct cfg_template *t,
				 const union cfg_value *value)
{
	if (t == NULL)
		return 0;

	switch (t->type) {
	case CONFIG_TYPE_STRING:
		if (t->range.s.check == NULL)
			break;
		return t->range.s.check(value->s);
	case CONFIG_TYPE_INT:
		if (t->range.i.min == t->range.i.max)
			break;
		if (value->i < t->range.i.min)
			return -1;
		if (value->i > t->range.i.max)
			return 1;
		break;
	case CONFIG_TYPE_UINT:
		if (t->range.u.min == t->range.u.max)
			break;
		if (value->u < t->range.u.min)
			return -1;
		if (value->u > t->range.u.max)
			return 1;
		break;
	case CONFIG_TYPE_LONG:
		if (t->range.l.min == t->range.l.max)
			break;
		if (value->l < t->range.l.min)
			return -1;
		if (value->l > t->range.l.max)
			return 1;
		break;
	case CONFIG_TYPE_ULONG:
		if (t->range.ul.min == t->range.ul.max)
			break;
		if (value->ul < t->range.ul.min)
			return -1;
		if (value->ul > t->range.ul.max)
			return 1;
		break;
	case CONFIG_TYPE_DOUBLE:
		if (t->range.d.min == t->range.d.max)
			break;
		if (value->d < t->range.d.min)
			return -1;
		if (value->d > t->range.d.max)
			return 1;
		break;
	case CONFIG_TYPE_NONE:
	case CONFIG_TYPE_LAST:
		break;
	}
	return 0;
}

int config_option_was_set(struct cfg_template *template, const char *name)
{
	if (get_index(template, name, &template) < 0)
		return 0;
	return (template->flags & CONFIG_FLAG_SET);
}

/*
 * return value: <0 if it was under the range
 *               =0 if it was OK (or the name was not found)
 *               >0 if it was over the range
 */
int config_set_value(struct cfg_template *template, const char *name, char *str)
{
	struct cfg_template *ptr = NULL;
	union cfg_value value = { 0UL };
	char *err_pos = NULL;
	long num = 0L;
	unsigned long ul = 0UL;

	if (get_index(template, name, &ptr) < 0)
		return 0;

	/* this should not be required, since we initialize all values
	 * before in config_init
	 */
	if (ptr->value == NULL) {
		ptr->value = (union cfg_value *)Malloc(sizeof(union cfg_value));
		memset(ptr->value, '\0', sizeof(union cfg_value));
		ptr->flags |= CONFIG_FLAG_ALLOCATED;
	}

	if (ptr->type == CONFIG_TYPE_STRING) {
		/* Check if the new value is OK for the range specified */
		if ((num = config_value_in_range(ptr, CFG_VALUE_PTR((void *)&str))))
			return num;

		/* if no value passed, copy the default one */
		if (str == NULL) {
			if (ptr->def.s == NULL) {
				ptr->flags |= CONFIG_FLAG_SET;
				return 0;
			}
			str = ptr->def.s;
		}
		if (ptr->value != NULL && ptr->value->s != NULL)
			free(ptr->value->s);
		ptr->value->s = Malloc(strlen(str) + 1);
		strncpy(ptr->value->s, str, strlen(str) + 1);
#ifdef DEBUG
		fprintf(stderr, "%s set to: %s\n", name, ptr->value->s);
#endif
		ptr->flags |= CONFIG_FLAG_SET;
		return 0;
	}

	errno = 0;
	switch (ptr->type) {
	case CONFIG_TYPE_INT:
	case CONFIG_TYPE_LONG:
		num = strtol(str, &err_pos, 0);
		break;
	case CONFIG_TYPE_UINT:
	case CONFIG_TYPE_ULONG:
		ul = strtol(str, &err_pos, 0);
		break;
	case CONFIG_TYPE_DOUBLE:
		value.d = strtod(str, &err_pos);
		break;
	default:
		fprintf(stderr, "Unknown type 0%o\n", ptr->type);
		return 0;
	}

	/* check whether we got an error during conversion */
	if (errno != 0 || *err_pos != '\0') {
		fprintf(stderr,
			"'%s' doesn't seem to be a valid value for %s, "
			"near '%s'.\n", str, name, err_pos);
		exit(1);	/* right now we fail ungraciously 
				 * we should return something meaningful
				 */
	}

	switch (ptr->type) {
	case CONFIG_TYPE_INT:
		value.i = (int)num;
		break;
	case CONFIG_TYPE_UINT:
		value.u = (unsigned int)ul;
		break;
	case CONFIG_TYPE_LONG:
		value.l = num;
		break;
	case CONFIG_TYPE_ULONG:
		value.ul = ul;
		break;
	default:
		break;
	}

	if ((num = config_value_in_range(ptr, &value)))
		return num;

	memcpy(ptr->value, &value, sizeof(union cfg_value));

#ifdef DEBUG
	fprintf(stderr, "%s set to %s\n", name, str);
#endif

	ptr->flags |= CONFIG_FLAG_SET;

	return 0;
}

static void config_set_default_value(struct cfg_template *ptr)
{
	if (ptr == NULL)
		return;

	if (ptr->value == NULL) {
		ptr->value = (union cfg_value *)Malloc(sizeof(union cfg_value));
		memset(ptr->value, '\0', sizeof(union cfg_value));
		ptr->flags |= CONFIG_FLAG_ALLOCATED;
	}

	switch (ptr->type) {
	case CONFIG_TYPE_INT:
		ptr->value->i = ptr->def.i;
		break;
	case CONFIG_TYPE_UINT:
		ptr->value->u = ptr->def.u;
		break;
	case CONFIG_TYPE_LONG:
		ptr->value->l = ptr->def.l;
		break;
	case CONFIG_TYPE_ULONG:
		ptr->value->ul = ptr->def.ul;
		break;
	case CONFIG_TYPE_DOUBLE:
		ptr->value->d = ptr->def.d;
		break;
	case CONFIG_TYPE_STRING:
		ptr->value->s = NULL;
		break;
	default:
		break;
	}
}

void config_init(struct cfg_template *template, int argc, char *const argv[])
{
	int opt = 0;
	struct option *long_options = get_long_options(template);
	struct cfg_template *ptr;

	for (ptr = template; ptr->type != CONFIG_TYPE_LAST; ptr++) {
		config_set_default_value(ptr);
	}

	while (1) {
		int op_index = 0;
		opt = getopt_long(argc, argv, ":", long_options, &op_index);
		if (opt == -1)
			break;	/* last option */

		switch (opt) {
		case 0:
			opt = config_set_value(template,
					       long_options[op_index].name,
					       optarg);
			if (opt > 0) {
				fprintf(stderr,
					"The value for %s exceeds the range: "
					"%s\n",
					long_options[op_index].name, optarg);
				exit(1);
			} else if (opt < 0) {
				fprintf(stderr,
					"The value for %s is under the range: "
					"%s\n",
					long_options[op_index].name, optarg);
				exit(1);
			}
			break;
		case ':':
			fprintf(stderr, "Missing parameter\n");
			exit(0);
		case '?':
		default:
			break;
		}
	}

	free(long_options);
}

static int _parse_argument(char *arg, char **param, char **value)
{
	char *token;

	token = strchr(arg, '=');
	if (token == NULL) {
		*param = NULL;
		return 1;
	} else if (token == arg) {
		*param = arg;
		return 1;
	} else if (token[1] == '\0') {
		*param = &token[1];
		return 1;	/* error */
	}

	*param = (char *)Malloc(token - arg + 2);
	memcpy(*param, arg, token - arg);
	(*param)[token - arg] = '\0';
	token++;
	*value = (char *)Malloc(strlen(token) + 1);
	memcpy(*value, token, strlen(token) + 1);	/* includes \0 */
	return 0;
}

void config_parse_noops(struct cfg_template *template, int argc, char *argv[])
{
	char *param;
	char *value;
	char *ptr;
	int target_ind;

	struct cfg_template *t = template;

	/* optind comes from getopt.h */
	while (optind < argc) {
		ptr = argv[optind];
		if (!strchr(ptr, '=')) {
			/* find next with bla=bleh */
			target_ind = optind + 1;
			while ((target_ind < argc) &&
			       (strchr(argv[target_ind], '=') == NULL)) {
				target_ind++;
			}
			if (target_ind == argc) {
				/* reached the end */
				break;
			} else {
				/* reorder */
				char *tmp;
				ptr = argv[target_ind];
				for (; target_ind > optind; target_ind--) {
					tmp = argv[target_ind];
					argv[target_ind] = argv[target_ind - 1];
					argv[target_ind - 1] = tmp;
				}
			}
		}

		/* guaranteed that the current argv[optind] has '=' */
		/* parse string */
		if (_parse_argument(ptr, &param, &value)) {
			if (param == NULL) {
				fprintf(stderr,
					"Parse error: not a parameter '%s'.\n",
					ptr);
			} else if (param == ptr) {
				fprintf(stderr,
					"Parse error: parameter '%s' begins "
					"with a '='.\n", ptr);
			} else {
				fprintf(stderr,
					"Parse error: parameter '%s' ends "
					"with a '='.\n", ptr);
			}
			exit(1);
		}

		if (get_index(template, param, &t) < 0) {
			fprintf(stderr, "Error: unknown parameter %s\n", param);
			exit(1);
		}

		target_ind = config_set_value(t, param, value);
		if (target_ind > 0) {
			fprintf(stderr,
				"The value for '%s' exceeds the range: %s\n",
				param, value);
			exit(1);
		} else if (target_ind < 0) {
			fprintf(stderr,
				"The value for '%s' is under the range: %s\n",
				param, value);
			exit(1);
		}
		if (value != NULL) {
			free(value);
			value = NULL;
		}
		if (param != NULL) {
			free(param);
			param = NULL;
		}
		optind++;
	}
}

int config_get_option_list(struct cfg_template *t, char ***retval,
			   unsigned int flags)
{
	int count = 0;
	struct cfg_template *ptr;

	if (retval == NULL)
		return 0;
	if (flags == 0)
		flags = ~flags;

	for (ptr = t; ptr->type != CONFIG_TYPE_LAST; ptr++) {
		if (ptr->flags & flags)
			count++;
	}

	if (!count)
		return 0;

	*retval = Malloc(sizeof(char **) * (count + 1));
	(*retval)[count] = NULL;	/* make sure last element is NULL */
	for (ptr = t, count = 0; ptr->type != CONFIG_TYPE_LAST; ptr++) {
		if (ptr->flags & flags) {
			(*retval)[count] = Malloc(strlen(ptr->op.name) + 1);
			strcpy((*retval)[count], ptr->op.name);
			count++;
		}
	}
	return count;
}

void config_cleanup(struct cfg_template *t)
{
	if (t == NULL)
		return;
	while (t->type != CONFIG_TYPE_LAST) {
		if (t->type == CONFIG_TYPE_STRING) {
			free(t->value->s);
			t->value->s = NULL;
		}
		if (t->flags & CONFIG_FLAG_ALLOCATED) {
			free(t->value);
		}
		t++;
	}
}
