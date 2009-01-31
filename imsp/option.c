/* option.c -- IMSP option routines
 *
 * Copyright (c) 1993-2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: Chris Newman <chrisn+@cmu.edu>
 * Start Date: 4/6/93
 *
 * Might want to make magicopt return malloc()'d string for variable width
 * magic options.
 */

#include <config.h>
#include <stdio.h>
#include <ctype.h>
#include "util.h"
#include "syncdb.h"
#include "option.h"

#include "glob.h"

/* from adate.c: */
extern char *n_arpadate();

/* from OS: */
extern char *malloc(), *realloc();

/* various strings */
static char options[] = "options";
static char optiondb[] = "user/%s/options";

/* predefined options used */
static char opt_quota[] = "imsp.user.quota";
static char opt_usage[] = "imsp.user.quota.usage";
static char opt_date[] = "common.date";
static char opt_domain[] = "common.domain";
static char opt_from[] = "common.from";

/* magic options
 */
static char *magicopt(name, val, user)
    char *name, *val, *user;
{
    char *tmp;
    static char magicbuf[256];
    
    if (*val == '\0') {
	if (!strcasecmp(name, opt_date)) {
	    return (n_arpadate());
	}
	if (!strcasecmp(name, opt_from) && *user) {
	    tmp = option_get("", opt_domain, 1, NULL);
	    *magicbuf = '\0';
	    if (tmp != NULL) {
		snprintf(magicbuf, sizeof(magicbuf), "%s@%s", user, tmp);
		free(tmp);
	    }
	    return (magicbuf);
	}
    } else if (!strcasecmp(name, opt_usage)) {
	snprintf(magicbuf, sizeof(magicbuf), "%ld", (long) ((atol(val) + 1023) / 1024));

	return (magicbuf);
    }

    return (val);
}

/* make sure user has options database
 *  returns 0 if database exists, -1 on failure
 */
int option_check(user)
    char *user;
{
    char dbname[256];

    snprintf(dbname, sizeof(dbname), optiondb, user);

    return (sdb_check(dbname));
}

/* create new user options database
 *  returns -1 on failure
 */
int option_create(user)
    char *user;
{
    char dbname[256];

    snprintf(dbname, sizeof(dbname), optiondb, user);
    
    return (sdb_create(dbname));
}

/* begin a match
 */
int option_matchstart(state, user, pat)
    option_state *state;
    char *user, *pat;
{
    int result;
    char dbname[256];

    /* read user options database if user isn't the empty string */
    state->ukv = (sdb_keyvalue *) NULL;
    state->ucount = 0;
    if (*user) {
	snprintf(dbname, sizeof(dbname), optiondb, user);
	result = sdb_match(dbname, pat, SDB_ICASE, NULL, 0,
			   &state->ukv, &state->ucount);
    }
    if (*user && result < 0) {
	state->ucount = state->gcount = 0;
	state->gkv = state->ukv = (sdb_keyvalue *) NULL;
	return (-1);
    } else {
	/* read global options database
	 * set copy flag due to magic options
	 */
	result = sdb_match(options, pat, SDB_ICASE, NULL, 1,
			   &state->gkv, &state->gcount);
	if (result < 0) {
	    sdb_freematch(state->ukv, state->ucount, 0);
	    state->ucount = state->gcount = 0;
	    state->gkv = state->ukv = (sdb_keyvalue *) NULL;
	    return (-1);
	}
    }
    state->ukvpos = state->ukv;
    state->gkvpos = state->gkv;
    state->utotal = state->ucount;
    state->gtotal = state->gcount;
    state->buflen = 0;
    state->buf = (char *) NULL;

    return (0);
}

/* get the next match
 *  returns *name, or NULL
 *  *name could vanish if any other db calls are made
 *  if admin is non-zero, then administrator options should be shown
 */
char *option_match(state, user, name, value, rwflag, admin)
    option_state *state;
    char *user;
    char **name, **value;
    int *rwflag;
    int admin;
{
    int cmp;
    char *val;

    /* NOTE: assume gkv & ukv arrays are sorted from lowest to highest */
    do {
	/* find the smallest key */
	if (state->gcount) {
	    cmp = -1;
	    if (state->ucount) {
		cmp = strcasecmp(state->gkvpos->key, state->ukvpos->key);
	    }
	} else if (state->ucount) {
	    cmp = 1;
	} else {
	    return (NULL);
	}

	/* grab the argument */
	if (cmp == 0) {
	    *name = state->ukvpos->key;
	    val = state->ukvpos->value;
	    ++state->ukvpos, ++state->gkvpos;
	    --state->gcount, --state->ucount;
	} else if (cmp > 0) {
	    *name = state->ukvpos->key;
	    val = state->ukvpos->value;
	    ++state->ukvpos, --state->ucount;
	} else {
	    *name = state->gkvpos->key;
	    val = state->gkvpos->value;
	    ++state->gkvpos, --state->gcount;
	}
    } while (*val == 'N' && !admin);

    /* set read/write flag */
    *rwflag = (*val == 'W');
    val += 2;

    /* handle "magic" options */
    val = magicopt(*name, val, user);

    /* make space for option value */
    if (state->buflen < strlen(val) + 1) {
	if (!state->buflen) {
	    state->buflen = strlen(val) + 1;
	    state->buf = malloc(state->buflen);
	} else {
	    state->buflen = strlen(val) + 1;
	    state->buf = realloc(state->buf, state->buflen);
	}
	if (state->buf == NULL) {
	    return (NULL);
	}
    }

    /* copy option value */
    strcpy(state->buf, val);
    *value = state->buf;

    return (*name);
}

/* finish option matching
 */
void option_matchdone(state)
    option_state *state;
{
    if (state->buf) free(state->buf);
    if (state->gkv) sdb_freematch(state->gkv, state->gtotal, 1);
    if (state->ukv) sdb_freematch(state->ukv, state->utotal, 0);
    state->buf = NULL;
    state->gkv = state->ukv = NULL;
}

/* get an option
 *  if admin is set then non-visible options will work
 *  returns NULL for no entry
 *  caller must free the result
 */
char *option_get(user, opt, admin, rwflag)
    char *user, *opt;
    int admin;
    int *rwflag;
{
    char *result, *value;
    char dbname[256];

    /* initialize results */
    value = result = NULL;
    
    /* check user options database if user isn't the empty string */
    if (*user) {
	snprintf(dbname, sizeof(dbname), optiondb, user);
	if (sdb_get(dbname, opt, SDB_ICASE, &value) < 0) return (NULL);
    }
    /* check global options */
    if (value == NULL && sdb_get(options, opt, SDB_ICASE, &value) < 0) {
	return (NULL);
    }

    /* check for "non-visible" options */
    if (value && *value == 'N' && !admin) value = NULL;

    /* set rwflag */
    if (rwflag && value) *rwflag = *value == 'W';
    
    /* check for "magic" options */
    if (value) {
	value += 2;
	value = magicopt(opt, value, user);
    }

    /* allocate space for result if necessary */
    if (value) {
	result = malloc(strlen(value) + 1);
	if (result != NULL) {
	    /* copy option value */
	    strcpy(result, value);
	}
    }
    
    return (result);
}

/* test if an option is "on"
 * like option_get, but parses boolean & returns dflt if option is not set.
 */
int option_test(user, opt, admin, dflt)
    char *user, *opt;
    int admin, dflt;
{
    char *value;
    char dbname[256];

    /* initialize result */
    value = NULL;
    
    /* check user options database if user isn't the empty string */
    if (*user) {
	snprintf(dbname, sizeof(dbname), optiondb, user);
	if (sdb_get(dbname, opt, SDB_ICASE, &value) < 0) return (NULL);
    }
    /* check global options */
    if (value == NULL && sdb_get(options, opt, SDB_ICASE, &value) < 0) {
	return (NULL);
    }

    /* check for "non-visible" options */
    if (value && *value == 'N' && !admin) value = NULL;

    /* check for "magic" options */
    if (value) value = magicopt(opt, value, user);

    return (value ? value[2] == '+' : dflt);
}

/* get a list option
 */
option_list *option_getlist(user, opt, admin)
    char *user, *opt;
    int admin;
{
    option_list *result;
    char *data, *scan, **ptr;
    int count = 0, c;

    /* get option */
    scan = data = option_get(user, opt, admin, NULL);
    if (!data) return (NULL);

    /* count entries in list */
    if (*scan != '(') {
	free(data);
	return (NULL);
    }
    ++scan;
    while (isspace(*scan)) ++scan;
    while (*scan && *scan != ')') {
	++count;
	while (*scan && *scan != ')' && !isspace(*scan)) ++scan;
	while (isspace(*scan)) ++scan;
    }

    /* make space for list */
    result = (option_list *)
	malloc(sizeof (option_list) + sizeof (char *) * count);
    if (result == NULL) {
	free(data);
	return (NULL);
    }

    /* parse the list */
    ptr = result->item;
    result->count = count;
    result->data = data;
    scan = data + 1;
    while (isspace(*scan)) ++scan;
    c = *scan;
    while (c && c != ')') {
	++count;
	*ptr++ = scan;
	while (*scan && *scan != ')' && !isspace(*scan)) ++scan;
	c = *scan;
	*scan++ = '\0';
	if (c && c != ')') {
	    while (isspace(*scan)) ++scan;
	    c = *scan;
	}
    }
    *ptr = NULL;

    return (result);
}

/* free results of option_getlist
 */
void option_freelist(olist)
    option_list *olist;
{
    free(olist->data);
    free((char *) olist);
}

/* check if a string is in a list
 * returns 0 if not in list or error, 1 if in list
 */
int option_lookup(user, opt, admin, str)
    char *user, *opt;
    int admin;
    char *str;
{
    option_list *olist;
    char **pptr;
    int result = 0;

    olist = option_getlist(user, opt, admin);
    if (olist != NULL) {
	if (olist->count) {
	    pptr = olist->item;
	    while (*pptr != NULL && strcasecmp(str, *pptr)) ++pptr;
	    if (*pptr) result = 1;
	}
	free(olist->data);
	free((char *) olist);
    }

    return (result);
}

/* check/update user quota usage
 *  delta -- change in usage (in bytes)
 *  returns -1 on db error, -3 on quota overflow, 0 on success
 *  NOTE: will never return -3 if delta is negative.
 */
int option_doquota(user, delta)
    char *user;
    long delta;
{
    char *value;
    long usage, quota;
    int result;
    char dbname[256];
    char usagestr[64];

    /* if there's no change, don't worry about it */
    if (!delta) return (0);
    
    /* set database & get usage */
    snprintf(dbname, sizeof(dbname), optiondb, user);
    if (sdb_get(dbname, opt_usage, SDB_ICASE, &value) < 0) {
	if (sdb_create(dbname) < 0 ||
	    sdb_get(dbname, opt_usage, SDB_ICASE, &value) < 0) {
	    return (-1);
	}
    }

    /* calculate the usage */
    usage = delta;
    if (value && *value) usage += atol(value + 1);
    if (usage < 0) usage = 0;
    snprintf(usagestr, sizeof(usagestr), "R %ld", usage);

    /* check quota if delta > 0 */
    if (delta > 0) {
	/* get the quota */
	quota = 0;
	if (sdb_get(dbname, opt_quota, SDB_ICASE, &value) < 0
	    || (!value && sdb_get(options, opt_quota, SDB_ICASE, &value) < 0)) {
	    return (-1);
	}
	if (value && *value) quota = atol(value + 1) * 1024L;
	if (quota && quota < usage) return (-3);
    }

    /* change usage in database */
    result = 0;
    if (sdb_writelock(dbname, opt_usage, SDB_ICASE) < 0) return (-1);
    result = sdb_set(dbname, opt_usage, SDB_ICASE, usagestr);
    if (sdb_unlock(dbname, opt_usage, SDB_ICASE) < 0) result = -1;

    return (result);
}

/* set an option
 *  returns -1 on failure, -3 on over quota
 */
int option_set(user, opt, admin, value)
    char *user, *opt;
    int admin;
    char *value;
{
    int globflag = 0, type = 0, result;
    long delta;
    char *scan, *newval, *oldval;
    char dbname[256];

    /* set database */
    snprintf(dbname, sizeof(dbname), optiondb, user);
    
    /* check for administrator features */
    if (admin) {
	/* check for global-option prefix */
	if (*opt == '*') {
	    globflag = 1;
	    strcpy(dbname, options);
	    ++opt;
	}
	/* check for read-only/non-visible prefix */
	if (*opt == '%') {
	    ++type;
	    if (*++opt == '%') {
		++type, ++opt;
	    }
	}
    }
    /* make sure there are no other special characters */
    for (scan = opt; *scan; ++scan) {
	if (*scan == '*' || *scan == '%') return (-1);
    }
    if (!strcasecmp(opt, opt_usage)) return (-1);

    /* lock the entry */
    if (sdb_writelock(dbname, opt, SDB_ICASE) < 0) return (-1);

    /* check if user is permitted to make change */
    if (sdb_get(dbname, opt, SDB_ICASE, &oldval) == 0) {
        if (oldval == NULL)
	    sdb_get(options, opt, SDB_ICASE, &oldval);

	/* option exists so check to make sure it is writable */
	if ((admin == 0) && (oldval != NULL) && (*oldval != 'W')) {
	    sdb_unlock(dbname, opt, SDB_ICASE);
	    return (-1);
	}
    }

    /* make space for new option */
    newval = malloc(strlen(value) + 3);
    if (newval == NULL) {
	sdb_unlock(dbname, opt, SDB_ICASE);
	return (-1);
    }

    /* adjust quota: only read-write user options count against quota */
    if (!globflag) {
	delta = 0;
	if (oldval && *oldval == 'W') delta = 2 - strlen(oldval) - strlen(opt);
	if (!type) delta += strlen(opt) + strlen(value);
	if ((result = option_doquota(user, delta)) < 0) {
	    free(newval);
	    sdb_unlock(dbname, opt, SDB_ICASE);
	    return (result);
	}
    }

    /* set type & copy new option */
    *newval = "WRN"[type];
    newval[1] = ' ';
    strcpy(newval + 2, value);

    /* add new option to database */
    result = sdb_set(dbname, opt, SDB_ICASE, newval);
    if (sdb_unlock(dbname, opt, SDB_ICASE) < 0) result = -1;
    free(newval);

    /* if we had an error, undo quota adjustment */
    if (result < 0) option_doquota(user, -delta);

    return (result);
}

/* unset an option
 *  returns -1 on error, 0 if option was not set, 1 if option was unset
 */
int option_unset(user, opt, admin)
    char *user, *opt;
    int admin;
{
    int globflag = 0, type = 0, result;
    char *scan, *oldval;
    char dbname[256];

    /* set database */
    snprintf(dbname, sizeof(dbname), optiondb, user);
    
    /* check for administrator features */
    if (admin) {
	/* check for global-option prefix */
	if (*opt == '*') {
	    globflag = 1;
	    strcpy(dbname, options);
	    ++opt;
	}
	/* check for read-only/non-visible prefix */
	if (*opt == '%') {
	    ++type;
	    if (*++opt == '%') {
		++type, ++opt;
	    }
	}
    }
    /* make sure there are no other special characters */
    for (scan = opt; *scan; ++scan) {
	if (*scan == '*' || *scan == '%') return (-1);
    }

    /* lock the entry */
    if (sdb_writelock(dbname, opt, SDB_ICASE) < 0) return (-1);

    /* check if user is allowed to unset the option */
    if ((sdb_get(dbname, opt, SDB_ICASE, &oldval) < 0) ||
	((admin == 0) && (oldval != NULL) && (*oldval != 'W'))) {
	sdb_unlock(dbname, opt, SDB_ICASE);
	return (-1);
    }

    /* adjust the quota usage */
    if (oldval != NULL) {
	if (option_doquota(user, 2 - strlen(oldval) - strlen(opt)) < 0) {
	    sdb_unlock(dbname, opt, SDB_ICASE);
	    return (-1);
	}
    }

    /* remove it */
    result = sdb_remove(dbname, opt, SDB_ICASE) < 0 ? 0 : 1;

    /* unlock the entry */
    if (sdb_unlock(dbname, opt, SDB_ICASE) < 0) result = -1;

    return (result);
}
