/* alock.c -- advisory locking routines
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
 * Start Date: 8/18/93
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "syncdb.h"
#include "alock.h"

/* database name */
static char alockdb[] = "user/%.*s/alock";

/* list of locks held by server */
typedef struct locklist_t {
    struct locklist_t *next;
    char dbname[256];
    char key[1];
} locklist_t;

/* global list of locked items */
static locklist_t *locklist = NULL;

/* lock/unlock an option or address book entry
 *   for option, item1 is option name and item2 is NULL
 *   for address book, item1 is address book and item2 is name
 *   lockflag is 0 for unlock, 1 for lock
 *   host is set to hostname on input and returns user@host if already locked
 *  returns -1 on failure, 0 on success, 1 on already locked/unlocked
 */
int alock_dolock(user, item1, item2, lockflag, host)
    char *user, *item1, *item2, **host;
    int lockflag;
{
    locklist_t *key, *lkey;
    char *s, *value;
    int result, result1, keylenplus;

    /* create the key */
    keylenplus = strlen(item1)
      + (item2 ? strlen(item2) + 1 : 0)
      + strlen(user) + strlen(*host) + 2;
    key = (locklist_t *)
	malloc(sizeof (locklist_t) + keylenplus);
    if (!key) return (-1);
    if (item2) {
	snprintf(key->dbname, sizeof(key->dbname), alockdb,
		(s = strchr(item1, '.')) ? s - item1 : strlen(item1), item1);
	snprintf(key->key, keylenplus, "%s\"%s", item1, item2);
    } else {
	snprintf(key->dbname, sizeof(key->dbname), alockdb, strlen(user), user);
	strcpy(key->key, item1);
    }

    /* look for lock to release */
    if (!lockflag) {
	for (lkey = locklist;
	     lkey && strcasecmp(lkey->key, key->key); lkey = locklist->next);
	if (!lkey) {
	    free((char *) key);
	    return (1);
	}
    }

    /* write-lock database, creating if necessary */
    if ((result = sdb_writelock(key->dbname, key->key, 1)) < 0) {
	/* create db & retry */
	sdb_create(key->dbname);
	result = sdb_writelock(key->dbname, key->key, 1);
    }

    /* change database */
    if (!result) {
	if (lockflag) {
	    if (sdb_get(key->dbname, key->key, 1, &value) == 0 && value) {
		result = 1;
		*host = value;
	    } else {
		value = key->key + strlen(key->key) + 1;
		snprintf(value, keylenplus - strlen(key->key) - 1, "%s@%s", user, *host);
		result = sdb_set(key->dbname, key->key, 1, value);
	    }
	} else {
	    result = sdb_remove(key->dbname, key->key, 1);
	}
    }

    /* unlock it */
    result1 = sdb_unlock(key->dbname, key->key, 1);
    if (!result) result = result1;

    /* remove entries from linked list */
    if (!lockflag || result) free((char *) key);
    if (!result && !lockflag) {
	if (lkey == locklist) {
	    locklist = locklist->next;
	} else {
	    for (key = locklist; key->next != lkey; key = key->next);
	    key->next = lkey->next;
	}
	free((char *)lkey);
    }

    /* add entry to linked list */
    if (lockflag && !result) {
	key->next = locklist;
	locklist = key;
    }

    return (result);
}

/* unlock all active locks
 */
void alock_unlock()
{
    locklist_t *key;

    while (locklist) {
	key = locklist;
	locklist = locklist->next;
	if (sdb_writelock(key->dbname, key->key, 1) == 0) {
	    sdb_remove(key->dbname, key->key, 1);
	    sdb_unlock(key->dbname, key->key, 1);
	}
	free((char *) key);
    }
}
