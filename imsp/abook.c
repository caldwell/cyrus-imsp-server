/* abook.c -- address book routines
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
 * Start Date: 6/28/93
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "xmalloc.h"
#include "util.h"
#include "syncdb.h"
#include "authize.h"
#include "abook.h"
#ifdef HAVE_LDAP
#include "abook_ldap.h"
#endif
#include "acl.h"
#include "option.h" /* for option_doquota() */

/* import from OS: */
extern char *malloc();

/* database names */
static char abooks[] = "abooks";
static char abooksdb[] = "user/%s/abooks";
static char abooksudb[] = "user/%.*s/abooks";
static char abookdb[] = "user/%.*s/abook.%s";

/* generate the database name for an address book
 *  returns -1 for invalid name, otherwise returns length of owner name
 */
static int abook_dbname(char *dbname, int maxout, const char *name)
{
    char *split;
    int len = strlen(name), ownerlen;

    /* catch empty name */
    if (len == 0) return (-1);

    /* disallow trailing "." */
    if (name[len - 1] == '.') return (-1);

    /* look for split to determine ownerlen */
    ownerlen = len;
    if ((split = strchr(name, '.'))) {
	ownerlen = split - name;
    }

    snprintf(dbname, maxout, abookdb, ownerlen, name, name);

    return (ownerlen);
}

/* check an access control list on an address book
 *  returns masked acl bits
 */
static long abook_rights(id, name, acl)
    auth_id *id;
    char *name, *acl;
{
    char dbname[256];
    char *uname;
    int len;
    long mask = 0;

    /* look up the database */
    len = abook_dbname(dbname, sizeof(dbname), name);
    if (len < 0) return (0);
    
    /* get the ACL */
    if (!acl && sdb_get(abooks, name, SDB_ICASE, &acl) < 0) return (0);
    if (acl) mask = acl_myrights(auth_get_state(id), acl);

    /* check for administrator */
    if (auth_level(id) == AUTH_ADMIN) mask |= ACL_ALL;

    /* check ownership */
    uname = auth_username(id);
    if (strlen(uname) == len && !strncasecmp(uname, name, len)) {
	mask |= (ACL_LOOKUP | ACL_ADMIN);
	if (!acl) mask = ACL_ALL;
    }

#ifdef HAVE_LDAP
    /* If this abook is implemented via LDAP lookups,
       turn off all access but READ, LOOKUP and ADMIN.
       Not even admins are allowed any further rights.
       Be sure to leave all the USER bits alone.
    */
    if (mask & ACL_USER1) {
	mask = mask & ((ACL_FULL & ~ACL_ALL) | 
		       ACL_READ | ACL_LOOKUP | ACL_ADMIN);
    }
#endif

    return (mask);
}

/* get ACL for parent db
 */
static long abook_parentacl(id, name, pacl)
    auth_id *id;
    char *name, **pacl;
{
    char dbname[256];
    char *dot, *cname;
    int exists = -1, nlen = 0;
    long mask = 0;

    nlen = strlen(name);
    
    if ((cname = malloc(nlen+1)) == NULL) {
      /* bummer, can't return a failure condition... */
      return 0;
    }
    (void)strcpy(cname, name);

    dot = cname + nlen - 1;
    *pacl = NULL;
    while (dot >= cname && exists < 0) {
	while (dot >= cname && *dot != '.') --dot;
	if (dot >= cname) *dot = '\0';
	sdb_get(abooks, cname, SDB_ICASE, pacl);
	abook_dbname(dbname, sizeof(dbname), cname);
	exists = sdb_check(dbname);
	if (exists == 0) mask = abook_rights(id, cname, *pacl);
        if (dot >= cname) --dot;
    }
    free(cname);
    return (mask);
}

#ifdef HAVE_LDAP
static int abook_usesldap(id, name)
     auth_id *id;
     char *name;
{
    return (abook_rights(id, name, NULL) & ACL_USER1 ? 1 : 0);
}
#endif

/* fetch an address book entry
 *
 * Look up an entry in an address book, returning all of its contents.
 * The address book name is given in "name".
 * "Alias" has the name of the entry being sought.
 * It sends back an array of (field, data) pairs via the return value pointer.
 * Also sets "count" to indicate how many fields were found in the entry.
 *
 * The "state" pointer is used by the internal database routines. When
 * using the sdb routines (instead of LDAP), the field/data array is actually
 * a series of pointers into "state".
 *
 * On error, returns the NULL pointer, resulting in a "No such entry" reply.
 *
 * Otherwise, the caller must call abook_fetchdone() to let it free the memory
 * associated with the returned pointer and the state variable.
 */
abook_fielddata *abook_fetch(state, id, name, alias, count, freedata)
    abook_state *state;
    auth_id *id;
    char *name, *alias;
    int *count;
    int *freedata;
{
    sdb_keyvalue *kv;
    char *pat;
    int kvcount, i, len;
    abook_fielddata *fdata = NULL, *fptr;
    char dbname[256];

    state->kv = NULL;
    *count = 0;
    *freedata = 0;
    if (abook_dbname(dbname, sizeof(dbname), name) < 0) return (NULL);

#ifdef HAVE_LDAP
    if (abook_usesldap(id, name)) {
	/* Lookup using an LDAP server */

	fdata = abook_ldap_fetch(alias, count);
	*freedata = 1;

    } else
#endif
    {
	/* Lookup in an IMSP database file */

	len = strlen(alias) + 1;
	pat = malloc(len + 2);
	if (!pat) return (NULL);
	snprintf(pat, len + 2, "%s\"*", alias);
	if (sdb_match(dbname, pat, SDB_ICASE, NULL, 0, &kv, &kvcount) >= 0
	    && kvcount) {
	    state->kv = kv;
	    state->kvcount = kvcount;
	    fdata = (abook_fielddata *) malloc(sizeof (abook_fielddata) * 
					       kvcount);
	    if (fdata) {
		fptr = fdata;
		for (i = 0; i < kvcount; ++i) {
		    if (!strncasecmp(pat, kv[i].key, len)
			&& kv[i].key[len] != '\0') {
			fptr->field = kv[i].key + len;
			fptr->data = kv[i].value;
			++fptr;
		    }
		}
		*count = fptr - fdata;
	    }
	}
	free(pat);
    }
    return (fdata);
}

/* free storage used by fetch
 */
void abook_fetchdone(state, data, count, freedata)
    abook_state *state;
    abook_fielddata *data;
    int count;
    int freedata;
{
    int i;

    if (data) {
	if (freedata) {
	    for (i = 0; i < count; i++) {
		free(data[i].field);
		free(data[i].data);
	    }
	}
	free(data);
    }
    if (state->kv) 
	sdb_freematch(state->kv, state->kvcount, 0);
    state->kv = NULL;
}

/* check if user has permission to fetch entries for a given address book
 *  returns non-zero if permitted, 0 otherwise
 */
int abook_canfetch(id, name)
    auth_id *id;
    char *name;
{
    return (abook_rights(id, name, NULL) & ACL_READ ? 1 : 0);
}

/* check if user has permission to lock entries for a given address book
 *  returns non-zero if permitted, 0 otherwise
 */
int abook_canlock(id, name)
    auth_id *id;
    char *name;
{
    return (abook_rights(id, name, NULL) & ACL_WRITE ? 1 : 0);
}

/* begin a search in address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_PERM_LIST
 */
int abook_searchstart(state, ldap_state, id, name, flist, fcount)
    abook_state *state;
    void **ldap_state;
    auth_id *id;
    char *name;
    abook_fielddata *flist;
    int fcount;
{
    char dbname[256];
    char *pat, *key;
    sdb_keyvalue *nkv;
    int i, j, result, ncount, cmp, len, kcount;

    *ldap_state = NULL;

    /* check permissions */
    if (!(abook_rights(id, name, NULL) & ACL_READ)) {
	return (AB_PERM);
    }

    /* Impose Joe's permission check for the "All Andrew Users" addr book:
     * If the '0' bit is set, don't allow unqualified searches.
     * This keeps users from "opening" the addr book in Mulberry and Simeon
     * while still letting them "search" for entries and "resolve nicknames".
     */
    if ((abook_rights(id, name, NULL) & ACL_USER0) &&
	(fcount == 0 || ((fcount == 1)
			 && (strcasecmp(flist[0].field, "name") == 0)
			 && (strcmp(flist[0].data, "*") == 0))
	 )) {
	return (AB_PERM_LIST);
    }

#ifdef HAVE_LDAP
    if (abook_usesldap(id, name)) {
	state->kv = NULL;
	/* Compiler warning here because
	 * ldap_state is void **, not the private type used internally by the 
	 * abook_ldap module 
	 */
	if (abook_ldap_searchstart(ldap_state, flist, fcount) < 0)
	    return (AB_FAIL);
	else
	    return (AB_SUCCESS);
    }
#endif

    if (abook_dbname(dbname, sizeof(dbname), name) < 0) return (AB_FAIL);

    /* start match */
    if (!fcount) {
	if (sdb_match(dbname, "*", SDB_ICASE, NULL, 1,
		      &state->kv, &state->kvcount) < 0) {
	    return (AB_FAIL);
	}
    } else {
	state->kv = nkv = NULL;
	/* first look for the "name" field */
	for (i = 0; i < fcount; ++i) {
	    if (!strcasecmp(flist[i].field, "name")) {
	        int patlen = strlen(flist[i].data) + 3;
		pat = malloc(patlen);
		if (!pat) return (AB_FAIL);
		snprintf(pat, patlen, "%s\"*", flist[i].data);
		result = sdb_match(dbname, pat, SDB_ICASE, NULL, 1,
				   &state->kv, &state->kvcount);
		free(pat);
		if (result < 0) return (AB_FAIL);
		if (!state->kvcount) return (AB_SUCCESS);
		break;
	    }
	}
	/* then do other fields */
	while (fcount) {
	    if (strcasecmp(flist->field, "name")) {
	        int patlen = strlen(flist->field) + 3;
		pat = malloc(patlen);
		if (!pat) {
		    if (state->kv) sdb_freematch(state->kv, state->kvcount, 1);
		    state->kv = NULL;
		    return (AB_FAIL);
		}
		snprintf(pat, patlen, "*\"%s", flist->field);
		if (!state->kv) {
		    result = sdb_match(dbname, pat, SDB_ICASE, flist->data, 1,
				       &state->kv, &state->kvcount);
		} else {
		    result = sdb_match(dbname, pat, SDB_ICASE, flist->data, 0,
				       &nkv, &ncount);
		}
		free(pat);
		if (result < 0) {
		    if (state->kv) sdb_freematch(state->kv, state->kvcount, 1);
		    state->kv = NULL;
		    return (AB_FAIL);
		}
		if (!state->kvcount) break;
		if (nkv) {
		    j = 0;
		    kcount = 0;
		    for (i = 0; i < state->kvcount; ++i) {
			if (j == ncount) {
			    *state->kv[i].key = '\0';
			} else if (*(key = state->kv[i].key)) {
			    len = strchr(key, '"') - key + 1;
			    cmp = strncasecmp(key, nkv[j].key, len);
			    while (cmp > 0 && ++j < ncount) {
				cmp = strncasecmp(key, nkv[j].key, len);
			    }
			    if (cmp) *state->kv[i].key = '\0';
			    else ++kcount;
			}
		    }
		    sdb_freematch(nkv, ncount, 0);
		    if (!kcount) break;
		}
	    }
	    --fcount;
	    ++flist;
	}
    }
    state->kvpos = state->kv;
    state->kvlast = NULL;

    return (AB_SUCCESS);
}    

/* get next search element, or NULL
 */
char *abook_search(state, ldap_state)
    abook_state *state;
    void *ldap_state;
{
#ifdef HAVE_LDAP
    if (ldap_state) {
	return (abook_ldap_search(ldap_state));

    } else 
#endif
	if (state->kvcount) {
	while (state->kvpos - state->kv < state->kvcount) {
	    if (*state->kvpos->key) {
		*strchr(state->kvpos->key, '"') = '\0';
		if (!state->kvlast
		    || strcasecmp(state->kvpos->key, state->kvlast)) {
		    return (state->kvlast = state->kvpos++->key);
		}
	    }
	    ++state->kvpos;
	}
    }

    return (NULL);
}

/* finish search: free storage used
 */
void abook_searchdone(state, ldap_state)
    abook_state *state;
    void *ldap_state;
{
    if (state->kv) sdb_freematch(state->kv, state->kvcount, 1);
#ifdef HAVE_LDAP
    if (ldap_state)
	abook_ldap_searchdone(ldap_state);
#endif
    state->kv = NULL;
}


/* create an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_EXIST
 */
int abook_create(id, name)
    auth_id *id;
    char *name;
{
    char dbname[256], acldb[256];
    char *acl = NULL;
    int ownerlen, result = 0;

    /* find abook, and make sure it doesn't exist */
    if ((ownerlen = abook_dbname(dbname, sizeof(dbname), name)) < 0) return (AB_FAIL);
    if (sdb_check(dbname) == 0) return (AB_EXIST);

#if 0
    /* The default address book for the current user always exists */

    /* 10/97 - Well, the addressbook doesn't always exist so someone 
     * may need to create the sucker. So, this section of the code is
     * ifdef'd out. It could be 'bad' protocol wise if this returns an
     * error but it is probably better than giving a non-intuitive error.
     */


    if (!strcasecmp(auth_username(id), name)) {
	return (AB_EXIST);
    }
#endif /* 0 */

    if (auth_level(id) == AUTH_ADMIN)
      goto skip_acl_check;

#ifndef DISABLE_AUTO_CREATE_AB
    if (!strcasecmp(auth_username(id), name)) {
	goto skip_acl_check;
    }
#endif /* DISABLE_AUTO_CREATE_AB */

    /* check create access */
    if (!(abook_parentacl(id, name, &acl) & ACL_CREATE)) {
	return (AB_PERM);
    }

skip_acl_check:
    /* create database */
    if (sdb_create(dbname) < 0) {
	return (AB_FAIL);
    }
    /* add addressbook to global abooks list, if appropriate */
    if (acl && (result = sdb_writelock(abooks, name, SDB_ICASE)) >= 0) {
	result = sdb_set(abooks, name, SDB_ICASE, acl);
	if (sdb_unlock(abooks, name, SDB_ICASE) < 0) result = AB_FAIL;
    }

    /* add addressbook name to personal abooks list */
    snprintf(acldb, sizeof(acldb), abooksudb, ownerlen, name);
    if (sdb_check(acldb) < 0 && sdb_create(acldb) < 0) {
	result = AB_FAIL;
    } else if (!result) {
	if (!(result = sdb_writelock(acldb, name, SDB_ICASE))) {
	    result = sdb_set(acldb, name, SDB_ICASE, "");
	    if (sdb_unlock(acldb, name, SDB_ICASE) < 0) result = AB_FAIL;
	}
	/* clean up on error */
	if (result < 0) {
	    if (sdb_writelock(acldb, name, SDB_ICASE) >= 0) {
		sdb_remove(acldb, name, SDB_ICASE);
		sdb_unlock(acldb, name, SDB_ICASE);
	    }
	}
    }
    if (result < 0) {
	sdb_delete(dbname);
    }

    return (result);
}

/* delete an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_NOEXIST
 */
int abook_delete(id, name)
    auth_id *id;
    char *name;
{
    char dbname[256], uname[256];
    int result, ownerlen;
    int delta, kvcount;
    sdb_keyvalue *kv, *kvpos;
    char *sep, *value;

    /* find abook, and make sure it exists */
    if ((ownerlen = abook_dbname(dbname, sizeof(dbname), name)) < 0) {
	return (AB_FAIL);
    }
    if (ownerlen == strlen(name) && auth_level(id) != AUTH_ADMIN) {
	return (AB_FAIL);
    }
    if (sdb_check(dbname) < 0) return (AB_NOEXIST);

    /* check delete access */
    if (!(abook_rights(id, name, NULL) & ACL_DELETE)) {
	return (AB_PERM);
    }

    /* if we need to adjust the quota, compute the delta */
    delta = 0;
    if (sdb_match(dbname, "*", SDB_ICASE, NULL, 0, &kv, &kvcount) >= 0
	&& kvcount > 0) {
	for (kvpos = kv; kvcount--; ++kvpos) {
	    if (kvpos->value) delta += strlen(kvpos->value);
	    if ((sep = strchr(kvpos->key, '"'))) delta += strlen(sep + 1);
	}
	sdb_freematch(kv, kvcount, 0);
	snprintf(uname, sizeof(uname), "%.*s", ownerlen, name);
    }

    /* remove address book database */
    result = sdb_delete(dbname);
    if (result == AB_SUCCESS) {
	if (delta) option_doquota(uname, -delta);
	    
	/* remove database name from abooks list */
	snprintf(dbname, sizeof(dbname), abooksudb, ownerlen, name);
	if (sdb_writelock(dbname, name, SDB_ICASE) >= 0) {
	    sdb_remove(dbname, name, SDB_ICASE);
	    sdb_unlock(dbname, name, SDB_ICASE);
	    if (sdb_count(dbname, SDB_ICASE) == 0) {
		sdb_delete(dbname);
	    }
	}

	/* if set, remove name from global abooks list */
	if (sdb_get(abooks, name, SDB_ICASE, &value) >= 0 && value != NULL) {
	    if (sdb_writelock(abooks, name, SDB_ICASE) >= 0) {
		sdb_remove(abooks, name, SDB_ICASE);
		sdb_unlock(abooks, name, SDB_ICASE);
	    }
	}
    }

    return (result);
}

/* rename an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_QUOTA, AB_NOEXIST, AB_EXIST
 */
int abook_rename(id, name, newname)
    auth_id *id;
    char *name, *newname;
{
    char dbsrc[256], dbdst[256], uname[256];
    int osrclen, odstlen, default_abook, new_name;
    int delta, kvcount, result;
    sdb_keyvalue *kv, *kvpos;
    char *sep, *value, *tmpacl = NULL;
    char tmpc;

    /* make sure names are valid */
    if (!strcasecmp(name, newname) ||
	(osrclen = abook_dbname(dbsrc, sizeof(dbsrc), name)) < 0 ||
	(odstlen = abook_dbname(dbdst, sizeof(dbdst), newname)) < 0) {
	return (AB_FAIL);
    }
    if (sdb_check(dbsrc) < 0) return (AB_NOEXIST);
    if (sdb_check(dbdst) == 0) return (AB_EXIST);
    default_abook = osrclen == strlen(name);
    new_name = osrclen != odstlen || strncasecmp(name, newname, osrclen);

    /* check permission */
    if (!(abook_rights(id, name, NULL) & ACL_DELETE)
	|| !(abook_rights(id, newname, NULL) & ACL_CREATE)) {
	return (AB_PERM);
    }

    /* if we need to adjust the quota, compute the delta */
    delta = 0;
    if (new_name) {
	if (sdb_match(dbsrc, "*", SDB_ICASE, NULL, 0, &kv, &kvcount) >= 0
	    && kvcount > 0) {
	    for (kvpos = kv; kvcount--; ++kvpos) {
		if (kvpos->value) delta += strlen(kvpos->value);
		if ((sep = strchr(kvpos->key, '"'))) delta += strlen(sep + 1);
	    }
	    sdb_freematch(kv, kvcount, 0);
	}
	snprintf(uname, sizeof(uname), "%.*s", odstlen, newname);
	if ((result = option_doquota(uname, delta)) < 0) {
	    return (result);
	}
    }

    /* copy to new location & delete old location */
    if (sdb_copy(dbsrc, dbdst, SDB_ICASE) < 0) {
	if (delta) option_doquota(uname, -delta);
	return (AB_FAIL);
    }
    if (sdb_delete(dbsrc) == 0 && delta) {
	/* if necessary, adjust down quota for old location */
	snprintf(uname, sizeof(uname), "%.*s", osrclen, name);
	option_doquota(uname, -delta);
    }
    if (default_abook) sdb_create(dbsrc);

    /* update user abooks file */
    if (!default_abook) {
	snprintf(dbsrc, sizeof(dbsrc), abooksudb, osrclen, name);
	if (sdb_writelock(dbsrc, name, SDB_ICASE) >= 0) {
	    sdb_remove(dbsrc, name, SDB_ICASE);
	    sdb_unlock(dbsrc, name, SDB_ICASE);
	}
    }
    snprintf(dbdst, sizeof(dbdst), abooksudb, odstlen, newname);
    if (sdb_check(dbdst) >= 0 || sdb_create(dbdst) >= 0) {
	if (sdb_writelock(dbdst, newname, SDB_ICASE) >= 0) {
	    sdb_set(dbdst, newname, SDB_ICASE, "");
	    sdb_unlock(dbdst, newname, SDB_ICASE);
	}
    }

    /* update global abooks file (ACL) */
    if (sdb_writelock(abooks, newname, SDB_ICASE) >= 0) {
	if (sdb_get(abooks, name, SDB_ICASE, &value) >= 0) {
	    if (value == NULL && new_name) {
		tmpacl = malloc(2);
		if (tmpacl) {
		    strcpy(tmpacl, "\t");
		    tmpc = name[osrclen];
		    name[osrclen] = '\0';
		    acl_set(&tmpacl, name, ACL_MODE_SET, ACL_ALL, NULL, NULL);
		    name[osrclen] = tmpc;
		}
		value = tmpacl;
	    }
	    if (value) {
		sdb_set(abooks, newname, SDB_ICASE, value);
		if (!default_abook
		    && sdb_writelock(abooks, name, SDB_ICASE) >= 0) {
		    sdb_remove(abooks, name, SDB_ICASE);
		    sdb_unlock(abooks, name, SDB_ICASE);
		}
	    }
	    if (tmpacl) free(tmpacl);
	}
	sdb_unlock(abooks, newname, SDB_ICASE);
    }

    return (AB_SUCCESS);
}

/* store a set of fields
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_QUOTA, AB_NOEXIST
 */
int abook_store(id, name, alias, flist, fcount)
    auth_id *id;
    char *name, *alias;
    abook_fielddata *flist;
    int fcount;
{
    char dbname[256], acldb[256], uname[256];
    char *key, *scan, *value;
    int i, result, ownerlen, maxfieldlen, len, keylen;
    long delta;

    if ((ownerlen = abook_dbname(dbname, sizeof(dbname), name)) < 0) return (AB_FAIL);
    snprintf(uname, sizeof(uname), "%.*s", ownerlen, name);

    /* check for invalid characters in alias or field */
    for (scan = alias; *scan && *scan != '*'
	 && *scan != '%' && *scan != '"'; ++scan);
    if (*scan) return (AB_FAIL);
    for (i = 0; i < fcount; ++i) {
	for (scan = flist[i].field;
	     *scan && *scan != '*' && *scan != '?' && *scan != '%'; ++scan);
	if (*scan) return (AB_FAIL);
    }

    /* make sure database exists */
    if (sdb_check(dbname) < 0) {
	if (ownerlen == strlen(name)) {
	    /* create primary address book */
	    if (sdb_create(dbname) < 0) return (AB_FAIL);
	} else {
	    return (AB_NOEXIST);
	}
	/* add addressbook name to personal abooks list */
	snprintf(acldb, sizeof(acldb), abooksudb, ownerlen, name);
	if (sdb_check(acldb) < 0 && sdb_create(acldb) < 0) {
	    result = AB_FAIL;
	} else if (!(result = sdb_writelock(acldb, name, SDB_ICASE))) {
	    result = sdb_set(acldb, name, SDB_ICASE, "");
	    if (sdb_unlock(acldb, name, SDB_ICASE) < 0) result = AB_FAIL;
	}
	if (result < 0) {
	    sdb_delete(dbname);
	    return (AB_FAIL);
	}
    }

    /* check permissions */
    if (!(abook_rights(id, name, NULL) & ACL_WRITE)) {
	return (AB_PERM);
    }

    /* lock database */
    if (sdb_writelock(dbname, NULL, SDB_ICASE) < 0) return (AB_FAIL);

    /* quota & max field length calculation */
    delta = 0;
    maxfieldlen = 0;
    for (i = 0; i < fcount; ++i) {
	if ((len = strlen(flist[i].field)) > maxfieldlen) {
	    maxfieldlen = len;
	}
	if (*flist[i].data) {
	    delta += len + strlen(flist[i].data);
	}
    }
    keylen = maxfieldlen + strlen(alias) + 2;
    if ((key = malloc(keylen)) == NULL) {
	sdb_unlock(dbname, NULL, SDB_ICASE);
	return (AB_FAIL);
    }
    for (i = 0; i < fcount; ++i) {
	snprintf(key, keylen, "%s\"%s", alias, flist[i].field);
	if (sdb_get(dbname, key, SDB_ICASE, &value) == 0 && value != NULL) {
	    delta -= strlen(value) + strlen(flist[i].field);
	}
    }
    if ((result = option_doquota(uname, delta)) < 0) {
        free(key);
	sdb_unlock(dbname, NULL, SDB_ICASE);
	return (result);
    }
    
    /* make changes to database */
    snprintf(key, keylen, "%s\"", alias);
    if (sdb_get(dbname, key, SDB_ICASE, &value) < 0 || value == NULL) {
	sdb_set(dbname, key, SDB_ICASE, "");
    }
    for (i = 0; i < fcount; ++i) {
	snprintf(key, keylen, "%s\"%s", alias, flist[i].field);
	if (*flist[i].data) {
	    sdb_set(dbname, key, SDB_ICASE, flist[i].data);
	} else {
	    sdb_remove(dbname, key, SDB_ICASE);
	}
    }
    free(key);

    /* if changes failed, back out quota change */
    if ((result = sdb_unlock(dbname, NULL, SDB_ICASE)) < 0) {
	option_doquota(uname, -delta);
    }

    return (result);
}

/* delete an entry
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_NOEXIST
 */
int abook_deleteent(id, name, alias)
    auth_id *id;
    char *name, *alias;
{
    char *key, *scan;
    sdb_keyvalue *kv;
    int i, result, kvcount, ownerlen, keylen;
    long delta;
    char dbname[256];

    /* check permissions */
    if (!(abook_rights(id, name, NULL) & ACL_DELETE)) {
	return (AB_PERM);
    }

    if ((ownerlen = abook_dbname(dbname, sizeof(dbname), name)) < 0) return (AB_FAIL);

    /* check for invalid characters in alias */
    for (scan = alias; *scan && *scan != '*' && *scan != '%'; ++scan);
    if (*scan) return (AB_FAIL);

    /* lock database */
    if (sdb_writelock(dbname, NULL, SDB_ICASE) < 0) return (AB_FAIL);

    /* find entries for key */
    keylen = strlen(alias) + 3;
    key = malloc(keylen);
    if (!key) {
	sdb_unlock(dbname, NULL, SDB_ICASE);
	return (AB_FAIL);
    }
    snprintf(key, keylen, "%s\"*", alias);
    result = sdb_match(dbname, key, SDB_ICASE, NULL, 1, &kv, &kvcount);
    free(key);
    if (result < 0 || !kvcount) {
	sdb_unlock(dbname, NULL, SDB_ICASE);
	return (result < 0 ? AB_FAIL : AB_NOEXIST);
    }

    /* quota check */
    delta = (strlen(alias) + 1) * kvcount;
    for (i = 0; i < kvcount; ++i) {
	delta -= strlen(kv[i].key) + strlen(kv[i].value);
    }
    if ((result = option_doquota(auth_username(id), delta)) < 0) {
	sdb_unlock(dbname, NULL, SDB_ICASE);
	return (result);
    }

    /* nuke the entries */
    for (i = 0; i < kvcount; ++i) {
	sdb_remove(dbname, kv[i].key, SDB_ICASE);
    }
    sdb_freematch(kv, kvcount, 0);

    /* unlock */
    if (sdb_unlock(dbname, NULL, SDB_ICASE) < 0) {
	option_doquota(auth_username(id), -delta);
	return (AB_FAIL);
    }
    
    return (AB_SUCCESS);
}

/* set an access control list
 *  rights is NULL to delete an entry: returns 1 if entry doesn't exist
 *  AB_FAIL, AB_NOEXIST, AB_PERM
 */
int abook_setacl(id, name, ident, rights)
    auth_id *id;
    char *name, *ident, *rights;
{
    char dbname[256];
    char *value, *acl, tmpc;
    int ownerlen, result = AB_FAIL;

    /* check permissions */
    if (!(abook_rights(id, name, NULL) & ACL_ADMIN)) {
	return (AB_PERM);
    }

    /* make sure db exists */
    if ((ownerlen = abook_dbname(dbname, sizeof(dbname), name)) < 0) return (AB_FAIL);
    if (sdb_check(dbname) < 0) return (AB_NOEXIST);

    /* lock acl db */
    if (sdb_writelock(abooks, name, SDB_ICASE) < 0) {
	return (AB_FAIL);
    }
    
    /* check for acl */
    if (sdb_get(abooks, name, SDB_ICASE, &value) >= 0) {
	/* if no ACL, create one */
	if (value == NULL) {
	    /* create default acl */
	    acl = malloc(2);
	    if (acl) {
		strcpy(acl, "\t");
		tmpc = name[ownerlen];
		name[ownerlen] = '\0';
		acl_set(&acl, name, ACL_MODE_SET, ACL_ALL, NULL, NULL);
		name[ownerlen] = tmpc;
	    }
	} else {
	    /* copy acl */
	    acl = strdup(value);
	}
	/* update acl */
	if (acl
	    && acl_set(&acl, ident, ACL_MODE_SET, 
		       rights ? acl_strtomask(rights) : 0L, 
		       NULL, NULL) == 0) {
	    if (sdb_set(abooks, name, SDB_ICASE, acl) == 0) {
		result = AB_SUCCESS;
	    }
	}
    }

    /* unlock db */
    if (sdb_unlock(abooks, name, SDB_ICASE) < 0) result = AB_FAIL;
    if (acl) free(acl);
    
    return (result);
}

/* return myrights for address book
 *  rights must be ACL_MAXSTR
 *  returns 0 for success
 */
int abook_myrights(id, name, rights)
    auth_id *id;
    char *name, *rights;
{
    /* some more error checking might be in order... */
    acl_masktostr(abook_rights(id, name, NULL), rights);

    return (AB_SUCCESS);
}

/* return acl string
 */
char *abook_getacl(id, name)
    auth_id *id;
    char *name;
{
    char dbname[256];
    char *acl;
    
    /* look up the database */
    if (abook_dbname(dbname, sizeof(dbname), name) < 0) return (NULL);

    /* make sure db exists */
    if (sdb_check(dbname) < 0) return (NULL);
    
    /* check rights */
    if (!(abook_rights(id, name, NULL) & ACL_LOOKUP)) return (NULL);

    /* check acl */
    if (sdb_get(abooks, name, SDB_ICASE, &acl) < 0) return (NULL);
    if (acl == NULL) acl = "";

    return (acl);
}

/* start finding address books
 */
int abook_findstart(state, id, pat)
    abook_state *state;
    auth_id *id;
    char *pat;
{
    char dbname[256];
    int pkvcount;
    
    state->kv = state->pkv = NULL;
    if (sdb_match(abooks, pat, 0, NULL, 0, &state->kv, &state->kvcount) < 0) {
	return (AB_FAIL);
    }
    state->kvend = state->kv + state->kvcount;
    state->kvpos = state->kv;
    snprintf(dbname, sizeof(dbname), abooksdb, auth_username(id));
    sdb_match(dbname, pat, 0, NULL, 0, &state->pkv, &pkvcount);
    if (state->pkv) {
	state->kvend = state->pkv + pkvcount;
	state->kvpos = state->pkv;
    }

    return (AB_SUCCESS);
}

/* return next address book found
 *  abook is set to address book name
 *  attrs is set to address book attributes
 *  returns NULL or address book name
 */
char *abook_find(state, id, abook, attrs)
    abook_state *state;
    auth_id *id;
    char **abook;
    int *attrs;
{
    char *user, *key;
    int result = 0, ulen;

    user = auth_username(id);
    ulen = strlen(user);
    do {
	if (!state->kvpos) return (NULL);
	if (state->kvpos < state->kvend) {
	    key = state->kvpos->key;
	    if (state->pkv || strncmp(user, key, ulen)
		|| (key[ulen] != '.' && key[ulen] != '\0')) {
		result = abook_rights(id, state->kvpos->key, NULL)&ACL_LOOKUP;
		*abook = state->kvpos->key;
		*attrs = 0;
	    }
	}
	if (++state->kvpos >= state->kvend) {
	    state->kvpos = NULL;
	    if (state->pkv) {
		sdb_freematch(state->pkv, state->kvend - state->pkv, 0);
		state->pkv = NULL;
		state->kvpos = state->kv;
		state->kvend = state->kv + state->kvcount;
	    }
	}
    } while (!result);

    return (*abook);
}

/* finish finding address books
 */
void abook_finddone(state)
    abook_state *state;
{
    if (state->pkv) {
	sdb_freematch(state->pkv, state->kvend - state->pkv, 0);
    }
    if (state->kv) {
	sdb_freematch(state->kv, state->kvcount, 0);
    }
    state->kvpos = state->kv = state->pkv = NULL;
}
