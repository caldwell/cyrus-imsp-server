#ifndef __abook_h
#define __abook_h

/* abook.h -- definitions for address book routines
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

#include "authize.h"
#include "syncdb.h"

/* return values */
#define AB_SUCCESS  0		/* general success */
#define AB_FAIL    -1		/* general failure */
#define AB_PERM    -2		/* permission failure */
#define AB_QUOTA   -3		/* quota overflow */
#define AB_NOEXIST -4		/* object doesn't exist */
#define AB_EXIST   -5		/* item already exists on create */
#define AB_PERM_LIST -6 	/* not allowed to list all entries */

/* field/data pairs for an address book entry */
typedef struct abook_fielddata {
    char *field;
    char *data;
} abook_fielddata;

/* address book state holder */
typedef struct abook_state {
    /* all fields are private to abook module: */
    sdb_keyvalue *kv, *kvpos, *kvend, *pkv;
    char *kvlast, *kvrights, *kvowner;
    int kvcount;
} abook_state;

#ifdef __STDC__
/*  abook_fetch(state, id, name, alias, count, freedata)
 * fetch an address book entry
 *  state:  pointer to existing abook_state structure
 */
abook_fielddata *abook_fetch(abook_state *, auth_id *, char *, char *, 
			     int *, int*);

/*  abook_fetchdone(state, data, count, freedata)
 * free storage used by fetch
 */
void abook_fetchdone(abook_state *, abook_fielddata *, int, int);

/*  abook_canfetch(id, name)
 * check if user can fetch entries for a given name
 *  returns 1 if permitted, 0 otherwise
 */
int abook_canfetch(auth_id *, char *);

/*  abook_canlock(id, name)
 * check if user has permission to lock entries for a given address book
 *  returns non-zero if permitted, 0 otherwise
 */
int abook_canlock(auth_id *, char *);

/*  abook_searchstart(state, ldap_state, id, name, flist, fcount)
 * begin a search in address book
 *  state  must point to a valid abook_state variable
 *  ldap_state if non-NULL, stores an LDAP context for the LDAP search
 *  id     indicates the authorization
 *  name   address book name
 *  flist  list of fields and patterns to look for in that field
 *  fcount number of fields of interest (may be 0)
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM
 */
int abook_searchstart(abook_state *, void **, auth_id *, char *,
		      abook_fielddata *, int);

/*  abook_search(state, ldap_state)
 * get next search element, or NULL
 *  abook_searchstart must have been called on "state" already
 */
char *abook_search(abook_state *, void *);

/*  abook_searchdone(state, ldap_state);
 * finish search: free storage used
 */
void abook_searchdone(abook_state *, void *);

/*  abook_create(id, name);
 * create an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_EXIST
 */
int abook_create(auth_id *, char *);

/*  abook_delete(id, name)
 * delete an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_NOEXIST
 */
int abook_delete(auth_id *, char *);

/*  abook_rename(id, oldname, newname)
 * rename an address book
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_NOEXIST, AB_EXIST
 */
int abook_rename(auth_id *, char *, char *);

/*  abook_store(id, name, alias, flist, fcount);
 * store a set of fields
 *  returns: AB_SUCCESS, AB_FAIL, AB_PERM, AB_QUOTA, AB_NOEXIST
 */
int abook_store(auth_id *, char *, char *,
		abook_fielddata *, int);

/*  abook_deleteent(id, name, alias)
 * delete an entry
 *  -1 for failure, -2 for permission denied, 1 for key doesn't exist
 */
int abook_deleteent(auth_id *, char *, char *);

/*  abook_setacl(id, name, ident, rights)
 * set an access control list
 *  rights is NULL to delete an entry: returns 1 if entry doesn't exist
 *  -1 for failure, -2 for permission denied, 0 for success
 */
int abook_setacl(auth_id *, char *, char *, char *);

/*  abook_myrights(id, name, rights)
 * return myrights for address book
 *  rights must have minimum length of ACL_MAXSTR
 *  returns -2 for permission denied, -1 for failure, 0 for success
 */
int abook_myrights(auth_id *, char *, char *);

/*  abook_getacl(id, name)
 * return acl for address book
 *  NULL = error
 *  "" = default ACL
 */
char *abook_getacl(auth_id *, char *);

/*  abook_findstart(state, id, pat)
 * start finding address books
 */
int abook_findstart(abook_state *, auth_id *, char *);

/*  abook_find(state, id, abook, attrs)
 * return next address book found
 *  abook is set to address book name
 *  attrs is set to address book attributes
 *  returns NULL or address book name
 */
char *abook_find(abook_state *, auth_id *, char **, int *);

/* finish finding address books
 */
void abook_finddone(abook_state *);
#else
abook_fielddata *abook_fetch();
void abook_fetchdone(), abook_searchdone(), abook_finddone();
int abook_canfetch(), abook_canlock(), abook_searchstart(), abook_create();
int abook_delete(), abook_rename(), abook_store(), abook_deleteent();
int abook_setacl(), abook_myrights(), abook_findstart();
char *abook_search(), *abook_getacl(), *abook_find();
#endif

#endif /* __abook_h */
