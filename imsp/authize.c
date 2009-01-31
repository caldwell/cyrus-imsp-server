/* authize.c -- authorization module for IMSP
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
#include "util.h"
#include "acl.h"
#include "syncdb.h"
#include "option.h"
#include "auth.h"
#include "authize.h"

/* from OS: */
extern char *malloc(), *realloc();
extern char *crypt();

/* name of anonymous user */
static char anonymous[] = "anonymous";

/* standard options for setting authentication levels */
char opt_alladmin[]  = "imsp.admin.all"; /* needed by sasl_support.c */

/* standard error messages */
static char err_nomem[] = "Not enough memory to log in";

/* Generate an auth_id from a user name
 * This routine no longer does password validation, so the caller must
 * only use this routine after a successful authentication.
 *  "idptr" is set to the new IMSP authentication structure
 *  "user" is the IMSP login name, and points to a dynamically allocated
 *               string which may be freed by the caller.
 *  "reply" is set to a success or failure message to be sent to the user
 *               (may not contain CR or LF characters)
 *  Returns -1 for malloc failures, otherwise 0 for success
 */
int
auth_login(auth_id **idptr, const char *user,
	   char *olduser, const char **reply)
{
    auth_id *id = *idptr;
    char *rptr;
    static char replybuf[256];

    /* Make space for auth_id if this is the first authentication 
     * of the session */
    if (!id) {
	*idptr = id = (auth_id *) malloc(sizeof (auth_id));
	if (!id) {
	    *reply = err_nomem;
	    return -1;
	}
	id->level = AUTH_NONE;
	strncpy(id->user, anonymous, sizeof(id->user));
	id->state = NULL;
    }

    /* copy in the user-id */
    strcpy(id->user, user);

    /* construct the reply to be sent back to the user */
    if (olduser) {
	/* Write a reply that mentions the switch-user operation */
	strcpy(replybuf, "Administrator switch from user `");
	rptr = beautify_copy(replybuf + strlen(replybuf), olduser);
	strcpy(rptr, "' to user `");
	rptr = beautify_copy(replybuf + strlen(replybuf), user);
	strcpy(rptr, "' successful.");
    } else {
	strcpy(replybuf, "User `");
	rptr = beautify_copy(replybuf + strlen(replybuf), user);
	strcpy(rptr, "' Logged in");
    }
    *reply = replybuf;

    /* determine the authorization level */
    id->level = AUTH_USER;
    if (option_lookup("", opt_alladmin, 1, id->user)) {
	id->level = AUTH_ADMIN;
    }

    /* Get an authentication state from the libcyrus "auth" module
     * (not to be confused the the IMSP authize module in this file).
     * This is needed for acl_myrights(). 
     * Free id->state in case this isn't the first authentication this session.
     */
    if (id->state)
	auth_freestate(id->state);
    id->state = auth_newstate(user, NULL);

    return 0;
}

/*
 * Decide whether the current user (as set in "id") is allowed to 
 * "switch-user" to become an alternate user (specified in "user").
 *
 * If the current id is an administrator,
 *   "id" is untouched,
 *   "reply" is set to a success message
 *   1 is returned.
 * Otherwise, 
 *   "id" and "reply" is left alone
 *   0 is returned.
 */
int
auth_switchuser(auth_id *id, char *user, char **olduser)
{
    int retval = 0;

    *olduser = NULL;

    /* Have we authenticated yet and are we an administrator? */
    if(id && (id->level == AUTH_ADMIN))
    {
	*olduser = strdup(auth_username(id));
	retval = 1;
    }
    return retval;
}

/* this frees any resources used by an auth_id, it must zero out passwords
 *  and will be called before the program exits.  If the argument is NULL,
 *  no action should be taken.
 */
void
auth_free(auth_id *id)
{
    if (id) {
	if (id->state)
	    auth_freestate(id->state);
	free((char *)id);
    }
}

/*
 * Return the libcyrus authentication state from the given authorization state
 */
struct auth_state *
auth_get_state(id)
     auth_id *id;
{
    return (id ? id->state : NULL);
}

/* Return the user name of an identity.  The user name is used to identify
 * the appropriate mailboxes/bb-subscriptions/options/address-book/etc to
 * use.  It is also used for error messages.  The string may not be longer
 * than AUTH_USERMAX.
 * If "id" is NULL, this should return a string representing an anonymous user.
 */
char *
auth_username(auth_id *id)
{
    return (id ? id->user : anonymous);
}

/* return the access level for a given id
 */
int
auth_level(auth_id *id)
{
    return (id ? id->level : AUTH_NONE);
}

