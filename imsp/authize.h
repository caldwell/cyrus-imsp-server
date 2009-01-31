#ifndef __authize_h
#define __authize_h
/* authize.h -- definitions for authorization API
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

#include "auth.h"	/* for struct auth_state */

/* maximum length for a user name */
#define AUTH_USERMAX 63

/* the option we keep administrators in */
extern char opt_alladmin[];

/* levels of authentication
 *  AUTH_NONE
 *    This is for an anonymous user, who is permitted to locate bboards, and
 *    view the values of global options.
 *  AUTH_SUBS
 *    This is for a user who may switch to any user to view their
 *    subscriptions, but may not change anything.
 *  AUTH_USER
 *    This is standard authentication, giving user access to their own
 *    options, subscriptions, address book, etc.
 *  AUTH_BB
 *    This allows the user to freely manipulate bboards.
 *  AUTH_ADMIN
 *    This allows the user full access to everything.
 */
#define AUTH_NONE  0
#define AUTH_SUBS  1
#define AUTH_USER  2
#define AUTH_BB    3
#define AUTH_ADMIN 4

/* The contents of this structure must not be accessed outside of the
 * auth_ module.  It may be variable sized.
 */
typedef struct auth_id {
    int level;
    char user[AUTH_USERMAX];
    struct auth_state *state;
} auth_id;

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
int auth_login(auth_id **idptr, const char *user,
	       char *olduser, const char **reply);

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
int auth_switchuser (auth_id *id, char *user, char **olduser);

/* this frees any resources used by an auth_id, it must zero out passwords
 *  and will be called before the program exits.  If the argument is NULL,
 *  no action should be taken.
 */
void auth_free(auth_id *id);

/*
 * Return the libcyrus authentication state from the given authorization state
 */
struct auth_state *auth_get_state(auth_id *id);

/* Return the user name of an identity.  The user name is used to identify
 * the appropriate mailboxes/bb-subscriptions/options/address-book/etc to
 * use.  It is also used for error messages.  The string may not be longer
 * than AUTH_USERMAX.
 * If "id" is NULL, this should return a string representing an anonymous user.
 */
char *auth_username(auth_id *id);

/* return the access level for a given id
 */
int auth_level(auth_id *id);
#endif
