/* option.h -- IMSP option routines
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
 */

#ifndef OPTION_H
#define OPTION_H

#include "syncdb.h"

/* state used for option_match */
typedef struct option_state {
    /* all variables are private to option module */
    sdb_keyvalue *gkv, *ukv, *gkvpos, *ukvpos;
    int gcount, ucount, gtotal, utotal, buflen;
    char *buf;
} option_state;

/* storage for list options */
typedef struct option_list {
    int count;
    char *data;
    char *item[1];
} option_list;

/* make sure user has options database
 *  returns 0 if database exists, -1 on failure
 */
int option_check( /* char *user */ );

/* create new user options database
 *  returns -1 on failure
 */
int option_create( /* char *user */ );

/* begin a match
 *  returns -1 on failure
 */
int option_matchstart( /* option_state *state, char *user, char *pat */ );

/* get the next match
 *  returns *name, or NULL
 *  *name could vanish if any other db calls are made
 *  if admin is non-zero, then administrator options should be shown
 */
char *option_match( /* option_state *state, char *user, char **name,
		       char **value, int *rwflag, int admin */ );

/* finish option matching
 */
void option_matchdone( /* option_state *state */ );

/* get an option
 *  if admin is set then non-visible options will be returned
 *  opt must be all lower case
 *  rwflag may be NULL if caller doesn't care
 *  returns NULL for no entry
 *  caller must free the result
 */
char *option_get( /* char *user, char *opt, int admin, int *rwflag */ );

/* test if an option is "on"
 *  opt must be all lower case
 * like option_get, but parses returning dflt if option is not set.
 */
int option_test( /* char *user, char *opt, int admin, int dflt */ );

/* get a list option
 *  opt must be all lower case
 */
option_list *option_getlist( /* char *user, char *opt, int admin */ );

/* free results of option_getlist
 *  opt must be all lower case
 */
void option_freelist( /* option_list *olist */ );

/* check if a string is in a list
 *  opt must be all lower case
 * returns -1 on failure, 0 if not in list, 1 if in list
 */
int option_lookup( /* char *user, char *opt, int admin, char *str */ );

/* check/update user quota usage
 *  delta -- change in usage (in bytes)
 *  returns -1 on db error, -2 on quota overflow, 0 on success
 *  NOTE: will never return -2 if delta is negative.
 */
int option_doquota( /* char *user, long delta */ );

/* set an option
 *  returns -1 on failure, -3 on over quota
 */
int option_set( /* char *user, char *opt, int admin, char *value */ );

/* unset an option
 *  returns -1 on error, 0 if option was not set, 1 if option was unset
 */
int option_unset( /* char *user, char *opt, int admin */ );

#endif /* OPTION_H */
