/* syncdb.h -- synchronized data base access for IMSP
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
 * Start Date: 3/25/93
 */

#ifndef SYNCDB_H
#define SYNCDB_H

#include "util.h"

/* a key-value pair returned by a wildcard match
 */
typedef keyvalue sdb_keyvalue;

/* defines for flags (GLOB_* defines are also valid): */
#define SDB_ICASE	0x01	/* case insensitive */
#define SDB_QUICK	0x10	/* don't reread cache if cache available */

#define SDB_FLUSH_GLOBAL	0x100	/* flush out global dbs */
#define SDB_FLUSH_PRIVATE	0x200	/* flush out private (user) dbs */

#ifdef __STDC__
int sdb_init(void);
void sdb_done(void);
void sdb_flush(int);
int sdb_check(char *);
int sdb_create(char *);
int sdb_delete(char *);
int sdb_copy(char *, char *, int);
int sdb_get(char *, char *, int, char **);
int sdb_count(char *, int);
int sdb_match(char *, char *, int, char *, int, sdb_keyvalue **, int *);
void sdb_freematch(sdb_keyvalue *, int, int);
int sdb_writelock(char *, char *, int);
int sdb_unlock(char *, char *, int);
int sdb_set(char *, char *, int, char *);
int sdb_remove(char *, char *, int);
#else

/* initialize sdb module (add to synchronization)
 * returns -1 on failure, 0 on success
 */
int sdb_init( /* void */ );

/* release any resources used by sdb module (remove from synchronization)
 */
void sdb_done( /* void */ );

/* flush global and/or private databases to disk
 */
void sdb_flush( /* int */ );

/* check if a database exists
 *  returns 0 if exists, -1 otherwise
 */
int sdb_check( /* char *db */ );

/* create a new database.  fails if database exists or isn't createable.
 * returns -1 on failure, 0 on success
 */
int sdb_create( /* char *db */ );

/* delete a database.  fails if database isn't deletable.
 * returns -1 on failure, 0 on success
 */
int sdb_delete( /* char *db */ );

/* copy the contents of one database to another
 *  returns -1 on failure, 0 on success
 */
int sdb_copy( /* char *dbsrc, char *dbdst, int flags */ );

/* get value of a key
 * on return, value points to a string which shouldn't be modified and may
 * change on future sdb_* calls.
 * returns -1 on failure, 0 on success
 */
int sdb_get( /* char *db, char *key, int flags, char **value */ );

/* count the number of keys in a database
 *  returns -1 on failure, number of keys on success
 */
int sdb_count( /* char *db, int flags */ );

/* get keys & values that match a key wildcard (using '*' and '%')
 *  kv is set to a key/value array, count is set to the number of items in kv
 *  Caller must call sdb_freematch with kv when done.
 *  flags are the GLOB_* flags
 *  If the copy flag is 1, all data returned will be copied and may be used
 *  indefinitely.  If the copy flag is 0, then only the kv array will be
 *  copied as necessary.  If copy flag is 0, the data may become invalid on any
 *  future sdb_* call.
 * returns -1 on failure, 0 on success
 */
int sdb_match( /* char *db, char *key, int flags, char *vpat, int copy,
		  sdb_keyvalue **kv, int *count */ );

/* free keyvalue list returned by sdb_match
 *  if kv is NULL, no action is taken.
 */
void sdb_freematch( /* sdb_keyvalue *kv, int count, int copy */ );

/* lock a key to allow local modification -- this may lock a whole set of keys
 * or database as a side effect.  specific key need not exist.
 * if key is NULL, this locks the entire database
 * returns -1 on error, 0 on success
 */
int sdb_writelock( /* char *db, char *key, int flags */ );

/* unlock a key
 * returns -1 on failure, 0 on success
 */
int sdb_unlock( /* char *db, char *key, int flags */ );

/* set the value for a key -- key must be locked
 * returns -1 on failure, 0 on success
 */
int sdb_set( /* char *db, char *key, int flags, char *value */ );

/* remove the entry for a key
 * returns -1 on failure, 0 on success
 */
int sdb_remove( /* char *db, char *key, int flags */ ); 

#endif /* __STDC__ */

#endif /* SYNCDB_H */
