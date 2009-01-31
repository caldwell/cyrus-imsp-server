/* bb.h -- bboard subscriptions/update/location databases
 *
 *	(C) Copyright 1993-1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Author: Chris Newman <chrisn+@cmu.edu>
 * Start Date: 5/3/93
 */

#include "auth.h"	/* for struct auth_state */

/* structure to hold state for bb searches */
typedef struct bb_state {
    /* all fields are private to bb module */
    sdb_keyvalue *bb, *bbpos, *bbend; /* start, position, end of bboard list */
    sdb_keyvalue *subs, *subpos, *subend; /* ditto for subscription list */
    /* The next two fields are a cool efficiency hack -- they keep a list
     * of pointers into the bb list for each subscription entry
     */
    sdb_keyvalue **bbsub, **bbsubpos;
    int subchgflag;		/* if a bboard was deleted/renamed */
    int inboxdone;		/* flag if inbox has been done */
    /* this is only non-NULL when the LIST pattern ends in a %.  It is used
     * to find partial matches
     */
    glob *pglob;
    int lastmin;		/* last minimum partial match */
    char *part;			/* pointer to partial match '.' set to '\0' */
    int inboxlen;
    char inboxname[AUTH_USERMAX + 6];
} bb_state;

/* status flags */
#define BB_SUBSCRIBED 0x01	/* user is subscribed to bboard */
#define BB_MARKED     0x02	/* bboard does contain unseen messages */
#define BB_UNMARKED   0x04	/* bboard doesn't contain unseen messages */
#define BB_NOSELECT   0x08	/* prefix to bboard */
#define BB_NOINFERIOR 0x10	/* can't have children appear */
/* shortcuts -- these pairs are mutually exclusive in this implementation: */
#define BB_STATE (BB_NOSELECT | BB_NOINFERIOR)
#define BB_MARK (BB_MARKED | BB_UNMARKED)

#ifdef __STDC__
/*  bb_subsinit(user)
 * initialize bboard subscriptions for user
 */
int bb_subsinit(char *);

/*  bb_subscribe(id, name, subscribe)
 * subscribe/unsubscribe to a bboard
 * returns -1 on failure, 0 on success, 1 if already subscribed/unsubscribed
 */
int bb_subscribe(struct auth_state *, char *, int);

/*  bb_matchstart(state, user, pattern)
 * begin a match
 *  returns -1 on failure
 */
int bb_matchstart(bb_state *, char *, char *);

/*  bb_matchverify(state, id, pattern, oldname, newname, autosub);
 * check if any matching subscriptions have been renamed or deleted
 *  (will call bb_subscribe to change entries as necessary)
 * must be called after bb_matchstart and before bb_match
 *  *newname will be set to NULL in case *oldname was deleted.
 *  *autosub will be set to 1 if the user's subscription status to *newname
 *   was changed.  Otherwise *autosub will be set to 0.
 * returns -1 on fatal error (no need to call bb_matchdone)
 * returns 0 if matching subscriptions are fully verified.
 * returns 1 if a rename/delete is being returned.  Call must call
 *   bb_matchverify again.
 */
int bb_matchverify(bb_state *, struct auth_state *, char *, char **, char **, int *);

/*  bb_match(state, id, name, loc, flags, sep_char, subonly);
 * get the next match
 *  returns *name, or NULL
 *  *name and *loc could vanish if any other db calls are made
 *  if subonly is set, only subscribed bboards will be returned.
 */
char *bb_match(bb_state *, struct auth_state *, char **, char **, char *, int *, int);

/* finish mailbox matching
 */
void bb_matchdone(bb_state *);

/*  bb_create(id, mbox, hostcount, hostlist)
 * do proxy IMAP to create a new bboard
 *  returns NULL on success, error message on failure
 */
char *bb_create(struct auth_state *, char *, int, char *);

/*  bb_delete(id, mbox, host)
 * do a proxy delete command
 *  host is usually NULL
 *  returns a status reply string
 */
char *bb_delete(struct auth_state *, char *, char *);

/*  bb_rename(id, oldname, newname, replace_flag)
 * do a proxy rename or a replace
 *  returns a status reply string
 */
char *bb_rename(struct auth_state *, char *, char *, int);

/*  bb_setacl(id, mbox, ident, rights)
 * do a proxy SETACL/DELETEACL command
 *  rights = NULL for DELETEACL
 */
char *bb_setacl(struct auth_state *, char *, char *, char *);

/*  bb_get(name, uid, hostlist, acl, sep_char)
 * get info about a bboard
 *  returns -1 on failure, 0 on success
 */
int bb_get(char *, char **, char **, char **, char *);

/*  bb_last(mailbox, uid, host)
 * set the last read mark for a mailbox.  May add mailbox to local db.
 *  returns -1 on failure, 0 on success
 */
int bb_last(char *, char *, char *);

/*  bb_seen(mailbox, uid, user)
 * set the seen mark for a mailbox.  May add to subscription list, but
 * won't change subscription status.
 *  returns -1 on failure, 0 on success
 */
int bb_seen(char *, char *, char *);

/*  bb_rights(id, mailbox, acl)
 * returns the rights bitmask for the acl list
 */
long bb_rights(struct auth_state *, char *, char *);
#else
int bb_subscribe(), bb_matchstart(), bb_matchverify(), bb_get();
char *bb_match(), *bb_create(), *bb_delete(), *bb_rename(), *bb_setacl();
int bb_last(), bb_seen(), bb_subsinit();
long bb_rights();
#endif
