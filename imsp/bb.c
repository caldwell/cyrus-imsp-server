/* bb.c -- bboard subscriptions/update/location databases
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
 * Start Date: 5/4/93
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "glob.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"
#include "dispatch.h"
#include "im_util.h"
#include "authize.h"
#include "imap_client.h"
#include "bb.h"
#include "acl.h"

/* import from OS: */
extern char *malloc(), *realloc();

/* name of mailboxes database */
static char mboxdb[] = "mailboxes";
static char newdb[] = "new";
static char changedb[] = "changed";

/* name of user's inbox */
static char inbox[] = "INBOX";

/* options used */
static char opt_hostlist[] = "imsp.imap.servers";
static char opt_newhost[] = "imsp.new.mailbox.servers";

/* proxy protocol */
static char proxy_list[] = "LIST";
static char proxy_acl[] = "ACL";
static char proxy_dolist[] = "%a LIST \"\" *\r\n";
static char proxy_getacl[] = "%a GETACL MAILBOX %s\r\n";
static char proxy_create[] = "%a CREATE %s%a%a\r\n";
static char proxy_delete[] = "%a DELETE %s\r\n";
static char proxy_rename[] = "%a RENAME %s %s\r\n";
static char proxy_setacl[] = "%a SETACL MAILBOX %s %s %s\r\n";
static char proxy_delacl[] = "%a DELETEACL MAILBOX %s %s\r\n";

/* value for an unspecified update string */
static char noinfosub[] = "1 0";

/* proxy replies */
static char rpl_noimap[] = "NO no available IMAP server to create";
static char rpl_dbfailure[] = "NO failed to modify mailbox list";
static char rpl_exists[] = "%a NO mailbox `%p' already exists\r\n";
static char rpl_inval[] = "NO invalid mailbox name";
static char rpl_notexists[] = "%a NO mailbox `%p' not found\r\n";
static char rpl_norename[] = "%a NO can't rename mailbox `%p' since mailbox `%p' already exists\r\n";
static char rpl_noreplace[] = "%a NO can't replace mailbox `%p' since mailbox `%p' doesn't exist\r\n";
static char rpl_wronghost[] = "%a NO mailbox `%p' is not located on that IMAP server\r\n";
static char rpl_badhost[] = "NO can't create mailbox on that host";
static char rpl_imapconn[] = "NO connection to IMAP server failed";
static char rpl_notsupported[] = "NO command not suppported at this site";
static char rpl_nomem[] = "NO IMSP server out of memory";
static char rpl_norep[] = "NO IMSP server does not support replicated mailboxes";
static char rpl_nocauth[] = "%a NO not authorized to create mailbox `%p'\r\n";
static char rpl_nodauth[] = "%a NO not authorized to delete mailbox `%p'\r\n";
static char rpl_norauth[] = "%a NO not authorized to rename mailbox `%p' to `%p'\r\n";
static char rpl_noaauth[] = "%a NO not authorized to change rights on mailbox `%p'\r\n";
static char rpl_okcreate[] = "OK Create of non-terminal names is unnecessary";

/* handler for getacl */
typedef struct getacl_handler {
    im_handler hand;
    char *entry, *mbox;
    int used, size, num, mlen;
} getacl_handler;

/* handler procedure to add an ACL entry to a mailbox entry
 */
static void add_acl(hand, val, con)
    getacl_handler *hand;
    int val;
    im_conn *con;
{
    char *value, *bits;
    int len, result;

    /* make sure it's a "MAILBOX" acl for the right mailbox: */
    if (strncasecmp(con->buf.upos, "MAILBOX ", 8) || !hand->entry) return;
    con->buf.upos += 8;
    value = copy_astring(&con->buf, 0);
    if (!value) return;
    result = strncasecmp(value, hand->mbox, hand->mlen);
    free(value);
    if (result) return;

    /* get the ACL */
    value = copy_astring(&con->buf, 0);
    if (!value) return;
    bits = get_atom(&con->buf);
    if (!bits) {
	free(value);
	return;
    }
    len = strlen(value) + strlen(bits) + 2;
    while (hand->size - hand->used < len) {
	hand->entry = realloc(hand->entry, hand->size += 256);
	if (!hand->entry) {
	    free(value);
	    return;
	}
    }
    sprintf(hand->entry + hand->used, "%s\t%s\t", value, bits);
    ++hand->num;
    free(value);
    hand->used += len;
}

/* do a proxy GETACL command
 */
static char *bb_addacl(db, con, mbox, base, size)
    char *db;
    im_conn *con;
    char *mbox, **base;
    long *size;
{
    getacl_handler h;
    char *reply;
    int result;

    imap_inithandler(&h.hand, proxy_acl, add_acl);
    h.entry = *base;
    h.mbox = mbox;
    h.mlen = strlen(mbox);
    h.num = 0;
    h.used = strlen(h.entry);
    h.size = *size;
    imap_addhandler(con, &h.hand);
    result = im_send(&con->buf, con->lit, proxy_getacl, con->tag, mbox);
    if (result == 0) reply = imap_wait(con);
    if (con->lit[0].ptr) free(con->lit[0].ptr);
    imap_removehandler(con, proxy_acl);
    if (result != 0 || !reply) {
	reply =  rpl_imapconn;
    } else {
	if (reply[0] == 'B') {
	    reply = rpl_notsupported;
	} else if (reply[0] == 'O' && reply[1] == 'K') {
	    reply = h.entry ? NULL : rpl_nomem;
	    if (sdb_set(db, mbox, SDB_ICASE, h.entry) < 0) {
		reply = rpl_dbfailure;
	    }
	}
    }
    *base = h.entry;
    *size = h.size;

    return (reply);
}

/* storage for new mailbox list used by bb_init/add_mailbox */
typedef struct list_handler {
    im_handler hand;
    char *mlist;
    int mused, msize, hostnum;
} list_handler;
#define MLIST_START_SIZE 1024

/* handler procedure to add an entry to the mailbox list
 */
static void add_mailbox(hand, val, con)
    list_handler *hand;
    int val;
    im_conn *con;
{
    char *mbox = con->buf.upos;
    int len, sep_char = '\r';

    /* for now, we ignore attributes */
    while (*mbox && *mbox != ')') ++mbox;
    if (!*mbox || mbox[1] != ' ') return;
    mbox += 2;

    /* grab the sep_char */
    if (*mbox == '"') {
	++mbox;
	if (*mbox == '\\') ++mbox;
	sep_char = *mbox++;
    } else if (*mbox != 'N' && *mbox != 'n') {
	return;
    }
    while (*mbox && *mbox != ' ') ++mbox;

    /* grab the mailbox name */
    if (*mbox != ' ') return;
    con->buf.upos = mbox + 1;
    mbox = copy_astring(&con->buf, 0);
    if (!mbox) return;
    len = strlen(mbox);

    /* add it to list */
    if (len && hand->mlist && strcasecmp(mbox, inbox)) {
	while (hand->mlist && hand->msize - hand->mused <= len + 3) {
	    hand->mlist = realloc(hand->mlist, hand->msize *= 2);
	}
	if (hand->mlist) {
	    sprintf(hand->mlist + hand->mused, "%c%c%s",
		    '0' + hand->hostnum, sep_char, mbox);
	    hand->mused += len + 3;
	}
    }
    free(mbox);
}

/* initialize the toplevel mailbox list
 */
int bb_init()
{
    option_list *hostlist = NULL;
    char *client, *response, *mbox, *value, *newval, *host;
    long size;
    im_conn **con;
    int result, hnum, len;
    list_handler hand;

    /* find IMAP hosts */
    hostlist = option_getlist("", opt_hostlist, 1);
    if (!hostlist || !hostlist->count) {
	if (hostlist) option_freelist(hostlist);
	return (-1);
    }
    con = (im_conn **) malloc(sizeof (im_conn *) * hostlist->count);
    if (!con) {
	option_freelist(hostlist);
	return (-1);
    }

    /* set up mailbox list handler */
    imap_inithandler(&hand.hand, proxy_list, add_mailbox);
    hand.mlist = malloc(hand.msize = MLIST_START_SIZE);
    if (!hand.mlist) {
	free((char *) con);
	option_freelist(hostlist);
	return (-1);
    }
    hand.mused = 0;

    /* loop through hosts, doing LIST */
    hand.hostnum = -1;
    while (++hand.hostnum < hostlist->count) {
	/* check for IMAP client descriptor on hostname */
	client = strchr(hostlist->item[hand.hostnum], '/');
	if (client) *client++ = '\0';

	/* connect to imap host */
	con[hand.hostnum] =
	    imap_connect(hostlist->item[hand.hostnum], NULL, 1);
	if (con[hand.hostnum] == NULL) break;

	/* add "LIST" handler */
	imap_addhandler(con[hand.hostnum], &hand.hand);

	/* do a "LIST "" *" */
	result = im_send(&con[hand.hostnum]->buf, NULL,
			 proxy_dolist, con[hand.hostnum]->tag);
	if (result == 0) response = imap_wait(con[hand.hostnum]);

	/* clean up & exit on error */
	imap_removehandler(con[hand.hostnum], proxy_list);
	if (result < 0 || !response
	    || response[0] != 'O' || response[1] != 'K') {
	    break;
	}
    }
    sdb_delete(newdb);
    if (hand.hostnum < hostlist->count) {
	result = -1;
    } else if (sdb_create(newdb) != 0
	       || sdb_writelock(newdb, NULL, SDB_ICASE) != 0) {
	hand.hostnum = 0;
	result = -1;
    } else {
	/* loop through mailboxes doing GETACL */
	mbox = hand.mlist;
	newval = NULL;
	size = 0;
	while (mbox - hand.mlist < hand.mused) {
	    mbox += 2;
	    if (sdb_get(newdb, mbox, SDB_ICASE, &value) >= 0 && value != NULL) {
		/*XXX: replication: modify entry to add new host */
	    } else {
		/* add new entry */
		hnum = mbox[-2] - '0';
		host = hostlist->item[hnum];
		len = 8 + strlen(host);
		if (size < len) {
		    if (newval) free(newval);
		    newval = malloc(size = len + 256);
		    if (!newval) break;
		}
		snprintf(newval, size, "* %c (%s) ", mbox[-1], host);
		response = bb_addacl(newdb, con[hnum], mbox, &newval, &size);
		if (response) break;
	    }
	    while (*mbox++);
	}
	result = 0;
	if (response || !newval) result = -1;
	if (newval) free(newval);
    }

    /* clean up everything */
    for (hnum = 0; hnum < hostlist->count; ++hnum) {
	if (con[hnum]) imap_close(con[hnum]);
    }
    if (hand.mlist) free(hand.mlist);
    free((char *) con);
    if (!result) {
	/* copy over new mailboxes database */
	sdb_create(mboxdb);
	sdb_unlock(newdb, NULL, SDB_ICASE);
	sdb_copy(newdb, mboxdb, SDB_ICASE);
	sdb_delete(newdb);
    }
    if (hand.hostnum >= hostlist->count) {
	sdb_unlock(newdb, NULL, SDB_ICASE);
	sdb_delete(newdb);
    }
    option_freelist(hostlist);
    
    return (result);
}

/* get/parse info about a bboard
 */
int bb_get(name, uid, loc, acl, sep_char)
    char *name;
    char **uid, **loc, **acl;
    char *sep_char;
{
    char *value = NULL;
    
    if (name) {
	sdb_get(mboxdb, name, SDB_ICASE, &value);
    } else {
	value = *uid;
    }
    if (value) {
	if (uid) *uid = value;
	while (*value && *value++ != ' '); /* skip last-uid */
	if (*value && sep_char) *sep_char = *value++;
	while (*value && *value++ != ' '); /* skip sep-char/flags */
	if (loc) *loc = value;
	value = strchr(value, ')'); /* skip to end of location list */
	if (value && acl) {
	    *acl = value + 2;
	}
    }

    return (value ? 0 : -1);
}

/* get the rights to a bboard
 */
long bb_rights(id, name, acl)
    struct auth_state *id;
    char *name, *acl;
{
    long rights = acl_myrights(id, acl);
    char *user = auth_username(id);
    int len = strlen(user);

    if (auth_level(id) >= AUTH_BB) {
	rights |= ACL_ALL;
    } else if (!strcasecmp(inbox, name)
	|| (!strncasecmp("user.", name, 5)
	    && !strncasecmp(user, name + 5, len)
	    && (name[5+len] == '.' || name[5+len] == '\0'))) {
	rights |= ACL_LOOKUP | ACL_ADMIN;
    }
    
    return (rights);
}

/* check if we have create rights in parent
 *  returns 0 if we do, -1 otherwise
 */
static int bb_parentcreate(id, name, ploc)
    struct auth_state *id;
    char *name;
    char **ploc;
{
    int result = -1;
    char *dot;
    char *loc, *acl;

    if (auth_level(id) >= AUTH_BB) result = 0;
    if (ploc) *ploc = NULL;
    dot = strrchr(name, '.');
    while (dot) {
	*dot = '\0';
	if (bb_get(name, NULL, &loc, &acl, NULL) == 0) {
	    *dot = '.';
	    if (bb_rights(id, name, acl) & ACL_CREATE) result = 0;
	    if (ploc) *ploc = loc;
	    break;
	}
	*dot = '.';
	while (--dot >= name && *dot != '.');
	if (dot < name) dot = NULL;
    }

    return (result);
}

/* check if any child of <name> has lookup rights
 *  returns -1 on failure, 0 on success
 */
static int bb_childlookup(id, name, end, len)
    struct auth_state *id;
    sdb_keyvalue *name, *end;
    int len;
{
    char *key = name->key, *acl;

    while (name < end && !strncasecmp(key, name->key, len)) {
	if (name->key[len] == '.') {
	    bb_get(NULL, &name->value, NULL, &acl, NULL);
	    if (bb_rights(id, name->key, acl) & ACL_LOOKUP) {
		return (0);
	    }
	}
	++name;
    }

    return (-1);
}

/* returns 0 if we already did a given partial match
 */
static int bb_didpartial(base, name, len)
    sdb_keyvalue *base, *name;
    int len;
{
    char *key = name->key;
    int result = -1;

    if (len >= 0) {
	while (--name >= base && strncasecmp(key, name->key, len) == 0) {
	    if (name->key[len] == '.' || name->key[len] == '\0') {
		result = 0;
		break;
	    }
	}
    }

    return (result);
}

/* convert uid string to number
 */
static unsigned long uidval(uid)
    char *uid;
{
    unsigned long result = 0;

    while (isspace(*uid)) ++uid;
    while (isdigit(*uid)) result = result * 10 + (*uid++ - '0');

    return (result);
}

/* initialize bboard subscriptions
 */
int bb_subsinit(user)
    char *user;
{
    char dbname[256];

    /* check if it already exists */
    snprintf(dbname, sizeof(dbname), "user/%s/subs", user);

    return (sdb_check(dbname) == 0 || sdb_create(dbname) == 0 ? 0 : -1);
}

/* subscribe/unsubscribe to a bboard
 * returns -1 on failure, 0 on success, 1 if already subscribed/unsubscribed
 */
#ifdef __STDC__
int bb_subscribe(struct auth_state *id, char *name, int subscribe)
#else
int bb_subscribe(id, name, subscribe)
    struct auth_state *id;
    char *name;
    int subscribe;
#endif
{
    char *user, *value, *bbvalue, *newval, *acl;
    int result, result1;
    char dbname[256], iboxname[256];

    /* get old value / verify bboard name / verify proper rights */
    user = auth_username(id);
    if (!strcasecmp(inbox, name)) {
	snprintf(iboxname, sizeof(iboxname), "user.%s", user);
	name = iboxname;
    }
    snprintf(dbname, sizeof(dbname), "user/%s/subs", user);
    if (sdb_writelock(dbname, name, SDB_ICASE) < 0) return (-1);
    if (sdb_get(dbname, name, SDB_ICASE, &value) < 0
	|| bb_get(name, &bbvalue, NULL, &acl, NULL) < 0
	|| (!value && !(bb_rights(id, name, acl) & (ACL_LOOKUP|ACL_READ)))) {
	sdb_unlock(dbname, name, SDB_ICASE);
	return (-1);
    }

    /* check for silly requests */
    if (((!value || *value == '0') && !subscribe)
	|| (value && *value == '1' && subscribe)) {
	sdb_unlock(dbname, name, SDB_ICASE);
	return (1);
    }

    /* create new value & change it */
    newval = malloc(value ? strlen(value) + 1 : sizeof (noinfosub));
    if (newval == NULL) {
	sdb_unlock(dbname, name, SDB_ICASE);
	return (-1);
    }
    strcpy(newval, value ? value : noinfosub);
    *newval = subscribe ? '1' : '0';
    result = sdb_set(dbname, name, SDB_ICASE, newval);
    result1 = sdb_unlock(dbname, name, SDB_ICASE);
    free(newval);
    if (!result) result = result1;

    return (result);
}

/* finish mailbox matching
 */
void bb_matchdone(state)
    bb_state *state;
{
    if (state->pglob) glob_free(&state->pglob);
    if (state->bbsub) free((char *) state->bbsub);
    if (state->subs) {
	sdb_freematch(state->subs, state->subend - state->subs, 1);
    }
    if (state->bb) sdb_freematch(state->bb, state->bbend - state->bb, 0);
    memset((char *) state, 0, sizeof (bb_state));
}

/* begin a match
 *  returns -1 on failure
 */
int bb_matchstart(state, user, pat)
    bb_state *state;
    char *user, *pat;
{
    char *end;
    int bbcount, subcount;
    char dbname[256];

    /* initialize match state */
    memset((char *) state, 0, sizeof (bb_state));
    snprintf(state->inboxname, sizeof(state->inboxname), "user.%s", user);
    state->inboxlen = strlen(state->inboxname);
    state->lastmin = -1;
    end = pat + strlen(pat) - 1;

    /* check if inbox matches */
    state->pglob = glob_init(pat, GLOB_ICASE | GLOB_HIERARCHY);
    if (glob_test(state->pglob, inbox, 5, NULL) < 0) {
	state->inboxdone = 1;
    }

    /* do the match */
    if (*end == '%') {
	/* for partial matches, we save the glob pattern and pass a '*'
	 * down to the db level, since the db level doesn't do partial
	 * matches.
	 */
	*end = '*';
    } else {
	glob_free(&state->pglob);
    }
    if (sdb_match(mboxdb, pat, GLOB_ICASE | GLOB_HIERARCHY, NULL, 0,
		  &state->bb, &bbcount) >= 0) {
	state->bbend = state->bb + bbcount;
	state->bbpos = state->bb;
	snprintf(dbname, sizeof(dbname), "user/%s/subs", user);
	if (sdb_match(dbname, pat, GLOB_ICASE | GLOB_HIERARCHY, NULL,
		      1, &state->subs, &subcount) >= 0) {
	    state->subend = state->subs + subcount;
	    state->subpos = state->subs;
	    state->bbsub = (sdb_keyvalue **)
		malloc(sizeof (sdb_keyvalue *) * (subcount + 1));
	}
    }

    /* done -- check for success */
    if (state->pglob) *end = '%';
    if (state->bbsub != NULL) {
	state->bbsubpos = state->bbsub;

	return (0);
    }
    bb_matchdone(state);

    return (-1);
}

/* check if any matching subscriptions have been renamed or deleted
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
int bb_matchverify(state, id, pat, oldname, newname, autosub)
    bb_state *state;
    struct auth_state *id;
    char *pat, **oldname, **newname;
    int *autosub;
{
    char dbname[256];
    char *key, *end, *user, *value;
    int cmp, result, wassub, subcount;

    /* set database name so we have it if needed */
    user = auth_username(id);
    snprintf(dbname, sizeof(dbname), "user/%s/subs", user);

    /* build bbsubpos array & check for deleted/renamed bboards */
    while (state->subpos < state->subend) {
	key = state->subpos->key;
	cmp = -1;
	while (state->bbpos < state->bbend
	       && (cmp = strcmp(key, state->bbpos->key)) > 0) {
	    ++state->bbpos;
	}
	/* we have a deleted/renamed bboard */
	if (cmp) {
	    state->subchgflag = 1;
	    wassub = *state->subpos->value == '1';
	    *oldname = key;
	    *newname = NULL;
	    *autosub = 0;
	    if (sdb_writelock(dbname, key, SDB_ICASE) >= 0) {
		sdb_remove(dbname, key, SDB_ICASE);
		sdb_unlock(dbname, key, SDB_ICASE);
	    }
	    ++state->subpos;
	    if (!wassub) continue;
	    sdb_get(changedb, *oldname, SDB_ICASE, newname);
	    if (*newname) {
		if (sdb_get(mboxdb, *newname, SDB_ICASE, &value) >= 0
		    && value == NULL) {
		    /* bboard renamed and deleted */
		    *newname = NULL;
		    if (sdb_writelock(changedb, *oldname, SDB_ICASE) >= 0) {
			sdb_remove(changedb, *oldname, SDB_ICASE);
			sdb_unlock(changedb, *oldname, SDB_ICASE);
		    }
		} else if (bb_subscribe(id, *newname, 1) == 0) {
		    *autosub = 1;
		}
	    }
	    return (1);
	}
	*state->bbsubpos++ = state->bbpos++;
	++state->subpos;
    }
    *state->bbsubpos = state->bbend;

    /* if things changed, we need to rebuild subs & state->bbsub */
    if (state->subchgflag) {
	state->bbpos = state->bb;
	end = pat + strlen(pat) - 1;
	if (state->pglob) *end = '*'; /* assume user hasn't changed pat */
	sdb_freematch(state->subs, state->subend - state->subs, 1);
	if (sdb_match(dbname, pat, SDB_ICASE, NULL, 0,
		      &state->subs, &subcount) < 0) {
	    if (state->pglob) *end = '%';
	    bb_matchdone(state);
	    return (-1);
	}
	if (state->pglob) *end = '%';
	state->subend = state->subs + subcount;
	state->subpos = state->subs;
	free((char *) state->bbsub);
	state->bbsub = (sdb_keyvalue **)
	    malloc(sizeof (sdb_keyvalue *) * (subcount + 1));
	if (!state->bbsub) {
	    bb_matchdone(state);
	    return (-1);
	}
	state->bbsubpos = state->bbsub;
	state->subchgflag = 0;
	result = bb_matchverify(state, id, pat, oldname, newname, autosub);
	if (result < 0) return (result);

	/* we fixed it, but it's still broken.  Give up. */
	if (result || state->subchgflag) {
	    bb_matchdone(state);
	    return (-1);
	}
    }

    /* things are groovy!  Reset and get ready to go */
    state->bbpos = state->bb;
    state->subpos = state->subs;
    state->bbsubpos = state->bbsub;

    return (0);
}

/* get the next match
 *  returns *name, or NULL
 *  *name and *loc could vanish if any other db calls are made
 *  if subonly is set, only subscribed bboards will be returned.
 */
#ifdef __STDC__
char *bb_match(bb_state *state, struct auth_state *id, char **name, char **loc,
	       char *sep_char, int *flags, int subonly)
#else
char *bb_match(state, id, name, loc, sep_char, flags, subonly)
    bb_state *state;
    struct auth_state *id;
    char **name, **loc;
    char *sep_char;
    int *flags;
    int subonly;
#endif
{
    char *uid, *acl, *key, *value;
    int len, mlen = -1, cmp;
    char dbname[256];

    /* turn '\0' back into '.' from partial matches */
    if (state->part) {
	*state->part = '.';
	state->part = NULL;
    }

    /* check for inbox */
    *flags = 0;
    if (!state->inboxdone) {
	snprintf(dbname, sizeof(dbname), "user/%s/subs", auth_username(id));
	if (sdb_get(mboxdb, state->inboxname,
		    SDB_ICASE | SDB_QUICK, &uid) >= 0
	    && bb_get(NULL, &uid, loc, &acl, sep_char) == 0
	    && (!subonly ||
		sdb_get(dbname, state->inboxname,
			SDB_ICASE | SDB_QUICK, &value) < 0
		|| value == NULL || *value == '1')) {
	    key = inbox;
	} else {
	    state->inboxdone = 1;
	}
    }
    
    /* keep looking until we find a bboard we have lookup rights to */
    while (state->inboxdone) {
	if (subonly) state->bbpos = *state->bbsubpos;
	/* loop through uninteresting bboards */
	while (state->bbpos < state->bbend) {
	    if (!subonly || *state->subpos->value == '1') {
		key = state->bbpos->key;
		if (!state->pglob) break;
		if (state->lastmin < 0) state->lastmin = 0;
		len = strlen(key);
		if ((mlen = glob_test(state->pglob, key, len,
				      &state->lastmin)) >= 0
		    && bb_didpartial(state->bb, state->bbpos, mlen) < 0) {
		    if (mlen == len) mlen = state->lastmin = -1;
		    break;
		}
	    }
	    if (state->lastmin < 0) {
		if (subonly) {
		    ++state->subpos;
		    state->bbpos = *++state->bbsubpos;
		} else if (++state->bbpos > *state->bbsubpos) {
		    ++state->subpos, ++state->bbsubpos;
		}
	    }
	}
	if (state->bbpos == state->bbend) return (NULL);

	/* make sure it's not inbox & check LOOKUP right */
	cmp = strncasecmp(state->inboxname, key, state->inboxlen);
	if (mlen >= 0 || cmp != 0 || key[state->inboxlen] != '\0') {
	    uid = state->bbpos->value;
	    bb_get(NULL, &uid, loc, &acl, sep_char);
	    if ((cmp == 0 && key[state->inboxlen] == '.')
		|| (mlen < 0 && (bb_rights(id, key, acl) & ACL_LOOKUP))
		|| (mlen >= 0 && bb_childlookup(id, state->bbpos, state->bbend,
						mlen) == 0)) {
		break;
	    }
	}
	if (state->lastmin < 0) {
	    if (subonly) {
		++state->subpos;
		state->bbpos = *++state->bbsubpos;
	    } else if (++state->bbpos > *state->bbsubpos) {
		++state->subpos, ++state->bbsubpos;
	    }
	}
    }
    
    /* set flags */
    *name = key;
    /* if no messages on bboard, we're not interested */
    if (uid[0] == '0' && uid[1] == ' ') *flags |= BB_UNMARKED;

    /* check for NOINFERIOR:
     *  if it's the INBOX or
     *  the user doesn't have create rights,
     *  and there are no inferiors to which the user has lookup rights,
     *  then we set the NOINFERIOR flag
     */
    if (!state->inboxdone ||
	(!(bb_rights(id, key, acl) & ACL_CREATE)
	 && bb_childlookup(id, state->bbpos, state->bbend,
			   mlen ? mlen : strlen(key)) < 0)) {
	*flags |= BB_NOINFERIOR;
    }

    /* check against subscription list */
    if (state->inboxdone && *state->bbsubpos == state->bbpos) {
	if (*state->subpos->value == '1') {
	    *flags |= BB_SUBSCRIBED;
	}
	/* if we have info about a non-empty bboard, check uids */
	if (!(*flags & BB_UNMARKED) && (uid[0] != '*' || uid[1] != ' ')) {
	    if (uidval(state->subpos->value + 2) >= uidval(uid)) {
		*flags |= BB_UNMARKED;
	    } else {
		*flags |= BB_MARKED;
	    }
	}
	if (state->lastmin < 0) {
	    ++state->subpos, ++state->bbsubpos;
	}
    }

    /* if a partial match, don't allow select, dump all other flags,
     * and truncate name appropriately
     */
    if (mlen >= 0) {
	/* truncate name for partial match */
	*flags = BB_NOSELECT;
	key[mlen] = '\0';
	state->part = key + mlen;
    }

    /* flag as done, and advance to next */
    if (!state->inboxdone) {
	state->inboxdone = 1;
    } else if (state->lastmin < 0) {
	++state->bbpos;
    }

    return (key);
}

/* do a create command, return IMSP reply string
 */
#ifdef __STDC__
char *bb_create(struct auth_state *id, char *mbox, int count, char *hostlist)
#else
char *bb_create(id, mbox, count, hostlist)
    struct auth_state *id;
    char *mbox;
    int count;
    char *hostlist;
#endif
{
    char *reply = NULL, *host = NULL, *part = NULL;
    char *value, *loc;
    option_list *olist = NULL;
    int result, created = 0;
    long size;
    im_conn *con;

    /* don't allow create INBOX */
    if (!strcasecmp(mbox, inbox)) return (rpl_inval);
    
    /*XXX: eventually need to add replication support */
    if (count > 1) return (rpl_norep);

    if (mbox[strlen(mbox) - 1] == '.') return (rpl_okcreate);

    /* check if mailbox already exists */
    if (sdb_writelock(mboxdb, mbox, SDB_ICASE) < 0) return (rpl_dbfailure);
    value = NULL;
    sdb_get(mboxdb, mbox, SDB_ICASE, &value);
    if (value != NULL) {
	reply = rpl_exists;
    } else if (bb_parentcreate(id, mbox, &loc) < 0) {
	reply = rpl_nocauth;
    } else if (!count) {
	hostlist = loc;
    }

    /* get the host to use */
    if (!reply) {
	if (hostlist) {
	    /* get first host from hostlist */
	    host = copy_get_partition(hostlist, &part);
	    if (hostlist != loc
		&& option_lookup("", opt_hostlist, 0, host) < 1) {
		reply = rpl_badhost;
	    }
	} else if ((olist = option_getlist("", opt_newhost, 1))
		   && olist->count > 0) {
	    host = olist->item[0];
	}
	if (!host) reply = rpl_noimap;
    }

    /* connect to IMAP server */
    if (!reply && !(con = imap_connect(host, id, 0))) {
	reply = rpl_imapconn;
    }

    /* send CREATE command */
    if (!reply) {
	result = im_send(&con->buf, con->lit, proxy_create,
			 con->tag, mbox, part ? " " : "",
			 part ? part : "");
	if (result < 0 || !(reply = imap_wait(con))) {
	    reply = rpl_imapconn;
	} else if (reply[0] == 'B') {
	    reply = rpl_notsupported;
	} else if (reply[0] == 'O' && reply[1] == 'K') {
	    reply = NULL;
	    created = 1;
	}
	if (con->lit[0].ptr) free(con->lit[0].ptr);
    }

    /* send GETACL command */
    value = NULL;
    if (!reply) {
	size = strlen(host) + 256;
	value = malloc(size);
	if (!value) {
	    reply = rpl_nomem;
	} else {
	    snprintf(value, size, "* . (%s) ", host);
	    reply = bb_addacl(mboxdb, con, mbox, &value, &size);
	}
    }

    /* cleanup */
    if (sdb_unlock(mboxdb, mbox, SDB_ICASE) < 0 && !reply) {
	reply = rpl_dbfailure;
    }
    if (created && reply) {
	/* if we created the mailbox, but something later failed, try to
	 * delete it
	 */
	if (im_send(&con->buf, con->lit, proxy_delete, con->tag, mbox) == 0) {
	    imap_wait(con);
	}
	if (con->lit[0].ptr) free(con->lit[0].ptr);
    }
    if (value) free(value);
    if (olist) {
	option_freelist(olist);
    } else if (host) {
	free(host);
    }

    return (reply);
}

/* do a proxy delete command
 *  host is usually NULL
 *  returns a status reply string
 */
char *bb_delete(id, mbox, host)
    struct auth_state *id;
    char *mbox, *host;
{
    char *reply = NULL, *value = NULL, *myhost = host;
    char *scan, *uid, *loc, *acl;
    int dbdeleted = 0, len;
    im_conn *con;

    /* don't allow delete of inbox */
    if (!strcasecmp(inbox, mbox)) return (rpl_inval);
    
    /* check if mailbox exists */
    if (sdb_writelock(mboxdb, mbox, SDB_ICASE) < 0) return (rpl_dbfailure);
    if (bb_get(mbox, &uid, &loc, &acl, NULL) < 0) {
	reply = rpl_notexists;
    } else {
	/* check delete rights */
	/*XXX: need to add support for replication here */
	if (!(bb_rights(id, mbox, acl) & ACL_DELETE)) {
	    reply = rpl_nodauth;
	}
    }

    /* get hostname & connect to IMAP server */
    if (!reply) {
	if (myhost) {
	    len = strlen(myhost);
	    scan = loc;
	    do {
		while (*scan == '(' || *scan == ' ') ++scan;
		if (!strncasecmp(myhost, scan, len)) break;
		while (*scan && *scan != ')' && *scan != ' ') ++scan;
	    } while (*scan && *scan != ')');
	    if (!*scan || *scan == ')') reply = rpl_wronghost;
	} else {
	    myhost = copy_get_partition(loc, NULL);
	}
	if (!myhost) {
	    reply = rpl_nomem;
	} else if (!(con = imap_connect(myhost, id, 0))) {
	    reply = rpl_imapconn;
	}
    }

    /* remove mailbox from local db, keeping a record in case of error */
    if (!reply) {
	if ((value = malloc(strlen(uid) + 1)) == NULL) {
	    reply = rpl_nomem;
	} else {
	    strcpy(value, uid);
	    if (sdb_remove(mboxdb, mbox, SDB_ICASE) < 0) {
		reply = rpl_dbfailure;
	    } else {
		if (sdb_unlock(mboxdb, mbox, SDB_ICASE) < 0) {
		    reply = rpl_dbfailure;
		} else {
		    dbdeleted = 1;
		}
	    }
	}
    }

    /* send DELETE command */
    if (!reply) {
	if (im_send(&con->buf, con->lit, proxy_delete, con->tag, mbox) < 0
	    || !(reply = imap_wait(con))) {
	    reply = rpl_imapconn;
	} else if (reply[0] == 'B') {
	    reply = rpl_notsupported;
	}
    }

    /* if we failed to delete the mailbox, but we removed it from our db,
     * try to put it back
     */
    if ((reply[0] != 'O' || reply[1] != 'K') && dbdeleted
	&& sdb_writelock(mboxdb, mbox, SDB_ICASE) == 0) {
	dbdeleted = 0;
	sdb_set(mboxdb, mbox, SDB_ICASE, value);
    }

    /* clean up */
    if (!dbdeleted) sdb_unlock(mboxdb, mbox, SDB_ICASE);
    if (value) free(value);
    if (myhost != host) free(myhost);

    return (reply);
}

/* do a proxy rename or replace command
 *  returns reply string
 */
char *bb_rename(id, oldname, newname, rflag)
    struct auth_state *id;
    char *oldname;
    char *newname;
    int rflag;
{
    char *reply = NULL, *host = NULL, *iname = NULL;
    char *value, *uid, *loc, *acl;
    int didrename = 0, result, count, i;
    im_conn *con;
    sdb_keyvalue *kv = NULL;
    char dbname[256];

    /* deal with inbox */
    if (!strcasecmp(newname, inbox)) return (rpl_inval);
    if (!strcasecmp(oldname, inbox)) {
        int inamelen = strlen(auth_username(id)) + 6;
	iname = malloc(inamelen);
	if (!iname) return (rpl_nomem);
	snprintf(iname, inamelen, "user.%s", auth_username(id));
	oldname = iname;
    }
    
    /* lock db entries */
    if (sdb_writelock(mboxdb, oldname, SDB_ICASE) < 0) return (rpl_dbfailure);
    if (sdb_writelock(mboxdb, newname, SDB_ICASE) < 0) {
	sdb_unlock(mboxdb, oldname, SDB_ICASE);
	return (rpl_dbfailure);
    }

    /* make sure newname doesn't exist and check access rights */
    value = NULL;
    sdb_get(mboxdb, newname, SDB_ICASE, &value);
    if (rflag) {
	if (value == NULL) {
	    reply = rpl_noreplace;
	}
    } else if (value != NULL) {
	reply = rpl_norename;
    } else if (bb_parentcreate(id, newname, 0) < 0) {
	reply = rpl_norauth;
    }

    /* make sure oldname exists and check access rights */
    if (!reply) {
	if (bb_get(oldname, &uid, &loc, &acl, NULL) < 0) {
	    reply = rpl_notexists;
	} else if (!(bb_rights(id, oldname, acl) & ACL_DELETE)) {
	    reply = rpl_norauth;
	}
    }

    /* get host and connect to server */
    if (!reply) {
	host = copy_get_partition(loc, NULL);
	if (!(con = imap_connect(host, id, 0))) {
	    reply = rpl_imapconn;
	}
    }

    /* send RENAME command (or DELETE command if replacing) */
    if (!reply) {
	result = im_send(&con->buf, con->lit,
			 rflag ? proxy_delete : proxy_rename,
			 con->tag, oldname, newname);
	if (result < 0 || !(reply = imap_wait(con))) {
	    reply = rpl_imapconn;
	} else if (reply[0] == 'B') {
	    reply = rpl_notsupported;
	} else if (reply[0] == 'O' && reply[1] == 'K') {
	    didrename = 1;
	}
	if (con->lit[0].ptr) free(con->lit[0].ptr);
    }

    /* attempt to update the database */
    if (didrename) {
	if (rflag == 0 && sdb_set(mboxdb, newname, SDB_ICASE, uid) < 0) {
	    reply = rpl_dbfailure;
	} else if (iname) {
	    if (bb_last(oldname, 0, NULL) < 0) {
		reply = rpl_dbfailure;
	    }
	} else if (sdb_remove(mboxdb, oldname, SDB_ICASE) < 0) {
	    reply = rpl_dbfailure;
	    sdb_remove(mboxdb, newname, SDB_ICASE);
	}
    }

    /* unlock mbox db */
    if (sdb_unlock(mboxdb, newname, SDB_ICASE) < 0 && didrename) {
	reply = rpl_dbfailure;
    }
    if (sdb_unlock(mboxdb, oldname, SDB_ICASE) < 0 && didrename) {
	reply = rpl_dbfailure;
    }

    if (didrename && reply != rpl_dbfailure && !iname) {
	/* update changed file on success */
	sdb_create(changedb);
	if (sdb_writelock(changedb, NULL, SDB_ICASE) >= 0) {
	    if (sdb_match(changedb, "*", SDB_ICASE | GLOB_SUBSTRING,
			  oldname, 1, &kv, &count)==0) {
		/* we have some old entries to update */
		for (i = count; i--; ) {
		    if (!strcasecmp(kv[count].key, newname)) {
			sdb_remove(changedb, kv[count].key, SDB_ICASE);
		    } else {
			sdb_set(changedb, kv[count].key, SDB_ICASE, newname);
		    }
		}
	    }
	    sdb_set(changedb, oldname, SDB_ICASE, newname);
	    sdb_unlock(changedb, NULL, SDB_ICASE);
	    if (kv) sdb_freematch(kv, count, 1);
	}

	/* update user's subscriptions file */
	snprintf(dbname, sizeof(dbname), "user/%s/subs", auth_username(id));
	if (sdb_get(dbname, oldname, SDB_ICASE, &value) >= 0 && value != NULL) {
	    bb_subscribe(id, newname, 1);
	    bb_subscribe(id, oldname, 0);
	}
    }
    
    /* cleanup */
    if (didrename && reply == rpl_dbfailure && !rflag) {
	/* if we did the rename, but the db update failed, try to undo */
	result = im_send(&con->buf, con->lit, proxy_rename,
			 con->tag, newname, oldname);
	if (result == 0) imap_wait(con);
	if (con->lit[0].ptr) free(con->lit[0].ptr);
    }
    if (host) free(host);
    if (iname) free(iname);

    return (reply);
}

/* set access control list
 */
char *bb_setacl(id, mbox, ident, rights)
    struct auth_state *id;
    char *mbox, *ident, *rights;
{
    char *uid, *loc, *acl;
    char *reply = NULL, *host = NULL, *value = NULL;
    long size;
    im_conn *con;
    
    /* lock entry */
    if (sdb_writelock(mboxdb, mbox, SDB_ICASE) < 0) {
	return (rpl_dbfailure);
    }

    if (bb_get(mbox, &uid, &loc, &acl, NULL) < 0) {
	/* bboard lookup failed */
	reply = rpl_notexists;
    } else if (!(bb_rights(id, mbox, acl) & ACL_ADMIN)) {
	/* verify administer rights failed */
	reply = rpl_noaauth;
    } else if ((host = copy_get_partition(loc, NULL)) == NULL) {
	/* get hostname failed */
	reply = rpl_nomem;
    } else if (!(con = imap_connect(host, id, 0))) {
	/* connect to imap server failed */
	reply = rpl_imapconn;
    } else if (im_send(&con->buf, con->lit,
		       rights ? proxy_setacl : proxy_delacl,
		       con->tag, mbox, ident, rights) < 0) {
	/* send proxy command failed */
	reply = rpl_imapconn;
    } else if (!(reply = imap_wait(con))) {
	/* server response failed */
	reply = rpl_imapconn;
    } else if (reply[0] == 'B') {
	/* BAD -- IMAP server doesn't support SETACL */
	reply = rpl_notsupported;
    } else if (reply[0] == 'O' && reply[1] == 'K') {
	/* setacl successful -- now we need to GETACL to update localdb */
	size = acl - uid + 256;
	value = malloc(size);
	if (!value) {
	    reply = rpl_nomem;
	} else {
	    strncpy(value, uid, acl - uid);
	    value[acl - uid] = '\0';
	    reply = bb_addacl(mboxdb, con, mbox, &value, &size);
	}
    }

    /* cleanup */
    if (sdb_unlock(mboxdb, mbox, SDB_ICASE) < 0) {
	reply = rpl_dbfailure;
    }
    if (value) free(value);
    if (host) free(host);
    
    return (reply);
}

/* set the last read mark for a mailbox.  May add mailbox to local db.
 *  returns -1 on failure, 0 on success
 */
int bb_last(mbox, uid, host)
    char *mbox, *uid, *host;
{
    char *old = NULL, *new = NULL, *scan;
    int ulen, result = -1, result1;
    long size;
    im_conn *con;
    
    /* lock entry */
    if (sdb_writelock(mboxdb, mbox, SDB_ICASE) < 0) {
	return (-1);
    }

    /* check if entry exists */
    if (sdb_get(mboxdb, mbox, SDB_ICASE, &old) >= 0) {
	if (old == NULL) {
	    /* if entry doesn't exist, connect to server, get ACL,
	     * and add to database
	     */
	    size = strlen(uid) + strlen(host) + 256;
	    if ((con = imap_connect(host, NULL, 1)) != NULL
		&& (new = malloc(size)) != NULL) {
		snprintf(new, size, "%s . (%s) ", uid, host);
		if (bb_addacl(mboxdb, con, mbox, &new, &size) == NULL) {
		    result = 0;
		}
	    }
	} else {
	    /* see if we can do it in place */
	    for (scan = old; *scan && *scan != ' '; ++scan);
	    ulen = strlen(uid);
	    if (scan - old == ulen) {
		new = old;
		strncpy(new, uid, ulen);
	    } else {
		new = malloc(strlen(old) - (scan - old) + ulen + 1);
		if (new) {
		    strcpy(new, uid);
		    strcat(new, scan);
		}
	    }
	    /* update db if we have a new entry, and cleanup */
	    if (new) result = sdb_set(mboxdb, mbox, SDB_ICASE, new);
	}
    }

    /* cleanup */
    result1 = sdb_unlock(mboxdb, mbox, SDB_ICASE);
    if (!result) result = result1;
    if (new && new != old) free(new);

    return (result);
}

/* set the seen mark for a mailbox.  May add to subscription list, but
 * won't change subscription status.
 *  returns -1 on failure, 0 on success
 */
int bb_seen(mbox, uid, user)
    char *mbox, *uid, *user;
{
    char *value, *new = NULL;
    char dbname[256];
    int result = -1, result1, newlen;

    /* set the db name */
    snprintf(dbname, sizeof(dbname), "user/%s/subs", user);

    /* sanity check for existance of mbox & subscription list */
    if (sdb_get(mboxdb, mbox, SDB_ICASE, &value) < 0 || !value
	|| sdb_writelock(dbname, mbox, SDB_ICASE) < 0) {
	return (-1);
    }

    /* get old subscription status */
    sdb_get(dbname, mbox, SDB_ICASE, &value);
    if (!value) value = "0";

    /* set new value */
    newlen = strlen(uid) + 3;
    new = malloc(newlen);
    if (new) {
	snprintf(new, newlen, "%c %s", *value, uid);
	result = sdb_set(dbname, mbox, SDB_ICASE, new);
    }

    /* clean up */
    result1 = sdb_unlock(dbname, mbox, SDB_ICASE);
    if (!result) result = result1;
    if (new) free(new);

    return (result);
}
