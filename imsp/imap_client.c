/* imap_client.c -- IMAP client routines
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
 * Start Date: 5/9/93
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <acte.h>
#include "dispatch.h"
#include "authize.h"
#include "im_util.h"
#include "imap_client.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"

extern int from64();

/* from OS: */
extern char *malloc();

/* proxy strings
 */
static char proxy_login[]  = "%a LOGIN %s %s\r\n";
static char proxy_auth[]   = "%a AUTHENTICATE %a\r\n";
static char proxy_logout[] = "%a LOGOUT\r\n";
static char proxy_cancel[] = "*\r\n";

/* other strings */
static char BYE[] = "BYE";

/* list of active connections
 */
static im_conn *conlist = NULL;

/* wait for tagged response, dispatching unsolicited data appropriately
 */
char *imap_wait(con)
    im_conn *con;
{
    int litpos = 1, val;
    char *dtype, *scan, *digit;
    im_handler *hand;
    
    for (;;) {
	dispatch_flush(&con->buf);
	if (dispatch_readline(&con->buf) == NULL) return (NULL);
	if (*con->buf.upos == '+') {
	    if (!con->lit[litpos].ptr) return (con->buf.upos);
	    if (dispatch_write(&con->buf, con->lit[litpos].ptr,
			       con->lit[litpos].len) < 0) {
		return (NULL);
	    }
	    ++litpos;
	} else if (*con->buf.upos == '*') {
	    /* parse the unsolicited data */
	    val = -1;
	    for (dtype = con->buf.upos + 1; isspace(*dtype); ++dtype);
	    for (scan = dtype; *scan && !isspace(*scan); ++scan);
	    if (isdigit(*dtype) && *scan) {
		*scan = '\0';
		val = atoi(dtype);
		dtype = scan + 1;
		for (scan = dtype; *scan && !isspace(*scan); ++scan);
	    }
	    con->buf.upos = *scan ? scan + 1 : scan;
	    *scan = '\0';
	    /* look for a handler */
	    for (hand = con->hlist; hand && strcmp(dtype, hand->command);
		 hand = hand->next);
	    if (hand) {
		(*hand->proc)(hand, val, con);
	    } else if (!strcmp(dtype, BYE)) {
		con->closing = 1;
	    } else {
		printf("unhandled unsolicited data: [%d] `%s' %s\n",
		       val, dtype, con->buf.upos);
	    }
	} else if (strncmp(con->tag, con->buf.upos, strlen(con->tag))) {
	    /*XXX: this annoying error case needs to be dealt with */
	    printf("unexpected tag from `%s': %s\n", con->host, con->buf.upos);
	} else {
	    /* set the user position */
	    con->buf.upos += strlen(con->tag);
	    if (*con->buf.upos == ' ') ++con->buf.upos;

	    /* bump the tag number */
	    digit = con->tag + strlen(con->tag) - 1;
	    while (*digit == '9' && digit > con->tag) *digit-- = '0';
	    ++*digit;
	    
	    return (con->buf.upos);
	}
    }
}

/* deal with an async read
 */
int imap_async_read(fbuf, data)
    fbuf_t *fbuf;
    void *data;
{
    im_conn *con = data;
    char *line;

    line = dispatch_readline(fbuf);
    if (!line && fbuf->eof) {
	/* we got an EOF or error: blow away the connection */
#ifdef DEBUG
	printf("removing connection structure to host `%s'\n", con->host);
#endif
	imap_close(con);
	return (-1);
    }
    /* look for a "* BYE" */
    if (line && *line == '*' && !strncmp(line + 2, BYE, 3)) {
	con->closing = 1;
#ifdef DEBUG
	printf("connection to host `%s' closing\n", con->host);
#endif
    }

    return (0);
}

/* get a connection
 */
#ifdef __STDC__
im_conn *imap_connect(char *host, auth_id *id, int admin)
#else
im_conn *imap_connect(host, id, admin)
    char *host;
    auth_id *id;
    int admin;
#endif
{
    int result, litpos, fd, len, rwflag;
    char *user, *pass, *response, *outbuf, *val;
    im_conn *con;
    struct acte_client *mech;
    void *state;
    int protlevel;
    char *(*encodefunc)();
    char *(*decodefunc)();
    int maxplain, socksz;
    struct sockaddr_in addr, laddr;
    struct hostent *hp, *gethostbyname();
    struct servent *svent;

    /* look for a pre-existing connection */
    user = auth_username(id);
    for (con = conlist;
	 con != NULL && (strcmp(host, con->host) || strcmp(user, con->user));
	 con = con->next);

    if (con) {
	if (!con->closing) return (con);
	/* if connection is closing (or closed), we need to re-connect */
	if (con->buf.fd >= 0) {
	    dispatch_close(&con->buf);
	}
    } else {
	/* make sure hostname is valid */
	if ((hp = gethostbyname(host)) == NULL) return (NULL);

	/* create space & initialize new im_conn structure */
	con = (im_conn *) malloc(sizeof (im_conn) + strlen(host));
	if (!con) return (con);
	con->hlist = NULL;
	con->d.fbuf = &con->buf;
	con->d.read_proc = imap_async_read;
	con->d.write_proc = NULL;
	con->d.data = con;
    }

    /* initialize connection options */
    strcpy(con->host, host);
    con->user = user;
    con->closing = 0;
    strcpy(con->tag, "A001");

    /* create socket & connect */
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	free((char *) con);
	return (NULL);
    }
    dispatch_initbuf(&con->buf, fd);
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    svent = getservbyname(IMAP_PORTNAME, IMAP_PROTOCOL);
    addr.sin_port = svent ? svent->s_port : htons(IMAP_PORT);
    if (connect(con->buf.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
	dispatch_close(&con->buf);
	free((char *) con);
	return (NULL);
    }

    /* look for a valid first line */
    if (dispatch_readline(&con->buf) == NULL
	|| (strncmp("* OK", con->buf.upos, 4)
	    && strncmp("* PREAUTH", con->buf.upos, 9))) {
	dispatch_close(&con->buf);
	free((char *) con);
	return (NULL);
    }

    /* if it's not PREAUTH, we need to login */
    if (con->buf.upos[2] != 'P') {
	if (proxy_init(id, host, admin, &user, &pass, &mech) != 0) {
	    dispatch_close(&con->buf);
	    free((char *) con);
	    return (NULL);
	}
	if (!mech) {
	    /* standard LOGIN command */
	    result = im_send(&con->buf, con->lit, proxy_login, con->tag,
			     user, pass);
	    /* wait for response to the login command */
	    response = NULL;
	    if (result >= 0) {
		response = imap_wait(con);
	    }
	    if (con->lit[0].ptr) {
		/* Nuke password */
		for (litpos = 0; con->lit[litpos+1].ptr; ++litpos);
		memset(con->lit[litpos].ptr, 0, con->lit[litpos].len);
		free(con->lit[0].ptr);
	    }
	    /* check for errors */
	    if (!response || response[0] != 'O' || response[1] != 'K') {
		dispatch_close(&con->buf);
		free((char *) con);
		return (NULL);
	    }
	} else {
	    /* AUTHENTICATE command */
	    protlevel = ACTE_PROT_ANY;
	    val = option_get("", "imsp.proxy.authlevel", 1, &rwflag);
	    if (val) {
		protlevel = atoi(val);
		free(val);
	    }
	    socksz = sizeof (struct sockaddr_in);
	    getsockname(con->buf.fd, &laddr, &socksz);
	    result = mech->start("imap", host, user, protlevel, MAX_BUF,
				 &laddr, &addr, &state);
	    if (result == 0) {
		result = im_send(&con->buf, NULL, proxy_auth, con->tag,
				 mech->auth_type);
		if (result < 0) mech->free_state(state);
	    }
	    if (result != 0) {
		dispatch_close(&con->buf);
		free((char *) con);
		return (NULL);
	    }
	    con->lit[1].ptr = NULL;
	    response = imap_wait(con);
	    while (response && *response == '+') {
		len = from64(response, response + 2);
		result = mech->auth(state, len, response, &len,
				    &outbuf);
		if (result == ACTE_FAIL) {
		    im_send(&con->buf, NULL, proxy_cancel);
		    mech->free_state(state);
		    dispatch_close(&con->buf);
		    free((char *) con);
		    return (NULL);
		}
		result = im_send(&con->buf, NULL, "%b\r\n", len, outbuf);
		response = result == 0 ? imap_wait(con) : NULL;
	    }
	    /* check for errors */
	    if (!response || response[0] != 'O' || response[1] != 'K') {
		mech->free_state(state);
		dispatch_close(&con->buf);
		free((char *) con);
		return (NULL);
	    }
	    /* set protection */
	    mech->query_state(state, &user, &protlevel, &encodefunc,
			      &decodefunc, &maxplain);
	    if (encodefunc || decodefunc) {
		con->buf.efunc = encodefunc;
		con->buf.dfunc = decodefunc;
		con->buf.maxplain = maxplain;
		con->buf.state = state;
		con->buf.free_state = mech->free_state;
	    } else {
		mech->free_state(state);
	    }
	}
    }

    /* add to connection list and async watch */
    dispatch_add(&con->d);
    con->next = conlist;
    conlist = con;

    return (con);
}

/* close & free a connection
 */
void imap_close(con)
    im_conn *con;
{
    im_handler *scan, *next;
    im_conn **pcon;

    for (pcon = &conlist; *pcon && *pcon != con; pcon = &(*pcon)->next);
    if (*pcon) *pcon = con->next;
    if (con->buf.fd >= 0) {
	dispatch_remove(&con->buf);
	if (!con->closing &&
	    im_send(&con->buf, NULL, proxy_logout, con->tag) >= 0) {
	    imap_wait(con);
	}
	dispatch_close(&con->buf);
    }
    for (scan = con->hlist; scan; scan = next) {
	next = scan->next;
	if (scan->usage > 0 && !--scan->usage) free((char *) scan);
    }
    free((char *) con);
}

/* close and free all connections
 */
void imap_closeall()
{
    while (conlist) imap_close(conlist);
}

/* create a new IMAP handler, if con is non-NULL, add the handler to con
 *  size is the size of the allocated space.  If size is less than
 *       sizeof (im_handler), then it will be set to sizeof (im_handler)
 */
#ifdef __STDC__
im_handler *imap_newhandler(im_conn *con, char *com, im_hproc proc, int size)
#else
im_handler *imap_newhandler(con, com, proc, size)
    im_conn *con;
    char *com;
    im_hproc proc;
    int size;
#endif
{
    im_handler *newhand;

    if (!proc || !com) return (NULL);
    if (size < sizeof (im_handler)) size = sizeof (im_handler);
    newhand = (im_handler *) malloc(size);
    if (!newhand) return (newhand);
    newhand->command = com;
    newhand->proc = proc;
    newhand->usage = 0;
    if (con) {
	imap_addhandler(con, newhand);
    }

    return (newhand);
}

/* remove an IMAP handler from a connection
 *  returns -1 if no handler found
 */
int imap_removehandler(con, command)
    im_conn *con;
    char *command;
{
    im_handler **hptr, *hnext;

    hptr = &con->hlist;
    while (*hptr != NULL && strcmp(command, (*hptr)->command)) {
	hptr = &(*hptr)->next;
    }
    if (*hptr == NULL) return (-1);
    hnext = (*hptr)->next;
    if ((*hptr)->usage > 0 && !--(*hptr)->usage) free(*hptr);
    *hptr = hnext;

    return (0);
}
