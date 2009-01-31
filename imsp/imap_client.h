/* imap_client.h -- IMAP client routines
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

/* IMAP unsolicited data handler procedure
 */
typedef void (*im_hproc)(/* struct im_handler *hand, int val, im_conn *con */);

/* IMAP unsolicited data handler structure
 */
typedef struct im_handler {
    struct im_handler *next;
    char *command;
    im_hproc proc;
    int usage;			/* -1 = static storage */
} im_handler;

/* IMAP connection structure
 */
typedef struct im_conn {
    struct im_conn *next;
    char *user;
    int closing;
    im_handler *hlist;
    dispatch_t d;
    fbuf_t buf;
    im_literal lit[16];
    char tag[5];
    char host[1];
} im_conn;

/* try IMAP_PORTNAME first */
#define IMAP_PORTNAME "imap"
#define IMAP_PROTOCOL "tcp"
#define IMAP_PORT     143

#ifdef __STDC__
/* wait for the completion of the last IMAP command sent, dispatching
 * unsolicited data to im_handlers as appropriate
 */
char *imap_wait(im_conn *);

/*  imap_connect(host, id, adminflag)
 * get a pointer to an existing IMAP connection, or create a new one
 */
im_conn *imap_connect(char *, auth_id *, int);

/* send logout, close and free an IMAP connection
 */
void imap_close(im_conn *);

/* close all connections
 */
void imap_closeall(void);

/*  imap_newhandler(con, command, proc, size)
 * create a new IMAP handler, if con is non-NULL, add the handler to con
 *  size is the size of the allocated space.  If size is less than
 *       sizeof (im_handler), then it will be set to sizeof (im_handler)
 */
im_handler *imap_newhandler(im_conn *, char *, im_hproc, int);

/* remove an IMAP handler from a connection
 *  returns -1 if no handler found
 */
int imap_removehandler(im_conn *, char *);
#else
char *imap_wait();
im_conn *imap_connect();
void imap_close(), imap_closeall();
im_handler *imap_newhandler();
int imap_removehandler();
#endif

/* add an IMAP handler to a connection
 */
#define imap_addhandler(con, hand) { \
    if ((hand)->usage >= 0) ++(hand)->usage; \
    (hand)->next = (con)->hlist; \
    (con)->hlist = (hand); \
}

/* initialize the fields in an IMAP handler
 */
#define imap_inithandler(hand, comval, procval) \
    ((hand)->command = (comval), (hand)->proc = (procval), (hand)->usage = -1)
