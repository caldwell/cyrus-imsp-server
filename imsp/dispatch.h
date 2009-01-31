/* dispatch.h -- dispatch functions
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
 * Start Date: 2/22/93
 */

#define MAX_BUF 4096

#include <sasl/sasl.h>

/* a file buffer structure
 */
typedef struct fbuf_t {
    char *upos;			/* user position in line */
    int fd;			/* file descriptor */
    char *lend;			/* end of line in buffer */
    char *uend;			/* end of user area */
    char *iptr;			/* position for new data */
    int ileft;			/* unused bytes in ibuf */
    int ocount;			/* amount of data in obuf */
    int nonblocking;		/* flag for non-blocking input */
    int eof;			/* hit an EOF on read */
    int telem;			/* telemetry log */

    char *(*efunc)();		/* protection encoding function */
    char *(*dfunc)();		/* protection decoding function */
    void (*free_state)();	/* free protection state function */
    void *state;		/* protection state */
    int maxplain;		/* protection max plaintext on write */
    unsigned dcount;		/* amount of decoded data in pbuf */
    unsigned ecount;		/* amount of encoded data in pbuf */
    char *eptr;			/* position of encoded data in pbuf */
    char *dptr;			/* position in decoded data in pbuf */

    char ibuf[MAX_BUF];		/* line buffered data */
    char obuf[MAX_BUF];		/* output buffered data */
    char pbuf[MAX_BUF+4];	/* protection buffered data */

    sasl_conn_t *saslconn;
} fbuf_t;

/* a dispatch structure
 *  int read_proc(fbuf, data)
 *   fbuf_t *fbuf    file buffer
 *   void *data      user data
 *  returns -1 if self-removed, 0 otherwise
 */
typedef struct dispatch_t {
    struct dispatch_t *next;	/* next pointer */
    fbuf_t *fbuf;		/* file buffer */
    int (*read_proc)();		/* call on read */
    int (*write_proc)();	/* call on write */
    void *data;			/* generic data pointer */
} dispatch_t;

/* types for an error proc */
#define DISPATCH_READ_IDLE  0
#define DISPATCH_WRITE_IDLE 1
#define DISPATCH_READ_ERR   2
#define DISPATCH_WRITE_ERR  3

#ifdef __STDC__
/* an err procedure -- return non-zero to flag an error
 */
typedef int (*err_proc_t)(int);

/* initialize dispatch system */
void dispatch_init(void);

/* initialize a file buffer */
void dispatch_initbuf(fbuf_t *, int);

/* set err function, returns old err function */
err_proc_t dispatch_err(int, int, err_proc_t);

/* add a file descriptor to the dispatch list (structure not copied) */
void dispatch_add(dispatch_t *);

/* remove a file descriptor from the dispatch system */
void dispatch_remove(fbuf_t *);

/* check if a file descriptor is in the dispatch list */
int dispatch_check(int);

/* set the dispatch procedures */
void dispatch_setproc( int, int (*)(), int (*)());

/* (blocking) dispatch loop: returns 0 on success, -1 on unix select error */
int dispatch_loop(int, int);

/* (blocking) read specified amount of data from a file */
int dispatch_read(fbuf_t *, char *, int);

/* (blocking) read a line of text (CRLF terminated) from a file */
char *dispatch_readline(fbuf_t *);

/* flush data from a file buffer */
int dispatch_flush(fbuf_t *);

/* (blocking) write data */
int dispatch_write(fbuf_t *, const char *, int);

/* close a file buffer and remove it from dispatch system */
void dispatch_close(fbuf_t *);

/* Add SASL */
int dispatch_addsasl(fbuf_t *fbuf, sasl_conn_t *conn);

/* activate telemetry for user */
void dispatch_telemetry(fbuf_t *, char *);
#else
typedef int (*err_proc_t)();
void dispatch_init(), dispatch_initbuf(), dispatch_add(), dispatch_remove();
void dispatch_setproc(), dispatch_close(), dispatch_telemetry();
err_proc_t dispatch_err();
int dispatch_check(), dispatch_loop(), dispatch_read(), dispatch_flush();
int dispatch_write();
char *dispatch_readline();
#endif
