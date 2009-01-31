/* dispatch.c -- dispatch routines
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
 *  SASL foo: Tim Martin <tmartin@andrew.cmu.edu>
 * Start Date: 2/16/93
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/param.h>
#include <netinet/in.h>
#ifdef AIX
#include <sys/select.h>
#endif
#include "dispatch.h"

#include <sasl/sasl.h>

#ifndef HAVE_GETDTABLESIZE
#define getdtablesize() 32
#endif

#ifndef MAX
#define MAX(a, b) ((b) > (a) ? (b) : (a))
#endif
#ifndef MIN
#define MIN(a, b) ((b) < (a) ? (b) : (a))
#endif

/* list of files to dispatch
 */
static dispatch_t *head;
static fd_set read_set, write_set;
static int nfds;
static int max_idle_rd, max_idle_wr;
static err_proc_t err_proc;

/* do nothing error procedure
 */
static int errproc(type)
    int type;
{
    return (1);
}

/* initialize dispatch module
 */
void dispatch_init()
{
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    head = (dispatch_t *) NULL;
    nfds = getdtablesize();
    max_idle_rd = 0;
    max_idle_wr = 0;
    err_proc = errproc;
}

/* initialize a file buffer
 */
void dispatch_initbuf(fbuf, fd)
    fbuf_t *fbuf;
    int fd;
{
    fbuf->fd = fd;
    fbuf->uend = fbuf->iptr = fbuf->ibuf;
    fbuf->ileft = MAX_BUF;
    fbuf->ocount = 0;
    fbuf->efunc = NULL;
    fbuf->dfunc = NULL;
    fbuf->free_state = NULL;
    fbuf->ecount = 0;
    fbuf->dptr = NULL;
    fbuf->nonblocking = 0;
    fbuf->eof = 0;
    fbuf->telem = -1;
    fbuf->saslconn = NULL;

}

/* set dispatch err function
 */
err_proc_t dispatch_err(read_secs, write_secs, iproc)
    int read_secs, write_secs;
    err_proc_t iproc;
{
    err_proc_t oldiproc;

    oldiproc = err_proc;
    max_idle_rd = read_secs;
    max_idle_wr = write_secs;
    err_proc = iproc ? iproc : errproc;

    return (oldiproc);
}

/* add a file descriptor
 */
void dispatch_add(dptr)
    dispatch_t *dptr;
{
    dptr->next = head;
    head = dptr;
    if (dptr->read_proc) {
	FD_SET(dptr->fbuf->fd, &read_set);
    }
    if (dptr->write_proc) {
	FD_SET(dptr->fbuf->fd, &write_set);
    }
}

/* remove a file descriptor
 */
void dispatch_remove(fbuf)
    fbuf_t *fbuf;
{
    dispatch_t **dptr;

    for (dptr = &head; *dptr != NULL; dptr = &(*dptr)->next) {
	if (fbuf == (*dptr)->fbuf) {
	    FD_CLR(fbuf->fd, &read_set);
	    FD_CLR(fbuf->fd, &write_set);
	    *dptr = (*dptr)->next;
	    break;
	}
    }
}

/* check if a file descriptor is in dispatch list
 */
int dispatch_check(fd)
    int fd;
{
    dispatch_t *dptr;

    for (dptr = head; dptr != NULL && dptr->fbuf->fd != fd; dptr = dptr->next);

    return (dptr != NULL);
}

/* set the dispatch procedures
 */
void dispatch_setproc(fd, read_proc, write_proc)
    int fd;
    int (*read_proc)(), (*write_proc)();
{
    dispatch_t *dptr;

    for (dptr = head; dptr != NULL && dptr->fbuf->fd != fd; dptr = dptr->next);
    if (dptr) {
	if (dptr->read_proc != read_proc) {
	    FD_CLR(fd, &read_set);
	    dptr->read_proc = read_proc;
	    if (read_proc) {
		FD_SET(fd, &read_set);
	    }
	}
	if (dptr->write_proc != write_proc) {
	    FD_CLR(fd, &write_set);
	    dptr->write_proc = write_proc;
	    if (write_proc) {
		FD_SET(fd, &write_set);
	    }
	}
    }
}

static void blocking(fbuf, block)
    fbuf_t *fbuf;
    int block;
{
    int arg;
    
    fbuf->nonblocking = !block;
    if (fcntl(fbuf->fd, F_GETFL, &arg) >= 0) {
	if (block) arg |= O_NDELAY;
	else arg &= ~O_NDELAY;
	fcntl(fbuf->fd, F_SETFL, &arg);
    }
}

/* main dispatch loop
 * fd is file descriptor we're waiting for.  Onwrite means we're waiting
 * for a write.
 *  Returns -1 on unix error, -2 on idle error, 0 on no error
 */
int dispatch_loop(fd, onwrite)
    int fd, onwrite;
{
    int			nfound;
    dispatch_t		*dptr;
    fbuf_t		*fbuf;
    fd_set		rset, wset;
    struct timeval	timeout, *to;

    for (;;) {
	rset = read_set;
	wset = write_set;
	FD_SET(fd, (onwrite ? &wset : &rset));
	timeout.tv_usec = 0;
	timeout.tv_sec = onwrite ? max_idle_wr : max_idle_rd;
	to = timeout.tv_sec ? &timeout : NULL;
	nfound = select(nfds, &rset, &wset, NULL, to);
	if (nfound < 0 && errno != EINTR) {
	    return (-1);
	} else if (nfound == 0) {
	    if ((*err_proc)(onwrite ? DISPATCH_WRITE_IDLE
			    : DISPATCH_READ_IDLE)) {
		return (-2);
	    }
	} else if (nfound > 0) {
	    if ((onwrite && FD_ISSET(fd, &wset))
		|| (!onwrite && FD_ISSET(fd, &rset))) {
		break;
	    }
	    /* look for fd to dispatch */
	    for (dptr = head; dptr != NULL; dptr = dptr->next) {
		fbuf = dptr->fbuf;
		if (dptr->read_proc && FD_ISSET(fbuf->fd, &rset)) {
		    blocking(fbuf, 0);
		    if ((*dptr->read_proc)(fbuf, dptr->data)) {
			break;
		    }
		    blocking(fbuf, 1);
		}
		if (dptr->write_proc && FD_ISSET(fbuf->fd, &wset)) {
		    (*dptr->write_proc)(fbuf, dptr->data);
		}
	    }
	}
    }

    return (0);
}

/* try to parse a CRLF terminated line from the input buffer
 *  start search at "*pscan"
 *  returns -1 for failure, 0 for success
 */
static int parse_line(fbuf, pscan)
    fbuf_t *fbuf;
    char **pscan;
{
    char *scan = *pscan;
    char *src, *dst;
    int count, bytes, result = -1;
    
    /* try to grab a line */
    while (scan + 1 < fbuf->iptr && (scan[0] != '\r' || scan[1] != '\n')) {
	++scan;
    }
    if (scan + 1 < fbuf->iptr) {
	/* if we found the end of line, we're done */
	*scan = '\0';
	fbuf->upos = fbuf->uend;
	fbuf->lend = scan;
	fbuf->uend = scan + 2;
	result = 0;
    } else {
	/* if not, shift the buffer to make room for more stuff */
	dst = fbuf->ibuf;
	src = fbuf->uend;
	bytes = fbuf->iptr - src;
	count = src - dst;
	scan -= count;
	if (!bytes) {
	    fbuf->uend = fbuf->iptr = dst;
	    fbuf->ileft = MAX_BUF;
	} else if (count) {
	    fbuf->uend = dst;
	    fbuf->iptr -= count;
	    fbuf->ileft += count;
	    do {
		*dst++ = *src++;
	    } while (--bytes);
	}
    }
    *pscan = scan;

    return (result);
}

/* fill iptr with up to ileft bytes.  Return bytes added.
 */
static int fill_buf(fbuf, iptr, ileft)
    fbuf_t *fbuf;
    char *iptr;
    int ileft;
{
    char *ptr;
    int len;
    int count;
    int result = 0;


    if (!(len = ileft)) return (-1);
    ptr = iptr;

    /* do we have any pending in 'pbuf'? */
    if (fbuf->dcount > 0) {
	if (fbuf->dcount >= ileft) {
	    result = ileft;
	} else {
	    result = fbuf->dcount;
	}	
	memcpy(ptr, fbuf->dptr, result);
	fbuf->dptr += result;
	fbuf->dcount -= result;
    }

    while (!result) {
	if (!fbuf->nonblocking && dispatch_loop(fbuf->fd, 0) < 0) {
	    result = -1;
	} else {
	    /* Limit what we pull in at a time to be
	     * the same as what we claimed to SASL */
	    if(len > MAX_BUF)
		len = MAX_BUF;

	    count = read(fbuf->fd, ptr, len);
	    if (count == 0) {
		fbuf->eof = 1;
		break;
	    } else if (count < 0) {
		if (errno != EWOULDBLOCK) result = -1;
		break;
	    } else if (fbuf->saslconn!=NULL) {
		const char *tmpbuf;
		unsigned tmplen;
		int lup;
		
		result = sasl_decode(fbuf->saslconn, ptr, count,
				     &tmpbuf, &tmplen);
		if (result != SASL_OK) {
		    return -1;
		}		  
		
		if (tmplen > 0) {
		    if (tmplen > ileft) {
			/* copy extra into 'pbuf', which must be empty */
			fbuf->dcount = tmplen - ileft;
			
			if (fbuf->dcount > MAX_BUF) {
			    /* more than we can handle */
			    return -1;
			}
			
			memcpy(fbuf->pbuf, tmpbuf + ileft, fbuf->dcount);
			fbuf->dptr = fbuf->pbuf;
			
			/* only return 'ileft' */
			tmplen = ileft;
		    }
		    memcpy(ptr, tmpbuf, tmplen);
		    result = tmplen;
		}
	    } else {
		result = count;
	    }
	}
    }
    if (fbuf->telem >= 0 && result > 0) {
	write(fbuf->telem, iptr, result);
    }

    return (result);
}

/* read up to the specified amount of data from a file
 */
int dispatch_read(fbuf, buf, size)
    fbuf_t *fbuf;
    char *buf;
    int size;
{
    int count, remaining = size, total;

    total = count = fbuf->iptr - fbuf->uend;
    if (count) {
	if (remaining < count) count = remaining;
	memcpy(buf, fbuf->uend, count);
	remaining -= count;
	fbuf->uend += count;
	buf += count;
    }
    if (remaining > 0) {
	do {
	    count = fill_buf(fbuf, buf, remaining);
	    if (count == 0) break;
	    if (count < 0) { (*err_proc)(DISPATCH_READ_ERR); return (count); }
	    total += count;
	    buf += count;
	    remaining -= count;
	} while ((remaining > 0) && !fbuf->nonblocking);
    }

    return (total);
}

/* read line (CRLF terminated)
 */
char *dispatch_readline(fbuf)
    fbuf_t *fbuf;
{
    char *scan;
    int count;

    scan = fbuf->uend;
    do {
	/* try to get a line from the buffer */
	if (parse_line(fbuf, &scan) == 0) {
	    return (fbuf->upos);
	}
	/* get some more stuff into the buffer */
	count = fill_buf(fbuf, fbuf->iptr, fbuf->ileft);
	if (count <= 0) {
	    if (count < 0) (*err_proc)(DISPATCH_READ_ERR);
	    break;
	}
	fbuf->iptr += count;
	fbuf->ileft -= count;
    } while (!fbuf->nonblocking);

    return (NULL);
}

/* flush output from a buffer
 */
static int do_flush(fbuf, buf, len)
    fbuf_t *fbuf;
    char *buf;
    int len;
{
    int count, chunk;
    unsigned elen;
    const char *ptr;
    char ebuf[MAX_BUF+4];

    do {
	if (fbuf->saslconn != NULL) {
	  int result;
	  chunk = MIN(len, fbuf->maxplain);
	  
	  result=sasl_encode(fbuf->saslconn, buf, chunk, &ptr, &elen);
	  
	  if (result!=SASL_OK)
	  {
	    (*err_proc)(DISPATCH_WRITE_ERR);
	    return (-1);
	  }

	  len -=chunk;
	  buf +=chunk;
	  
	} else {
	  elen = len;
	  len = 0;
	  ptr = buf;
	}
	do {
	  count = dispatch_loop(fbuf->fd, 1);
	  if (count < 0) {
	    (*err_proc)(DISPATCH_WRITE_ERR);
	    return (-1);
	  }
	  count = write(fbuf->fd, ptr, elen);
	  if (count < 0) {
	    if (errno != EINTR && errno != EINPROGRESS) {
	      (*err_proc)(DISPATCH_WRITE_ERR);
	      return (-1);
	    }
	    count = 0;
	  }
	  ptr += count;
	  elen -= count;
	} while (elen);
    } while (len);

    return (0);
}

/* flush any output in buffer
 */
int dispatch_flush(fbuf)
    fbuf_t *fbuf;
{
    int status = 0;
    
    if (fbuf->ocount) {
	status = do_flush(fbuf, fbuf->obuf, fbuf->ocount);
	fbuf->ocount = 0;
    }

    return (status);
}

/* (blocking) buffered write a string to the server
 *  calls idle procedure on any write error
 */
int dispatch_write(fbuf, buf, len)
    fbuf_t *fbuf;
    const char *buf;
    int len;
{
    int status = 0;

    if (len < 1) len = strlen(buf);
    if (fbuf->telem >= 0) {
	write(fbuf->telem, buf, len);
    }
    if (len < MAX_BUF / 2) {
	if (len + fbuf->ocount > MAX_BUF) status = dispatch_flush(fbuf);
	memcpy(fbuf->obuf + fbuf->ocount, buf, len);
	fbuf->ocount += len;
    } else {
	dispatch_flush(fbuf);
	status = do_flush(fbuf, buf, len);
    }

    return (status);
}

/* close a file buffer and remove it from dispatch system
 */
void dispatch_close(fbuf)
    fbuf_t *fbuf;
{
    if (fbuf->fd >= 0) {
	dispatch_remove(fbuf);
	dispatch_flush(fbuf);
	close(fbuf->fd);
	if (fbuf->free_state) {
	    fbuf->free_state(fbuf->state);
	}
	fbuf->fd = -1;
    }
    if (fbuf->telem >= 0) {
	close(fbuf->telem);
	fbuf->telem = -1;
    }
}

/* activate telemetry logging, if desired
 */
void dispatch_telemetry(fbuf, user)
    fbuf_t *fbuf;
    char *user;
{
    char fname[MAXPATHLEN];

    /* If telemetry was already enabled on this fbuf, close it.
     * This happens when an administrator uses LOGIN to switch to 
     * another userid.
     */
    if (fbuf->telem >= 0) {
	close(fbuf->telem);
	fbuf->telem = -1;
    }
    snprintf(fname, sizeof(fname), "/var/imsp/log/%s/%ld", user, (long) getpid());
    fbuf->telem = open(fname, O_WRONLY|O_CREAT, 0600);
}

int dispatch_addsasl(fbuf_t *fbuf, sasl_conn_t *conn)
{
  int max;
  const int *maxp;
  int result;

  fbuf->saslconn=conn;

  /* ask SASL for layer max */
  result = sasl_getprop(conn, SASL_MAXOUTBUF, (const void **) &maxp);
  max = *maxp;
  if (result != SASL_OK)
    return -1;
  
  if (max == 0 || max > MAX_BUF) {
    /* max = 0 means unlimited, and we can't go bigger */
    max = MAX_BUF;
  }
  
  max-=50; /* account for extra foo incurred from layers */
  
  fbuf->maxplain=max;

  return 0;
}
