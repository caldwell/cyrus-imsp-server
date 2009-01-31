/* im_util.c -- IMAP and IMSP protocol utility functions
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
 * Start Date: 5/9/93
 */

#include <config.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "dispatch.h"
#include "exitcodes.h"
#include "im_util.h"
#include "util.h"

#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#define MAX_DIGITS  32  /* max number of digits in long integer */

/* flag that a literal is ready to be sent */
static char literalrdy[] = "+ go\r\n";

/* base64 conversion string */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

enum {
    MAXLIST = 256,
    MAXQUOTED = 8192,
    MAXWORD = 8192,
    MAXLITERAL = INT_MAX / 20
};

/* bit 1: valid atom CHARACTER
 * bit 2: valid quoted string CHARACTER
 * bit 4: valid atom or list_wildcards CHARACTER
 */
char im_table[256] = {
    0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 2, 0, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 7, 0, 7, 7, 6, 7, 7, 2, 2, 6, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 2, 7, 7, 7, 2,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* copy host and get the partition info from a hostname or hostlist
 */
char *copy_get_partition(str, partition)
    char *str;
    char **partition;
{
    char *scan, *new, *start;
    int hlen, len;

    if (partition) *partition = NULL;
    for (start = str; *start == '(' || *start == ' '; ++start);
    for (scan = start; *scan && *scan != '/'
	 && *scan != ' ' && *scan != ')'; ++scan);
    hlen = scan - start;
    while (*scan && *scan != ' ' && *scan != ')') ++scan;
    len = scan - start;
    if (!*scan && start == str && len == hlen) return (str);
    new = malloc(len + 1);
    if (new) {
	strncpy(new, start, len);
	new[len] = '\0';
	if (hlen < len) {
	    new[hlen] = '\0';
	    if (partition) *partition = new + hlen + 1;
	}
    }

    return (new);
}

/* get an atom from a buffer.  contents may be destroyed by copy_astring.
 */
char *get_atom(buf)
    fbuf_t *buf;
{
    char *end = buf->lend;
    char *start, *pos;

    pos = start = buf->upos;
    if (*pos == '{') return ((char *) NULL);
    while (pos < end && isatom(*pos)) ++pos;
    if (pos == start || (*pos && *pos != ' ')) return ((char *) NULL);
    *pos = '\0';
    if (pos < end) ++pos;
    buf->upos = pos;

    return (start);
}

/* get an atom w/ last_wildcard from a buffer.
 *  contents may be destroyed by copy_astring.
 */
char *get_latom(buf)
    fbuf_t *buf;
{
    char *end = buf->lend;
    char *start, *pos;

    pos = start = buf->upos;
    if (*pos == '{') return ((char *) NULL);
    while (pos < end && islatom(*pos)) ++pos;
    if (pos == start || (*pos && *pos != ' ')) return ((char *) NULL);
    *pos = '\0';
    if (pos < end) ++pos;
    buf->upos = pos;

    return (start);
}

/* copy an atom from a buffer.  Caller must free when done.
 */
char *copy_atom(buf)
    fbuf_t *buf;
{
    char *end = buf->lend;
    char *start, *pos, *result;

    pos = start = buf->upos;
    if (*pos == '{') return ((char *) NULL);
    while (pos < end && isatom(*pos)) ++pos;
    if (pos == start) return ((char *) NULL);
    *pos = '\0';
    if(pos - start > MAXWORD) {
	fatal("word too big", EC_IOERR);
    }
    result = malloc(pos - start + 1);
    if (pos < end) ++pos;
    buf->upos = pos;
    if (result) strcpy(result, start);

    return (result);
}

/* copy an atom with list_wildcards from a buffer.  Caller must free when done.
 */
char *copy_latom(buf)
    fbuf_t *buf;
{
    char *end = buf->lend;
    char *start, *pos, *result;

    pos = start = buf->upos;
    if (*pos == '{') return ((char *) NULL);
    while (pos < end && islatom(*pos)) ++pos;
    if (pos == start) return ((char *) NULL);
    *pos = '\0';
    if(pos - start > MAXWORD) {
	fatal("word too big", EC_IOERR);
    }
    result = malloc(pos - start + 1);
    if (pos < end) ++pos;
    buf->upos = pos;
    if (result) strcpy(result, start);

    return (result);
}

/* copy a string from a buffer.  Caller must free when done.
 * flags:
 *  bit 1 - "+" prompt will be written to ask for literals
 *  bit 2 - allow list_wildcards in atoms
 */
#ifdef __STDC__
char *copy_astring(fbuf_t *buf, int flags)
#else
char *copy_astring(buf, flags)
    fbuf_t *buf;
    int flags;
#endif
{
    char *start, *pos, *end, *result;
    int litlen;

    end = buf->lend;
    pos = start = buf->upos + 1;
    if (*buf->upos == '"') {
	/* parse a quoted string */
	while (pos < end && isqstr(*pos)) ++pos;
	if (*pos != '"') return ((char *) NULL);
	*pos = '\0';
	if(pos - start > MAXQUOTED) {
	    fatal("word too big", EC_IOERR);
	}
	result = malloc(pos - start + 1);
	if (pos < end && ++pos < end) {
	    if (*pos != ' ') return ((char *) NULL);
	    ++pos;
	}
	buf->upos = pos;
	if (result) strcpy(result, start);
	return (result);
    } else if (*buf->upos == '{') {
	int nonsynch = 0;

	/* parse a literal */
	litlen = 0;
	while (pos < end && isdigit(*pos)) {
	    litlen = litlen * 10 + (*pos - '0');
	    ++pos;
	    if(litlen > MAXLITERAL || litlen < 0) {
		/* we overflowed */
		fatal("literal too big", EC_IOERR);
	    }
	}
	if (pos[0] == '+') {
	    nonsynch = 1;
	    pos++;
	}
	if (pos[0] == '}' && pos[1] == '\0' && litlen) {
	    /* make space for literal & get it */
	    start = malloc(litlen + 1);
	    if (start == NULL) return (start);
	    if (!nonsynch && (flags&1)) {
		dispatch_write(buf, literalrdy, sizeof (literalrdy) - 1);
		dispatch_flush(buf);
	    }
	    if (dispatch_read(buf, start, litlen) <= 0
		|| dispatch_readline(buf) == NULL) {
		free(start);
		return ((char *) NULL);
	    }
	    if (*buf->upos == ' ') ++buf->upos;
	    start[litlen] = '\0';
	    return (start);
	}
    }
    
    return (flags&2 ? copy_latom(buf) : copy_atom(buf));
}

/* copy a list of atoms from a buffer
 *  returns -1 for error, 0 for empty list, 1+ for list with that many
 *  elements which must be freed by caller.  List string returned in
 *  char ** argument.
 */
int copy_atom_list(buf, plist)
    fbuf_t *buf;
    char **plist;
{
    char *start, *pos, *end, *dst;
    int count;

    /* get start & end */
    end = buf->lend;
    pos = start = buf->upos;

    /* initialize to empty list */
    count = 0;
    *plist = NULL;

    /* check for NIL or ( */
    if (end - pos >= 3 && !strncasecmp(pos, "nil", 3)) {
	if (buf) buf->upos = pos + 3;
	return (0);
    }
    if (*pos != '(') return (-1);
    ++pos;
    if (*pos == ' ') ++pos;

    /* count list elements */
    while (pos < end && *pos != ')') {
	++count;
	while (pos < end && isatom(*pos)) ++pos;
	if (pos < end && *pos != ' ') return (-1);
	if (pos[-1] == ')') {
	    --pos;
	    break;
	}
	++pos;
    }
    if (pos >= end) return (-1);
    buf->upos = pos + 1;
    if (*buf->upos == ' ') ++buf->upos;
    if (!count) return (0);
    end = pos;

    /* make space & copy */
    if(pos - start > MAXLIST * MAXWORD) {
	fatal("list too long", EC_IOERR);
    }
    *plist = dst = malloc(pos - start + 2);
    if (!dst) return (-1);
    memcpy(dst, start, pos - start + 1);
    dst[pos - start + 1] = '\0';

    return (count);
}

/* output an IMAP/IMSP string
 *  fbuf   -- dispatch file buffer
 *  litbuf -- if NULL, all literals sent.  If non-NULL, litbuf[0].ptr must be
 *            freed by caller, and litbuf must point to an array of im_literals
 *            of length 2 + max number of literals output.  The output string
 *            will be broken into pieces and the first piece will be sent.
 *            Caller will have to wait for "+" from the server before sending
 *            the next piece.
 *  str    -- an sprintf style string with the following meanings:
 *            %a -- atom
 *            %s -- string (will be quoted or literalized as needed)
 *            %p -- pretty-print (used for error messages and such)
 *            %d -- decimal
 *	      %b -- base64 string (length, string)
 *            %% -- %
 */
#ifdef __STDC__
int im_send(fbuf_t *fbuf, im_literal *litbuf, char *str, ...)
#else
int im_send(va_alist)
    va_dcl
#endif
{
    va_list ap;
    char *wkspace, *wkptr, *astr, *scan;
    int wksize, wkused, len, maxlen, result, litpos, i, c1, c2;
    long val;

    /* initialize argument list */
#ifdef __STDC__
    va_start(ap, str);
#else
    fbuf_t *fbuf;
    char *str;
    im_literal *litbuf;
    va_start(ap);
    fbuf = va_arg(ap, fbuf_t *);
    litbuf = va_arg(ap, im_literal *);
    str = va_arg(ap, char *);
#endif

    /* initialize workspace */
    litpos = 0;
    if (litbuf) litbuf[0].ptr = NULL;
    wkused = 0;
    wksize = (strlen(str) + 1) * 4;
    wkptr = wkspace = malloc(wksize);
    if (wkspace == (char *) NULL) {
	va_end(ap);
	return (-1);
    }

    /* start copying string */
    while (*str) {
	wkused = wkptr - wkspace;
	if (*str == '%' && *++str != '%') {
	    maxlen = -1;
	    if (str[0] == '.' && str[1] == '*') {
		maxlen = va_arg(ap, long);
		str += 2;
	    }
	    /* calculate max length needed for argument */
	    len = 0;
	    switch (*str) {
		case 'a':
		    astr = va_arg(ap, char *);
		    len = strlen(astr);
		    break;
		case 'b':
		    val = va_arg(ap, long);
		    astr = va_arg(ap, char *);
		    len = val + (val >> 1) + 4;
		    break;
		case 's':
		    astr = va_arg(ap, char *);
		    len = strlen(astr) + MAX_LITERAL_EXTRA;
		    break;
		case 'p':
		    astr = va_arg(ap, char *);
		    len = strlen(astr) * 2;
		    break;
		case 'd':
		    val = va_arg(ap, long);
		    len = MAX_DIGITS;
		    break;
	    }

	    /* grow workspace if needed */
	    if (wkused + len >= wksize - 1) {
		wkspace = realloc(wkspace, wksize += len + strlen(str));
		if (wkspace == NULL) {
		    va_end(ap);
		    return (-1);
		}
		wkptr = wkspace + wkused;
	    }

	    /* copy argument */
	    switch (*str) {
		case 'a':
		    if (maxlen >= 0 && maxlen < len) len = maxlen;
		    strncpy(wkptr, astr, len);
		    wkptr += len;
		    break;
		case 's':
		    scan = astr;
		    len -= MAX_LITERAL_EXTRA;

		    /* send empty string as "" */
		    if (!*scan) {
			*wkptr++ = '"';
			*wkptr++ = '"';
		    }

		    /* try an atom */
		    if (*scan && *scan != '{') {
			while (*scan && isatom(*scan)) ++scan;
			if (*scan) {
			    scan = astr;
			} else {
			    strcpy(wkptr, astr);
			    wkptr += len;
			}
		    }

		    /* try a quoted string */
		    if (*scan) {
			while (*scan && isqstr(*scan)) ++scan;
			if (*scan) {
			    scan = astr;
			} else {
			    *wkptr++ = '"';
			    strcpy(wkptr, astr);
			    wkptr += len;
			    *wkptr++ = '"';
			}
		    }

		    /* send a literal */
		    if (*scan) {
			sprintf(wkptr, "{%d}\r\n%s", len, astr);
			wkptr += strlen(wkptr);
			if (litbuf) {
			    litbuf[litpos++].len = (wkptr - wkspace) - len;
			}
		    }
		    break;
		case 'p':
		    wkptr = beautify_copy(wkptr, astr);
		    break;
		case 'b':
		    len = val;
		    while (len) {
			c1 = (unsigned char) *astr++;
			*wkptr++ = basis_64[c1 >> 2];
			c2 = (--len == 0) ? 0 : (unsigned char) *astr++;
			*wkptr++ = basis_64[((c1 << 4) & 0x30) | (c2 >> 4)];
			if (!len) {
			    *wkptr++ = '=';
			    *wkptr++ = '=';
			} else {
			    c1 = (--len == 0) ? 0 : (unsigned char) *astr++;
			    *wkptr++ = basis_64[((c2 << 2) & 0x3c)|(c1 >> 6)];
			    if (!len) {
				*wkptr++ = '=';
			    } else {
				--len;
				*wkptr++ = basis_64[c1 & 0x3f];
			    }
			}
		    }
		    break;
		case 'd':
		    sprintf(wkptr, "%ld", val);
		    wkptr += strlen(wkptr);
		    break;
	    }
	    ++str;
	} else {
	    /* make extra space if needed */
	    if (wkused == wksize - 1) {
		wkspace = realloc(wkspace, wksize *= 2);
		if (wkspace == NULL) {
		    va_end(ap);
		    return (-1);
		}
		wkptr = wkspace + wkused;
	    }

	    /* copy character */
	    *wkptr++ = *str++;
	}
    }
    va_end(ap);
    *wkptr = '\0';
    if (litbuf) {
	litbuf[0].ptr = wkspace;
	for (i = 1; i <= litpos; ++i) {
	    litbuf[i].ptr = litbuf[i-1].ptr + litbuf[i-1].len;
	    litbuf[i].len -= litbuf[i-1].len;
	}
	litbuf[litpos].len = wkptr - litbuf[litpos].ptr;
	litbuf[litpos+1].ptr = NULL;
	result = dispatch_write(fbuf, wkspace, litbuf[0].len);
    } else {
	result = dispatch_write(fbuf, wkspace, wkptr - wkspace);
	free(wkspace);
    }

    return (result);
}
