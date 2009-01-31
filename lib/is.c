/* is.c -- IMAP grammar validity checking
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <ctype.h>

/*
 * Return nonzero if 's' matches the grammar for an atom
 */
int is_atom(s)
char *s;
{
    int len = 0;

    if (!*s) return 0;
    for (; *s; s++) {
	len++;
	if (*s & 0x80 || *s < 0x1f || *s == 0x7f ||
	    *s == ' ' || *s == '{' || *s == '(' || *s == ')' ||
	    *s == '\"' || *s == '%' || *s == '*' || *s == '\\') return 0;
    }
    if (len >= 1024) return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a sequence
 */
int is_sequence(s)
char *s;
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while (c = *s) {
	if (c == ',') {
	    if (!len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 0;
	}
	else if (c == ':') {
	    if (sawcolon || !len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 1;
	}
	else if (c == '*') {
	    if (len && s[-1] != ',' && s[-1] != ':') return 0;
	    if (isdigit(s[1])) return 0;
	}
	else if (!isdigit(c)) {
	    return 0;
	}
	s++;
	len++;
    }
    if (len == 0) return 0;
    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a number
 */
int is_number(s)
char *s;
{
    if (!*s) return 0;
    for (; *s; s++) {
	if (!isdigit(*s)) return 0;
    }
    return 1;
}
