/* im_util.h -- IMAP and IMSP protocol utility functions
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

#define MAX_INTEGER_LEN   24	/* max length of an integer */
#define MAX_LITERAL_EXTRA 32	/* max extra space needed for a literal */

/* IMAP/IMSP character information table */
extern char im_table[256];

/* isatom  -- is a valid atom character
 * isqstr  -- is valid quoted string character (like isatom, but allows space)
 * islatom -- is a valid atom character or list wildcard
 */
#define isatom(c)  (im_table[(unsigned char)(c)]&1)
#define isqstr(c)  (im_table[(unsigned char)(c)]&2)
#define islatom(c) (im_table[(unsigned char)(c)]&4)

/* literal storage used by im_send()
 */
typedef struct im_literal {
    char *ptr;
    int len;
} im_literal;

#ifdef __STDC__
/*  copy_get_partition(host_partition, partition)
 * copy and get the partition info from a hostname or hostlist
 *  return NULL on error, caller must free result if result differs
 *  from argument passed
 *  partition is set to NULL or a string which need not be freed by caller
 *  caller may pass NULL for partition argument
 */
char *copy_get_partition(char *, char **);

/* get an atom from a buffer.  contents may be destroyed by copy_string.
 */
char *get_atom(fbuf_t *);
char *get_latom(fbuf_t *buf);

/* copy an atom from a buffer.  Caller must free when done.
 */
char *copy_atom(fbuf_t *buf);
char *copy_latom(fbuf_t *buf);

/* copy a string from a buffer.  Caller must free when done.
 * flags:
 *  bit 1 - "+" prompt will be written to ask for literals
 *  bit 2 - allow list_wildcards in atoms
 */
char *copy_astring(fbuf_t *, int);

/* copy a list of atoms from a buffer
 *  returns -1 for error, 0 for empty list, 1+ for list with that many
 *  elements which must be freed by caller.  List string returned in
 *  char ** argument.
 */
int copy_atom_list(fbuf_t *, char **);

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
int im_send(fbuf_t *, im_literal *, char *, ...);
#else
char *copy_get_partition(), *get_atom(), *get_latom(), *copy_atom();
char *copy_latom(), *copy_astring();
int copy_atom_list(), im_send();
#endif
