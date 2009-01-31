/* map_private.c -- memory-mapping routines using MAP_PRIVATE.
 $Id: map_private.c,v 1.3 2003/12/09 20:28:27 cdaboo Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include "map.h"
#include "exitcodes.h"

/*
 * Create/refresh mapping of file
 * Always removes old mapping and creates a new one.
 */
void
map_refresh(fd, onceonly, base, len, newlen, name, mboxname)
int fd;
int onceonly;
const char **base;
unsigned long *len;
unsigned long newlen;
const char *name;
const char *mboxname;
{
    struct stat sbuf;
    char buf[80];

    if (newlen == MAP_UNKNOWN_LEN) {
	if (fstat(fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstating %s file%s%s: %m", name,
		   mboxname ? " for " : "", mboxname ? mboxname : "");
	    snprintf(buf, sizeof(buf), "failed to fstat %s file", name);
	    fatal(buf, EC_IOERR);
	}
	newlen = sbuf.st_size;
    }
	    
    if (*len) munmap((char *)*base, *len);
    if (newlen == 0) {
	*base = 0;
	*len = 0;
	return;
    }
    *base = (char *)mmap((caddr_t)0, newlen, PROT_READ,
			 (onceonly ? MAP_SHARED : MAP_PRIVATE)
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
			 , fd, 0L);
    if (*base == (char *)-1) {
	if (onceonly) {
	    /* Try again without using MAP_SHARED */
	    *len = 0;
	    map_refresh(fd, 0, base, len, newlen, name, mboxname);
	    return;
	}

	syslog(LOG_ERR, "IOERROR: mapping %s file%s%s: %m", name,
	       mboxname ? " for " : "", mboxname ? mboxname : "");
	snprintf(buf, sizeof(buf), "failed to mmap %s file", name);
	fatal(buf, EC_IOERR);
    }
    *len = newlen;
}

/*
 * Destroy mapping of file
 */
void
map_free(base, len)
const char **base;
unsigned long *len;
{
    if (*len) munmap((char *)*base, *len);
    *base = 0;
    *len = 0;
}
