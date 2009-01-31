/* n_binsearch.c -- Binary search in newline-separated file
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
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
 */
/* n_binsearch.c -- Routines for libnsearch.a
 *                  Libraries for searching through files
 * Written by Douglas DeCarlo
 *
 * (C) Copyright 1990 by Douglas DeCarlo.
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of Douglas DeCarlo not be used in
 * advertising or publicity pertaining to distribution of the software without
 * specific, written prior permission.  Douglas DeCarlo makes no
 * representations about the suitability of this software for any purpose.
 * It is provided "as is" without express or implied warranty.
 *
 * DOUGLAS DECARLO DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT
 * SHALL DOUGLAS DECARLO BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>

#define NS_BUFFSIZE    512

/* Static buffer used for default buffer */
static unsigned char n_searchBuff[NS_BUFFSIZE];

/* Case-independent comparison converter.
 * Treats \r and \t as end-of-string and treats '.' lower than
 * everything else.
 */
#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])
static char convert_to_lowercase[256] = {
    0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x01, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x02, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/* Given file descriptor fd, and buffer of size buffSize, search ahead so that
   the buffer contains text after a separator, with file offset directly after
   the separator.  Return the number of bytes read into the buffer, or
   negative if an error occurs */
static int n_scanSeparator(fd, offset, buffer, buffSize)
int fd;                 /* File descriptor for file */
off_t *offset;          /* offset info file to search at */
unsigned char *buffer;  /* buffer to read into */
unsigned long buffSize; /* size of buffer provided */
{
    register int len, diff;
    register unsigned char *ptr, *endBuff;

    /* Seek to offset position in file */
    if (lseek(fd, *offset, SEEK_SET) != *offset)
      return -1;

    do {
	/* Read in a buffer full */
	if ((len = read(fd, buffer, buffSize)) < 0)
	  return -1;

	/* Check if at end of file */
	if (!len) {
	    *buffer = 0;
	    return 0;
	}

	endBuff = buffer + len;
	ptr = buffer;

	/* Search for separator if not at start of search block */
	if (*offset) {
	    /* Scan ahead for separator */
	    for (; ptr < endBuff && *ptr != '\n'; ptr++, (*offset)++);

	    /* If not at the end of the buffer (separator found) */
	    if (ptr != endBuff) {
		/* Skip over newline */
		ptr++;
		(*offset)++;

		/* Move read in material back so stuff after newline is at 
		   front of buffer */
		bcopy(ptr, buffer, diff = endBuff - ptr);

		/* Fill up rest of buffer */
		if ((len = read(fd, buffer + diff, buffSize - diff)) < 0)
		  return -1;

		len += diff;

		ptr = buffer;
	    }
	}
    } while (ptr == endBuff);

    /* Null terminate buffer if it doesn't fill the whole buffer */
    if (len < buffSize)
      buffer[len] = '\0';

    return len;
}

/* Returns seek index of position in file were word was found or should
   be inserted.  If found, buff contains contents at the word.
   */
int n_binarySearchFD(fd, word, caseSensitive, buffer, buffSize, hint, end)
int fd;			 /* File descriptor for search file */
unsigned char *word;	 /* Word to search for */
int caseSensitive;	 /* Nonzero if case sensitive search */
unsigned char **buffer;	 /* Buffer to use to search in */
unsigned long *buffSize; /* Size of buffer */
off_t hint;		 /* Start searching here */
off_t end;		 /* if nonzero, size of file */
{
    register unsigned char *ptr, *wordPtr;
    register unsigned char *buff;
    register int len, n, cmp;
    unsigned long buffSizeOrig;
    struct stat fInfo;
    int firstsearch = 1;
    off_t orig, start = 0, mid, offset;

    /* If passed in a NULL buffSize, use static buffer since size unknown */
    if (buffSize == NULL) {
	buffSize = &buffSizeOrig;
	if (buffer != NULL) {
	    *buffer = NULL;
	}
    }

    /* If passed in a NULL (or pointer to a NULL), set buff to be the
       static library buffer */
    if (buffer == NULL) {
	buff = n_searchBuff;
	*buffSize = NS_BUFFSIZE;
    } else if (*buffer == NULL) {
	buff = n_searchBuff;
	*buffSize = NS_BUFFSIZE;
	*buffer = buff;
    } else
      buff = *buffer;

    buffSizeOrig = *buffSize;

    /* If end file position is zero, set it to be the end of file */
    if (!end) {
	/* Get file length */
	if (fstat(fd, &fInfo) < 0) {    
	    return -1;
	}
	end = fInfo.st_size;
    }

    orig = lseek(fd, 0, SEEK_CUR);

    /* Scan through the file */
    while (start <= end) {
	if (firstsearch) {
	    /* Use hint supplied by caller */
	    firstsearch = 0;
	    mid = offset = hint;
	    if (mid <= start || mid > end) mid = offset = start;
	}
	else {
	    /* Calc position of middle of this range */
	    mid = offset = (off_t)((start + end)/2);
	}

	/* Scan forward until after a separator character (or at start) */
	if ((len = n_scanSeparator(fd, &offset, buff, buffSizeOrig)) < 0) {
	    lseek(fd, orig, SEEK_SET);
	    return len;
	}

	/* Check to see if word at current location */
	if (!len) {
	    /* If at EOF, search back */
	    cmp = -1;
	} else {
	    /* Perform comparison */
	    n = len;
	    wordPtr = word;
	    ptr = buff;

	    if (caseSensitive) {
		/* Case sensitive compare */
		while (--n>=0 && (cmp = *wordPtr - *ptr) == 0) {
		    wordPtr++;
		    ptr++;
		}
		if (n >= 0 && !*wordPtr) {
		    cmp = '\t' - *ptr;
		}
		else if (!cmp) {
		    cmp = 1;
		}
	    } else {
		/* Case insensitive compare */
		while (--n>=0 &&
		       (cmp = TOLOWER(*wordPtr) - TOLOWER(*ptr)) == 0) {
		    wordPtr++;
		    ptr++;
		}
		if (n >= 0 && !*wordPtr) {
		    cmp = TOLOWER('\t') - TOLOWER(*ptr);
		}
		else if (!cmp) {
		    cmp = 1;
		}
	    }
	}

	/* Buffer compares with word */
	if (!cmp) {
	    *buffSize = len;
	    lseek(fd, orig, SEEK_SET);
	    return offset;
	}

	/* Split search range in half */
	if (cmp < 0)
	  /* Word smaller than buff, so search back */
	  end = mid - 1;
	else
	  /* Word larger than buff, so search ahead */
	  start = offset + 1;
    }

    /* Word was not found.  Scan to location where word should be
       inserted and return that. */
    len = n_scanSeparator(fd, &start, buff, buffSizeOrig);
    lseek(fd, orig, SEEK_SET);
    if (len < 0) return len;
    *buffSize = 0;
    return start;
}
