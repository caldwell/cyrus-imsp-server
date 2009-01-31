/* syncdb.c -- synchronized data base access for IMSP via disk files & locking
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
 * Start Date: 3/25/93
 *
 * Topical Notes:
 * 
 * Memory usage
 * ------------
 * On a low memory machine, it might be useful to try to free cache entries
 * before giving up with a memory error.
 *
 * TODO
 * ----
 * Clean up write locks on error exit.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <fcntl.h>
#include <syslog.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "util.h"
#include "syncdb.h"
#include "glob.h"

/* prefixes for database files */
#define PREFIX		"/var/imsp"
#define PREFIXLEN	(sizeof (PREFIX) - 1)
#define PRIVPREFIX	"user"
#define PRIVPREFIXLEN	(sizeof (PRIVPREFIX) - 1)

/* maximum accepted length for a database specifier or path */
#define MAXDBLEN	256
#define MAXDBPATHLEN	(PREFIXLEN + MAXDBLEN)

/* cache sizing constants */
#define CACHE_INCREMENT 100		/* number of elements to grow cache by */

/* a file cache */
typedef struct cache {
    char db[MAXDBPATHLEN+1];		/* database name */
    unsigned long mtime;		/* last modified time */
    unsigned short modified : 1;	/* 0 = unmodified, 1 = modified */
    unsigned short loaded : 1;		/* 0 = unloaded, 1 = loaded */
    unsigned short icase : 1;		/* case insensitive flag for cache */
    int fd;				/* file descriptor, if locked */
    int locks;				/* number of locks on db */
    unsigned long cachesize;		/* number of element slots in cache */
    unsigned long cachecount;		/* number of instantiated elements */
    sdb_keyvalue *kv;			/* cache element array */
} cache;

/* valid databases and caches */
static char *globdbstr[] = {
    "options", "mailboxes", "new", "changed", "abooks", NULL
};
static char *privdbstr[] = {
    "options", "mailboxes", "subs", "alock",
    "abooks", "abook", NULL
};
#define NUMGDBSTR	(sizeof (globdbstr) / sizeof (char *) - 1)
#define NUMPDBSTR	(sizeof (privdbstr) / sizeof (char *) - 1)
#define PDBPREFIXPOS    (NUMPDBSTR - 2)
static cache globdb[NUMGDBSTR];
static cache privdb[NUMPDBSTR];

/* lock file extension */
static char newext[] = "%s..";

/* private macro definitions */
#define CLEANUP_RETURN(x)     do { rtval = x; goto CLEANUP; } while(0)

/* private function prototypes */
static void freecache(cache *c);
static int writecache(cache *c);
extern int strcasecmp();

extern int imspd_debug;

/*  */

/* free a cache (assume it's unlocked)
 */

/* HISTORY
 * IncrDev Feb 18, 1996 by sh: dropped psuedo memory mapping
 * END HISTORY */

static void freecache(c)
    cache *c;
{
    register int i;			/* loop counter */
    
    /* sanity checks */
    if (c == NULL) return;

    if (c->kv != NULL) {

      /* walk the cache element array freeing elements */
      for (i = 0; i < c->cachecount; i++) {
	if (c->kv[i].key != NULL) free(c->kv[i].key);
	if (c->kv[i].value != NULL) free(c->kv[i].value);
      }

      /* free the cache array */
      free((char *)c->kv);
      c->kv = NULL;
    }

    /* reset cache counts to 0 */
    c->cachecount = 0;
    c->cachesize = 0;

    /* reset cache state to unloaded */
    c->modified = 0;
    c->loaded = 0;
    if (c->fd != -1) {
      if (c->fd < 3) {
	if (c->fd != 0) { /* this stuff may be uninitialzed soo... */
	  syslog(LOG_ERR, "imspd: not closing invalid fd of %d\n", c->fd);
	}
      } else {
	close(c->fd);
      }
    }
    c->fd = -1;
    if (c->locks > 0) {
      fprintf(stderr,"Shouldn't free cache %s - %d locks still active\n", 
	      c->db, c->locks);
    }
}

/*  */

/* find a cache by its name
 */

/* NOTES
 * There are two cache tables that contain cache datastructures for supported
 * databases: global cache and private cache.   Global cache contains cached global
 * databases like the generic options, mailbox lists etc.   Private cache contains
 * databases like user defined address books.
 *
 * -- DEVELOPER ATTENTION --
 * The current algorithm supports only one cached addressbook database at a time.
 * If a request comes for an addressbook database that is not loaded, then the
 * currently loaded addressbook entry is flushed, and the requested one is loaded.
 * The cache table should be changed to maintain a list of "loaded" databases.
 * This will dramatically improve the performance of copying entries between
 * addressbooks on the same server.
 * END NOTES */

/* HISTORY
 * IncrDev Feb 27, 1996 by sh: to flush modified private cache databases
 * END HISTORY */

static cache *findcache(db)
    char *db;
{
    char *scan;
    int i;
    
/* : try to load a private cache database */
    if (!strncmp(db, PRIVPREFIX, PRIVPREFIXLEN) && db[PRIVPREFIXLEN] == '/') {

/* : - pick off the private name */
	scan = strchr(db + PRIVPREFIXLEN + 1, '/');
	if (scan == NULL) return (NULL);
	++scan;

/* : - walk the private database table matching the name */
	for (i = 0; privdbstr[i]; ++i) {

	    if (!strcmp(scan, privdbstr[i]) ||
		(i >= PDBPREFIXPOS
		 && !strncmp(scan, privdbstr[i], strlen(privdbstr[i])))) {

/* : -- if this is not the correct instance of the private database then flush it and get the right one */
		if (strcmp(privdb[i].db + PREFIXLEN + 1, db)) {
		    if (privdb[i].locks > 0) return (NULL);
		    if (privdb[i].modified) {
			writecache(&privdb[i]);
		    }
		    freecache(&privdb[i]);
		    snprintf(privdb[i].db, sizeof(privdb[i].db), "%s/%s", PREFIX, db);
		}
		return (&privdb[i]);
	    }
	}
	return (NULL);
    }
    for (i = 0; globdbstr[i]; ++i) {
	if (!strcmp(db, globdbstr[i])) {
	    snprintf(globdb[i].db, sizeof(globdb[i].db), "%s/%s", PREFIX, db);
	    return (&globdb[i]);
	}
    }
    return (NULL);
}

/*  */

/* key compare functions for the sdb_keyvalue structure
 */
static int keycmp(kv1, kv2)
    sdb_keyvalue *kv1, *kv2;
{
    return (strcmp(kv1->key, kv2->key));
}
static int ikeycmp(kv1, kv2)
    sdb_keyvalue *kv1, *kv2;
{
    return (strcasecmp(kv1->key, kv2->key));
}

/*  */

/* parse the data in the cache database file into the cache
 * returns -1 on failure, 0 on success
 */

/* HISTORY
 * IncrDev Feb 21, 1996 by sh: rewrote it to allocate parsed key/value pairs
 * IncrDev Feb 21, 1996 by sh: changed contract to accept data buffer
 * END HISTORY */

static int parsecache(c, data, flags)
  cache *c;				/* U: cache to parse into */
  char* data;				/* I: database data buffer */
  int flags;				/* I: case insensitive if non-zero */
{
    int sorted;				/* source file was sorted if 1 */
    long lines;				/* number of lines in data */
    long size;				/* allocation size in bytes */
    char* scan;				/* source data scan pointer */
    char* dst;				/* destination data write pointer */
    char* token;			/* current token */
    char savech;			/* temporary save character */
    sdb_keyvalue *kv;			/* current keyvalue in cache */
    int (*cmpf)();			/* sort comparison function */

/* : initialization */
    lines = 0;
    sorted = 1;
    cmpf = (flags & SDB_ICASE) ? strcasecmp : strcmp;

/* : count the number of lines in the database data */
    lines = 0;
    for (scan = data; *scan != '\0'; scan++) {
	if (*scan == '\n') lines++;
    }

/* : make sure that we count a line without a linefeed at the end */
    if (*(scan-1) != '\n') ++lines;

/* : CLAIM - the number of lines in the data is equivalent to the number of
     key value pairs in the database.   We can base the size of the cache on
     that value.   In fact, when we allocate the array, we allocate the required
     number of slots plus a CACHE_INCREMENT that allows for growth of the cache
     from new keyvalue pairs. */
/* : allocate space for the cache array */
    size = ((lines + CACHE_INCREMENT) * sizeof(sdb_keyvalue));
    kv = (sdb_keyvalue *) malloc(size);
    if (kv == NULL) {
	return (-1);
    }
    c->kv = kv;
    c->cachecount = lines;
    c->cachesize = lines + CACHE_INCREMENT;

/* : walk each line in the data parsing key value pairs */
    scan = data;
    for (kv = c->kv; lines; --lines, ++kv) {

/* : - parse the key, handling quoted characters */
	token = scan;
	for (dst = scan; (*scan != ' ') && (*scan != '\n') && (*scan != '\0'); scan++) {
	    if (*scan == '\\') {
		if (*++scan == 'n') {
		    *dst++ = '\n';
		    continue;
		} else if (*scan == 's') {
		    *dst++ = ' ';
		    continue;
		}
	    }
	    *dst++ = *scan;
	}

/* : - save the current scan character and write a NUL terminator to the parsed string */
	savech = *scan;
	*dst = '\0';			/* this may overwrite *scan */

/* : - copy the parsed key to the keyvalue pair */
	kv->key = strdup(token);
	if (kv->key == NULL) {
	    return(-1);
	}

/* : - restore the saved scan character */
	*scan = savech;

/* : - if at end of line or string then set the value to NULL */
	if ((*scan == '\n') || (*scan == '\0')) {
	    kv->value = NULL;
	}
	
/* : - else parse the value, handling quoted characters */
	else {
	    ++scan;
	    token = scan;
	    for (dst = scan; (*scan != '\n') && (*scan != '\0'); ++scan) {
		if (*scan == '\\') {
		    if (*++scan == 'n') {
			*dst++ = '\n';
			continue;
		    } else if (*scan == 's') {
			*dst++ = ' ';
			continue;
		    }
		}
		*dst++ = *scan;
	    }
	    *dst = '\0';

/* : - copy the parsed value to the keyvalue pair */
	    kv->value = strdup(token);
	    if (kv->value == NULL) {
		return(-1);
	    }
	}

/* : - move scan to the start of the next line */
	scan++;

/* : - check to make sure that the data is sorted */
	if (sorted && (kv != c->kv) && ((*cmpf)(kv[-1].key, kv->key) > 0)) {
	    sorted = 0;
	}
    }

/* : sort it, only if necessary */
    if (!sorted) {
	qsort(c->kv, c->cachecount, sizeof (sdb_keyvalue),
	      (flags & SDB_ICASE) ? ikeycmp : keycmp);
    }

/* : return success */
    return(0);
}

/*  */

/* load a cache from database file
 * returns -1 on error, 0 on success
 */

/* HISTORY
 * IncrDev Feb 21, 1996 by sh: completely rewrote it to use new cache structure
 * END HISTORY */

static int loadcache(c, flags)
    cache *c;
    int flags;
{
    struct stat stbuf;			/* file statistics buffer */
    int fd;				/* database file descriptor */
    int fdl;				/* lock file descriptor */
    int rtval;				/* return value */
    int count;				/* number of characters read from file */
    char* data;				/* raw (unparsed) database data */
    char lname[MAXDBPATHLEN + 5];	/* lock file name buffer */

/* : initialization */
    data = NULL;
    rtval = 0;

/* : quit if the cache is loaded and we don't care if it's stale */
    if (c->loaded && (flags & SDB_QUICK)) {
	return (0);
    }

/* : quit if we can't stat the database file */
    if (stat(c->db, &stbuf) < 0) {
      if (imspd_debug) {
	fprintf(stderr,"%s: ", c->db);
	perror("failed to stat cache buffer");
      }
      return(-1);
    }

/* : quit if the cache is up to date */
    if ((c->loaded == 1) && ((flags & SDB_ICASE) == c->icase)
	&& (stbuf.st_mtime == c->mtime)) {
	return(0);
    }

/* : free any existing cache structure */
    freecache(c);

/* : if the database file is 0 length then the refresh is complete */
    if (stbuf.st_size == 0) {
	c->loaded = 1;
	c->modified = 0;
	c->icase = flags & SDB_ICASE;
	c->cachecount = 0;
	return(0);
    }

/* : open the database file if it hasn't already been opened */
    fd = c->fd;
    if (c->locks != 0 && (c->fd == -1)) {
      if (imspd_debug) {
	fprintf(stderr,"internal consistency error. We got locks but not a valid fd for %s\n",
		c->db);
	return(-1);
      } else {
	syslog(LOG_ERR,"internal consistency error. We got locks but not a valid fd for %s\n",
	       c->db);
      }
    }

    if ((c->locks == 0) || (c->fd == -1)) {
	fd = open(c->db, O_RDONLY);
	if (fd < 0) {
	  if (imspd_debug) {
	    fprintf(stderr,"%s: ", c->db);
	    perror("failed to open DB");
	  }
	  return (-1);
	}
	c->fd = fd;
    }

/* ESYS DOC - this is a very expensive proposition if the file is large.  For
   a short while, we will have allocated in virtual memory TWICE the size
   of the file.   This should be changed to some sort of chained buffer
   structure like the c-client file string driver.   Reasonably fast and
   not too expensive in memory. */
/* : allocate a buffer to hold the database file text */
    data = (char *) malloc(stbuf.st_size + 1);
    if (data == NULL) {
      if (imspd_debug) {
	perror("malloc of data failed");
      } else {
	syslog(LOG_ERR, "imspd: Unable to allocate %d bytes for %s: %m",
	       stbuf.st_size+1, c->db);
      }
      CLEANUP_RETURN(-1);
    }

/* : read data from file into the data buffer */
    count = read(fd, data, stbuf.st_size);
    if (count != stbuf.st_size) {
      if (imspd_debug) {
	fprintf(stderr, "internal consistency error count(%d) != stbuf.st_size (%d)\n",
		count, stbuf.st_size);
      }
	CLEANUP_RETURN(-1);
    }
    data[count] = '\0';			/* set a sentinel -- THIS IS IMPORTANT!*/

/* : parse the database data into the cache */
    if (parsecache(c, data, flags) < 0) {
	freecache(c);
	if (imspd_debug) {
	  fprintf(stderr,"parsecache failed\n");
	}
	CLEANUP_RETURN(-1);
    }

/* : mark the cache as loaded and not modified */
    c->loaded = 1;
    c->modified = 0;
    c->icase = flags & SDB_ICASE;

 CLEANUP:
/* : free the database data buffer */
    if (data != NULL) {
	free(data);
    }

/* : close the database file if unlocked */
    if (c->locks == 0) {
	close(fd);
	c->fd = -1;
    }

/* : return the return value */
    return(rtval);
}

/*  */

/* write the cache content to database file
 */

/* HISTORY
 * IncrDev Feb 21, 1996 by sh: changed contract to just write cache to file
 * END HISTORY */


static int writecache(c)
    cache *c;
{
    FILE *out;
    int i;
    char *scan;
    char newname[MAXDBPATHLEN + 5];

/* : open new database file for output */
    snprintf(newname, sizeof(newname), newext, c->db);
    if ((out = fopen(newname, "w")) == NULL) {
	return (-1);
    }

/* : walk the cache writing keyvalue elements to the database file */
    for (i = 0; i < c->cachecount; ++i) {
	if (c->kv[i].key == NULL) continue;
	for (scan = c->kv[i].key; *scan; ++scan) {
	    if (*scan == '\n') {
		putc('\\', out);
		putc('n', out);
	    } else if (*scan == ' ') {
		putc('\\', out);
		putc('s', out);
	    } else if (*scan == '\\') {
		putc('\\', out);
		putc('\\', out);
	    } else {
		putc(*scan, out);
	    }
	}
	if (c->kv[i].value != NULL) {
	    putc(' ', out);
	    for (scan = c->kv[i].value; *scan; ++scan) {
		if (*scan == '\n') {
		    putc('\\', out);
		    putc('n', out);
		} else if (*scan == '\\') {
		    putc('\\', out);
		    putc('\\', out);
		} else {
		    putc(*scan, out);
		}
	    }
	}
	putc('\n', out);
    }

/* : make sure write & rename succeed */
    if (fclose(out) == EOF || rename(newname, c->db) < 0) {
	unlink(newname);
	return (-1);
    }

/* : remove any stray locks */
    if (c->locks) {
	lock_unlock(c->fd);
	close(c->fd);
	c->locks = -1;
    }

/* : return success */
    return (0);
}

/* initialize sdb module (add to synchronization)
 * returns -1 on failure, 0 on success
 */
int sdb_init()
{
    int i;
    struct stat stbuf;
    char path[MAXPATHLEN];

    /* initialize cache */
    for (i = 0; i < NUMGDBSTR; ++i) {
	memset(globdb[i].db, '\0', sizeof (globdb[i].db));
	globdb[i].modified = 0;
	globdb[i].loaded = 0;
	globdb[i].locks = 0;
	globdb[i].cachesize = 0;
	globdb[i].cachecount = 0;
    }
    for (i = 0; i < NUMPDBSTR; ++i) {
	memset(privdb[i].db, '\0', sizeof (privdb[i].db));
	privdb[i].modified = 0;
	privdb[i].loaded = 0;
	privdb[i].locks = 0;
	privdb[i].fd = -1;
	privdb[i].cachesize = 0;
	privdb[i].cachecount = 0;
    }

    /* initialize directories */
    snprintf(path, sizeof(path), "%s/%s", PREFIX, PRIVPREFIX);
    if (stat(path, &stbuf) < 0) {
	mkdir(PREFIX, 0700);
	if (mkdir(path, 0700) < 0) {
	    return (-1);
	}
    }

    return (0);
}

/* flush (write) and free cached database files
 */

/* HISTORY
 * IncrDev Feb 21, 1996 by sh: to write modified caches before freeing them
 * END HISTORY */

void sdb_done()
{
    int i;
    cache *c;

    /* write and free caches */
    for (i = 0; i < NUMGDBSTR; ++i) {
	c = globdb + i;
	if (c->modified) {
	    writecache(c);
	}
	if (c->locks) {
	    lock_unlock(c->fd);
	    close(c->fd);
	    c->fd = -1;
	    c->locks = 0;
	}
	freecache(c);
    }
    for (i = 0; i < NUMPDBSTR; ++i) {
	c = privdb + i;
	if (c->modified) {
	    writecache(c);
	}
	if (c->locks) {
	    lock_unlock(c->fd);
	    close(c->fd);
	    c->fd = -1;
	    c->locks = 0;
	}
	freecache(c);
    }
}


/* flush global and/or private databases to disk
 */

void sdb_flush(flags)
int flags;
{
    int i;
    cache *c;

    /* write and free global caches (to /var/imsp/<db>) */
    if (flags & SDB_FLUSH_GLOBAL)
      for (i = 0; i < NUMGDBSTR; ++i) {
	c = globdb + i;
	if (c->modified) {
	    writecache(c);
	}
      }

    /* write and free private caches (to /var/imsp/user/.../<db>) */
    if (flags & SDB_FLUSH_PRIVATE) {
      for (i = 0; i < NUMPDBSTR; ++i) {
	c = privdb + i;
	if (c->modified) {
	    writecache(c);
	}
      }
    }
}

/* check if a database exists
 *  returns 0 if exists, -1 otherwise
 */
int sdb_check(db)
    char *db;
{
    cache *c;
    struct stat stbuf;
    
    if ((c = findcache(db)) == NULL) return (-1);
    
    return ((c->loaded || stat(c->db, &stbuf) >= 0) ? 0 : -1);
}

/* create a new database.  fails if database exists or isn't createable.
 * returns -1 on failure, 0 on success
 */
int sdb_create(db)
    char *db;
{
    int fd;
    char *scan;
    cache *c;
    struct stat stbuf;

    /* verify that db is valid & doesn't exist */
    if ((c = findcache(db)) == NULL || c->loaded || stat(c->db, &stbuf) >= 0) {
	return (-1);
    }

    /* make user's subdirectory if needed */
    if (!strncmp(db, PRIVPREFIX, PRIVPREFIXLEN)) {
	scan = strchr(c->db + PREFIXLEN + PRIVPREFIXLEN + 2, '/');
	if (scan == NULL) return (-1);
	*scan = '\0';
	mkdir(c->db, 0700);
	*scan = '/';
    }

    /* create datafile */
    if ((fd = open(c->db, O_WRONLY | O_CREAT, 0600)) < 0 || close(fd) < 0) {
	return (-1);
    }

    return (0);
}

/* delete a database.  fails if database isn't deletable.
 * returns -1 on failure, 0 on success
 */
int sdb_delete(db)
    char *db;
{
    char lname[MAXDBPATHLEN];
    cache *c;
    
    if ((c = findcache(db)) == NULL || c->locks) return (-1);

    /* remove file and empty cache */
    if (unlink(c->db) < 0) return (-1);
    freecache(c);

    /* try removing user directory for cleanliness sake */
    if (!strncmp(db, PRIVPREFIX, PRIVPREFIXLEN)) {
	strcpy(lname, c->db);
	*strrchr(lname, '/') = '\0';
	rmdir(lname);
    }

    return (0);
}


/* copy the contents of one database to another
 *  returns -1 on failure, 0 on success
 */
int sdb_copy(dbsrc, dbdst, flags)
    char *dbsrc, *dbdst;
    int flags;
{
    cache *citem;
    char dbname[MAXDBPATHLEN+1];
    int fd=0, result;

    /* create the destination. this locks and prevents another
    * rename from happening. */
    if (sdb_create(dbdst) < 0) {
      return (-1);
    }

    if ((citem = findcache(dbdst)) == NULL) {
      sdb_delete(dbdst);
      return (-1);
    }
    strcpy(dbname, citem->db);
    /* grab lock on destination */
    if ((fd = open(dbname, O_RDWR|O_CREAT, 0600)) < 0) {
      sdb_delete(dbdst);
      return (-1);
    }

    if (lock_reopen(fd, citem->db, NULL, NULL) < 0) {
      sdb_delete(dbdst);
      close(fd);
      return (-1);
    }
    /* make sure files are valid */
    if (((citem = findcache(dbsrc)) == NULL) || citem->locks) {
      sdb_delete(dbdst);
      return (-1);
    }

    /* read in source */
    if (loadcache(citem, flags) < 0) {
	lock_unlock(fd);
	close(fd);
	return (-1);
    }

    /* change cache to be the destination */
    citem->fd = fd;
    strcpy(citem->db, dbname);

    /* write the cache & unlock file */
    result = writecache(citem);

    return (result);
}

/* get value of a key
 * on return, value points to a string which shouldn't be modified and may
 * change on future sdb_* calls.
 * returns -1 on failure, 0 on success
 */
int sdb_get(db, key, flags, value)
    char *db, *key;
    int flags;
    char **value;
{
    cache *c;
    sdb_keyvalue *kv;

    /* get db in cache */
    c = findcache(db);
    if (c == NULL) {
	return(-1);
    }
    if (c->loaded == 0) {
	if (loadcache(c, flags) < 0) {
	    return (-1);
	}
    }

    /* if db empty, return no value */
    if (!c->cachecount) {
	*value = NULL;
	return (0);
    }

    /* do binary search */
    kv = kv_bsearch(key, c->kv, c->cachecount,
		    (flags & SDB_ICASE) ? strcasecmp : strcmp);
    *value = kv ? kv->value : NULL;

    return (0);
}

/* count the number of keys in a database
 *  returns -1 on failure, number of keys on success
 */
int sdb_count(db, flags)
    char *db;
    int flags;
{
    cache *c;

    /* get db in cache */
    c = findcache(db);
    if (c == NULL) {
	return(-1);
    }
    if (c->loaded == 0) {
	if (loadcache(c, flags) < 0) {
	    return (-1);
	}
    }

    return (c->cachecount);
}

/* check if a value matches a value pattern
 *  return 0 for match, 1 for no match, -1 for error
 */
static int valuematch(vpat, value)
    char *vpat, *value;
{
    glob *vg;
    int result;
    
    if (vpat == NULL) return (0);
    /*XXX: ?need to do international string check here */
    if ((vg = glob_init(vpat, 0)) == NULL) return (-1);
    result = GLOB_TEST(vg, value);
    glob_free(&vg);

    return (result >= 0 ? 0 : 1);
}

/* get keys & values that match a key wildcard (using '*' and '%')
 *  kv is set to a key/value array, count is set to the number of items in kv
 *  Caller must call sdb_freematch with kv when done.
 *  If the copy flag is 1, all data returned will be copied and may be used
 *  indefinitely.  If the copy flag is 0, then only the kv array will be
 *  copied as necessary.  If copy flag is 0, the data may become invalid on any
 *  future sdb_* call.
 * returns -1 on failure, 0 on success
 */

/* HISTORY
 * IncrDev Feb 22, 1996 by sh: to not depend on pseudo memory mapping
 * END HISTORY */

int sdb_match(db, key, flags, vpat, copy, pkv, count)
    char* db;				/* I: database name to match against */
    char* key;				/* I: key to match against */
    int flags;				/* I: case selection flag */
    char *vpat;				/* I: match pattern */
    int copy;				/* I: return full copy of matched kv pairs */
    sdb_keyvalue **pkv;			/* O: matching kv pairs */
    int *count;				/* O: number of matching kb pairs */
{
    int i;				/* loop counter */
    char *scan, *value;
    cache *c;
    sdb_keyvalue *ksrc, *kdst;
    glob *g, *vg;
    int gcount, copysize;

    /* initialization */
    *pkv = NULL;
    *count = 0;
    
    /* if vpat is "*", set it to NULL */
    if (vpat != NULL && vpat[0] == '*' && vpat[1] == '\0') vpat = NULL;
    
    /* get db in cache */
    c = findcache(db);
    if (c == NULL) {
	return(-1);
    }
    if (c->loaded == 0) {
	if (loadcache(c, flags) < 0) {
	    return (-1);
	}
    }

    /* if db empty, return no match */
    if (!c->cachecount) {
	return (0);
    }
    
   /* special case for no wildcards */
    for (scan = key; *scan != '*' && *scan != '%' && *scan != '?' && *scan;
	 ++scan);
    if (!*scan) {

	/* do binary search */
	ksrc = kv_bsearch(key, c->kv, c->cachecount,
			  (flags & SDB_ICASE) ? strcasecmp : strcmp);
	if (ksrc && valuematch(vpat, value = ksrc->value) == 0) {
	    key = ksrc->key;
	    kdst = *pkv = (sdb_keyvalue *)
		malloc(sizeof (sdb_keyvalue)
		       + (copy ? strlen(key) + strlen(value) + 2 : 0));
	    if (kdst == NULL) return (-1);
	    kdst->key = key;
	    kdst->value = value;
	    *count = 1;
	    if (copy) {
		scan = (char *) (kdst + 1);
		kdst->key = scan;
		while (*scan++ = *key++);
		kdst->value = scan;
		while (*scan++ = *value++);
	    }
	}
	return (0);
    }

    /* set key to NULL if it's a "*" */
    if (key[0] == '*' && key[1] == '\0') key = NULL;

    /* make space for a complete match -- we can reduce usage later */
    kdst = *pkv = (sdb_keyvalue *) malloc(sizeof (sdb_keyvalue) * c->cachecount);
    if (kdst == NULL) {
	return (-1);
    }
    memset(kdst, '\0', (sizeof(sdb_keyvalue) * c->cachecount));
    ksrc = c->kv;

    /* special case for full match */
    if (!key && !vpat) {
	memcpy((void *) kdst, (void *) ksrc, c->cachecount * sizeof (sdb_keyvalue));
	kdst += c->cachecount;
    } else {
	/* do globbing */
	if (key && (g = glob_init(key, (flags & SDB_ICASE) ? GLOB_ICASE : 0L))
	    == NULL) {
	    free((char *) kdst);
	    return (-1);
	}
	if (vpat && (vg = glob_init(vpat, (flags & SDB_ICASE) ? GLOB_ICASE:0L))
	    == NULL) {
	    if (key) glob_free(&g);
	    free((char *) kdst);
	    return (-1);
	}
	if (key && !vpat) {
	    for (gcount = c->cachecount; gcount; --gcount, ++ksrc) {
		if (GLOB_TEST(g, ksrc->key) >= 0) {
		    *kdst++ = *ksrc;
		}
	    }
	} else if (vpat && !key) {
	    for (gcount = c->cachecount; gcount; --gcount, ++ksrc) {
		if (GLOB_TEST(vg, ksrc->value) >= 0) {
		    *kdst++ = *ksrc;
		}
	    }
	} else {
	    for (gcount = c->cachecount; gcount; --gcount, ++ksrc) {
		if (GLOB_TEST(g, ksrc->key) >= 0
		    && GLOB_TEST(vg, ksrc->value) >= 0) {
		    *kdst++ = *ksrc;
		}
	    }
	}
	if (vpat) glob_free(&vg);
	if (key) glob_free(&g);

	/* check for no match */
	if (kdst == *pkv) {
	    free((char *) kdst);
	    *pkv = NULL;
	    *count = 0;
	    return (0);
	}
    }

    /* calculate the number of keyvalue pairs that matched */
    *count = kdst - *pkv;

    /* adjust down amount of space used by the match array */
    if (*count < c->cachecount) {
	*pkv = (sdb_keyvalue *) realloc((char *) *pkv, (*count * sizeof(sdb_keyvalue)));
    }

    /* if copy requested then walk the match array duplicating contents */
    if (copy) {
	kdst = *pkv + *count;
	for (ksrc = *pkv, i = 0; ksrc < kdst; ++ksrc, i++) {
	    value = ksrc->key;
	    ksrc->key = strdup(value);
	    if (ksrc->key == NULL) {
		sdb_freematch(*pkv, i, copy);
		*pkv = NULL;
		return(-1);
	    }

	    if(ksrc->value) {
		value = ksrc->value;
		ksrc->value = strdup(value);
	    }
	    
	    if (ksrc->value == NULL) {
		sdb_freematch(*pkv, i, copy);
		*pkv = NULL;
		return(-1);
	    }
	}
    }

    /* cleanup and return success if there was a match */
    return (*pkv == NULL ? -1 : 0);
}

/*  */

/* free keyvalue list returned by sdb_match
 */

/* HISTORY
 * IncrDev Feb 22, 1996 by sh: change interface contract 
 * IncrDev Feb 22, 1996 by sh: modified to walk list to free elements
 * END HISTORY */

void sdb_freematch(kv, count, copy)
    sdb_keyvalue *kv;
    int count;
    int copy;
{
    int i;				/* loop counter */

    /* sanity checks */
    if (kv == NULL) {
	return;
    }

    /* if the list is a copy then walk the kv list freeing keys and values */
    if (copy) {
	for (i = 0; i < count; i++) {
	    if (kv[i].key != NULL) free(kv[i].key);
	    if (kv[i].value != NULL) free(kv[i].value);
	}
    }

    /* free the keyvalue list */
    free((char *) kv);
}

/*  */

/* unlock a key
 * returns -1 on failure, 0 on success
 */

/* HISTORY
 * IncrDev Feb 23, 1996 by sh: to check for under locking
 * END HISTORY */

int sdb_unlock(db, key, flags)
    char *db, *key;
    int flags;
{
    cache *c;

    /* CLAIM - to unlock a cache, it *must* have been locked and therefore loaded.
       If we look for the cache and it is not instantiated, then there is a big
       problem. */
    /* find the appropriate cache entry */
    c = findcache(db);
    if (c == NULL) return (-1);

    /* if there are no locks then just return success */
    if (c->locks == 0) return (0);

    /*XXX: should write the cache if it's been modified */
    /* 11/6/97 - well, the problem is that if you do, performance
     * really blows as say for option_set, you basically do a 
     * lock, set, unlock for each option thereby causing the options db 
     * to be written to disk each time -- probably the right behavior but
     * it makes writes really bad.  So we don't do it. 
     */

    /* decrement the lock count on the cache and if 0, remove lock file */
    c->locks--;
    if (c->locks == 0) {
      lock_unlock(c->fd);
      close(c->fd);
      c->fd = -1;
    }
    
    /* return success */
    return (0);
}

/*  */

/* lock a key to allow local modification -- this may lock a whole set of keys
 * or database as a side effect.  specific key need not exist.
 * returns -1 on error, 0 on success
 */

/* HISTORY
 * IncrDev Feb 23, 1996 by sh: to load cache only if not already loaded
 * END HISTORY */

int sdb_writelock(db, key, flags)
    char *db, *key;
    int flags;
{
    cache *c;

    /* find the appropriate cache entry */
    c = findcache(db);
    if (c == NULL) {
      if (imspd_debug) {
	fprintf(stderr,"failed to find cache\n");
      }
      return(-1);
    }

    /* if the cache is already locked then increment it and return success */
    if (c->locks) {
	++c->locks;
	return (0);
    }

    /* get exclusive lock on database file */
    if (c->fd == -1) {
      c->fd = open(c->db, O_RDWR);
      if (c->fd < 0) return (-1);
    } 
    if (lock_reopen(c->fd, c->db, NULL, NULL) < 0) {
      if (imspd_debug) {
	fprintf(stderr,"failed to reopen\n");
      }
      close(c->fd);
      c->fd = -1;
      return (-1);
    }
    /* load the cache if necessary */
    if (c->loaded == 0) {
	if (loadcache(c, flags) < 0) {
	  if (imspd_debug) {
	    fprintf(stderr,"failed to load cache\n");
	  }
	    return (-1);
	}
    }
    ++c->locks;

    /* return success */
    return (0);
}

/*  */

/* set the value for a key -- key must be locked
 * returns -1 on failure, 0 on success
 */

/* HISTORY
 * Integ__ Feb 27, 1996 by sh: to handle 0 size cache case
 * IncrDev Feb 21, 1996 by sh: to grow cache by CACHE_INCREMENT
 * IncrDev Feb 18, 1996 by sh: removed cache rewriting - now done in sdb_done
 * END HISTORY */

int sdb_set(db, key, flags, value)
    char *db, *key, *value;
    int flags;
{
    cache *c;
    long size;				/* allocation size in bytes */
    int top, bot, mid, cmp;
    sdb_keyvalue *kvtop, *kvmid;
    int (*cmpf)() = (flags & SDB_ICASE) ? strcasecmp : strcmp;

    /* find the appropriate cache entry & make sure it's locked */
    if ((c = findcache(db)) == NULL || !c->locks) return (-1);

    /* if db not empty, look for the key */
    mid = 0;
    if (c->cachecount) {
	/* do binary search */
	top = c->cachecount - 1;
	bot = 0;
	while (bot <= top
	       && (cmp = (*cmpf)(key, c->kv[mid=(bot+top)>>1].key))) {
	    if (cmp < 0) {
		top = mid - 1;
	    } else {
		bot = mid + 1;
	    }
	}

	/* if we matched then set the value in the cache */
	if (!cmp) {
	    if (c->kv[mid].value != NULL) free(c->kv[mid].value);
	    c->kv[mid].value = strdup(value);
	    c->modified = 1;
	    return(0);
	}
	if (cmp > 0) ++mid;
    }

    /* grow the cache if necessary */
    if ((c->cachecount + 1) > c->cachesize) {
	size = ((c->cachesize + CACHE_INCREMENT) * sizeof(sdb_keyvalue));
	if (c->kv == NULL) {
	    c->kv = (sdb_keyvalue *) malloc(size);
	}
	else {
	    c->kv = (sdb_keyvalue *) realloc((void *)c->kv, size);
	}
	if (c->kv == NULL) {
	    freecache(c);
	    return(-1);
	}
	c->cachesize += CACHE_INCREMENT;
    }

    /* instantiate the new keyvalue pair */
    c->cachecount++;
    kvtop = c->kv + (c->cachecount - 1);
    kvmid = c->kv + mid;
    while (kvtop > kvmid) {
	*kvtop = *(kvtop - 1);
	--kvtop;
    }
    kvmid->key = strdup(key);
    kvmid->value = strdup(value);

    /* mark the cache as modified */
    c->modified = 1;

    /* return success */
    return (0);
}

/* remove the entry for a key
 * returns -1 on failure, 0 on success
 */

/* HISTORY
 * Integ__ Feb 23, 1996 by sh: forgot to free removed element key and value
 * IncrDev Feb 18, 1996 by sh: removed cache rewriting - now done in sdb_done
 * END HISTORY */

int sdb_remove(db, key, flags)
    char *db, *key;
    int flags;
{
    cache *c;
    sdb_keyvalue *kvtop, *kvmid;

    /* find the appropriate cache entry & make sure it's locked */
    if ((c = findcache(db)) == NULL || !c->locks) return (-1);

    /* if db not empty, look for the key */
    if (!c->cachecount) return (-1);
    
    /* do binary search */
    kvmid = kv_bsearch(key, c->kv, c->cachecount,
		       (flags & SDB_ICASE) ? strcasecmp : strcmp);
    if (!kvmid) return (-1);
    if (kvmid->key != NULL) free(kvmid->key);
    if (kvmid->value != NULL) free(kvmid->value);

    /* remove the key pair from the cache */
    kvtop = c->kv + --c->cachecount;
    while (kvmid < kvtop) {
	kvmid[0] = kvmid[1];
	++kvmid;
    }

    /* mark the cache as modified */
    c->modified = 1;

    /* return success */
    return (0);
}
