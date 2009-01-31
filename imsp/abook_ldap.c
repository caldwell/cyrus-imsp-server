/* abook_ldap.c  --  address books implemented via LDAP lookups
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <ldap.h>
#include <strings.h>
#include "xmalloc.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"
#include "authize.h"
#include "exitcodes.h"
#include "abook.h"
#include "abook_ldap.h"

#define ATTRMAPSIZE 20

struct map_pair {
  char *field;
  char *attr;
  char *append;
};

struct ldap_config {
    int configured;
    char *searchbase;
    int scope;
    char *ldaphost;
    int ldapport;
    char *fullnameattr;
    char *uniqueattr;
    char *defaultfilter;
    struct map_pair map[ATTRMAPSIZE];
};

static struct ldap_config config = {0};
static struct ldap_config secondaryconfig = {0};

static char opt_ldap_searchbase[]	= "imsp.ldap.searchbase";
static char opt_ldap_scope[]		= "imsp.ldap.scope";
static char opt_ldap_ldaphost[]		= "imsp.ldap.host";
static char opt_ldap_ldapport[]		= "imsp.ldap.port";
static char opt_ldap_fullnameattr[]	= "imsp.ldap.fullnameattr";
static char opt_ldap_uniqueattr[]	= "imsp.ldap.uniqueattr";
static char opt_ldap_defaultfilter[]	= "imsp.ldap.defaultfilter";
static char opt_ldap_attrmap[]		= "imsp.ldap.attrmap";
/*
 * appendmap is used to append a string onto the end of an
 * attribute before returning it to the client.  useful for
 * fully qualifing an email address.  turn foo into foo@bar.baz
 * by doing something like:
 * imsp.ldap.appendmap N (email "@bar.baz")
 * in your options file.
 */
static char opt_ldap_appendmap[]	= "imsp.ldap.appendmap";

/*
 * If imsp.ldap.secondary.searchbase is defined in the options file,
 * then use these settings as a backup search if and only if the search
 * using the primary LDAP settings returns no entries.
 * 
 * If the scope, host, and port options are undefined, they
 * will be inherited from the primary settings.
 *
 * 9-Nov-2001 jeaton@andrew.cmu.edu
 */
static char opt_ldap_secondary_searchbase[]	= "imsp.ldap.secondary.searchbase";
static char opt_ldap_secondary_scope[]		= "imsp.ldap.secondary.scope";
static char opt_ldap_secondary_ldaphost[]	= "imsp.ldap.secondary.host";
static char opt_ldap_secondary_ldapport[]	= "imsp.ldap.secondary.port";
static char opt_ldap_secondary_fullnameattr[]	= "imsp.ldap.secondary.fullnameattr";
static char opt_ldap_secondary_uniqueattr[]	= "imsp.ldap.secondary.uniqueattr";
static char opt_ldap_secondary_defaultfilter[]	= "imsp.ldap.secondary.defaultfilter";
static char opt_ldap_secondary_attrmap[]	= "imsp.ldap.secondary.attrmap";
static char opt_ldap_secondary_appendmap[]	= "imsp.ldap.secondary.appendmap";

static char err_ldap_missing[] = 
    "Missing LDAP setting in global options file: %s";
static char err_ldap_badvalue[] =
    "Illegal value for LDAP option in global options file: %s";

static void
config_error(char *reason, char *optname)
{
    syslog(LOG_ERR, reason, optname);
}

static int
config_ldap(void)
{
    int i = 0, j = 0;
    char *value;
    option_list *mapping;

    if (!config.configured) {
	/*
	syslog(LOG_NOTICE, "Configuring the LDAP settings for the first time");
	*/

	/* Search Base */
	value = option_get("", opt_ldap_searchbase, 1, NULL);
	if (value) {
	    config.searchbase = strdup(value);
	} else {
	    config_error(err_ldap_missing, opt_ldap_searchbase);
	    return -1;
	}

	/* Scope */
	value = option_get("", opt_ldap_scope, 1, NULL);
	if (value) {
	    if (strcasecmp(value, "subtree") == 0) {
		config.scope = LDAP_SCOPE_SUBTREE;
	    } else if (strcasecmp(value, "base") == 0) {
		config.scope = LDAP_SCOPE_BASE;
	    } else if (strcasecmp(value, "onelevel") == 0) {
		config.scope = LDAP_SCOPE_ONELEVEL;
	    } else {
		config_error(err_ldap_badvalue, opt_ldap_scope);
		return -1;
	    }
	} else {
	    config_error(err_ldap_missing, opt_ldap_scope);
	    return -1;
	}

	/* LDAP Server Hostname */
	value = option_get("", opt_ldap_ldaphost, 1, NULL);
	if (value) {
	    config.ldaphost = strdup(value);
	} else {
	    config_error(err_ldap_missing, opt_ldap_ldaphost);
	    return -1;
	}

	/* LDAP Server Port Number */
	value = option_get("", opt_ldap_ldapport, 1);
	if (value) {
	    config.ldapport = atoi(value);
	} else {
	    config.ldapport = LDAP_PORT;
	}

	/* Fullname Attribute */
	value = option_get("", opt_ldap_fullnameattr, 1, NULL);
	if (value) {
	    config.fullnameattr = strdup(value);
	} else {
	    config_error(err_ldap_missing, opt_ldap_fullnameattr);
	    return -1;
	}

	/* Unique Attribute */
	value = option_get("", opt_ldap_uniqueattr, 1, NULL);
	if (value) {
	    config.uniqueattr = strdup(value);
	} else {
	    config_error(err_ldap_missing, opt_ldap_uniqueattr);
	    return -1;
	}

	/* Default Search Filter */
	value = option_get("", opt_ldap_defaultfilter, 1, NULL);
	if (value) {
	    config.defaultfilter = strdup(value);
	} else {
	    config_error(err_ldap_missing, opt_ldap_defaultfilter);
	    return -1;
	}

	/* Mapping from IMSP fields to LDAP attributes */
	mapping = option_getlist("", opt_ldap_attrmap, 1);
	if (mapping == NULL) {
	    config_error(err_ldap_missing, opt_ldap_attrmap);
	    return -1;
	}
	/* there must be an even number of items to form pairs */
	if (mapping->count == 0 || 
	    (mapping->count % 2) != 0 ||
	    (mapping->count / 2) > ATTRMAPSIZE) {
	  config_error(err_ldap_badvalue, opt_ldap_attrmap);
	  return -1;
	}

	/* step through the items in the map option,
	   assigning them alternatively to the "field" and "value"
	   halfs of the map structure.
	*/
	for (i = 0; i < mapping->count; i++) {
	  if (strcasecmp(mapping->item[i], "null") == 0)
	    value = NULL;
	  else
	    value = strdup(mapping->item[i]);
	  if (i % 2 == 0)
	    config.map[i / 2].field = value;
	  else
	    config.map[i / 2].attr  = value;

	  config.map[i / 2].append = NULL;
	}
	/* add a null terminator pair at the end */
	config.map[i / 2].field = NULL;
	config.map[i / 2].attr  = NULL;

	/* appendmap */
	mapping = option_getlist("", opt_ldap_appendmap, 1);
	if (mapping != NULL) {
	  if (mapping->count == 0 ||
	    (mapping->count % 2) != 0 ||
	    (mapping->count / 2) > ATTRMAPSIZE) {
	    config_error(err_ldap_badvalue, opt_ldap_appendmap);
	    return -1;
	  }
	  /*
	   * step through the items in the appendmap,
	   * assigning them to the "append" field of the
	   * map structure, where necessary
	   */
	  for (i = 0; i < mapping->count; i++) {
	    for (j = 0; config.map[j].field != NULL ; j++) {
	      if (strcmp(mapping->item[i], config.map[j].field) == 0) {
		i++;
		config.map[j].append = strdup(mapping->item[i]);
	      }
	    }
	  }
	}

	/* Secondary search settings, if applicable */
	value = option_get("", opt_ldap_secondary_searchbase, 1, NULL);
	if (value) {
	  secondaryconfig.searchbase = strdup(value);

	  /* Scope */
	  value = option_get("", opt_ldap_secondary_scope, 1, NULL);
	  if (value) {
	    if (strcasecmp(value, "subtree") == 0) {
	      secondaryconfig.scope = LDAP_SCOPE_SUBTREE;
	    } else if (strcasecmp(value, "base") == 0) {
	      secondaryconfig.scope = LDAP_SCOPE_BASE;
	    } else if (strcasecmp(value, "onelevel") == 0) {
	      secondaryconfig.scope = LDAP_SCOPE_ONELEVEL;
	    } else {
	      config_error(err_ldap_badvalue, opt_ldap_secondary_scope);
	      return -1;
	    }
	  } else {
	    secondaryconfig.scope = config.scope;
	  }
	  
	  /* LDAP Server Hostname */
	  value = option_get("", opt_ldap_secondary_ldaphost, 1, NULL);
	  if (value) {
	    secondaryconfig.ldaphost = strdup(value);
	  } else {
	    secondaryconfig.ldaphost = strdup(config.ldaphost);
	  }
	  
	  /* LDAP Server Port Number */
	  value = option_get("", opt_ldap_secondary_ldapport, 1);
	  if (value) {
	    secondaryconfig.ldapport = atoi(value);
	  } else {
	    secondaryconfig.ldapport = config.ldapport;
	  }
	  
	  /* Fullname Attribute */
	  value = option_get("", opt_ldap_secondary_fullnameattr, 1, NULL);
	  if (value) {
	    secondaryconfig.fullnameattr = strdup(value);
	  } else {
	    secondaryconfig.fullnameattr = strdup(config.fullnameattr);
	  }
	  
	  /* Unique Attribute */
	  value = option_get("", opt_ldap_secondary_uniqueattr, 1, NULL);
	  if (value) {
	    secondaryconfig.uniqueattr = strdup(value);
	  } else {
	    secondaryconfig.uniqueattr = strdup(config.uniqueattr);
	  }
	  
	  /* Default Search Filter */
	  value = option_get("", opt_ldap_secondary_defaultfilter, 1, NULL);
	  if (value) {
	    secondaryconfig.defaultfilter = strdup(value);
	  } else {
	    secondaryconfig.defaultfilter = strdup(config.defaultfilter);
	  }
	  
	  /* Mapping from IMSP fields to LDAP attributes */
	  mapping = option_getlist("", opt_ldap_secondary_attrmap, 1);
	  if (mapping == NULL) {
	    mapping = mapping;
	  }
	  /* there must be an even number of items to form pairs */
	  if (mapping->count == 0 || 
	      (mapping->count % 2) != 0 ||
	      (mapping->count / 2) > ATTRMAPSIZE) {
	    config_error(err_ldap_badvalue, opt_ldap_secondary_attrmap);
	    return -1;
	  }
	  
	  /* step through the items in the map option,
	     assigning them alternatively to the "field" and "value"
	     halfs of the map structure.
	  */
	  for (i = 0; i < mapping->count; i++) {
	    if (strcasecmp(mapping->item[i], "null") == 0)
	      value = NULL;
	    else
	      value = strdup(mapping->item[i]);
	    if (i % 2 == 0)
	      secondaryconfig.map[i / 2].field = value;
	    else
	      secondaryconfig.map[i / 2].attr  = value;

	    secondaryconfig.map[i / 2].append = NULL;
	  }
	  /* add a null terminator pair at the end */
	  secondaryconfig.map[i / 2].field = NULL;
	  secondaryconfig.map[i / 2].attr  = NULL;

	  /* appendmap */
	  mapping = option_getlist("", opt_ldap_secondary_appendmap, 1);
	  if (mapping != NULL) {
	    if (mapping->count == 0 ||
		(mapping->count % 2) != 0 ||
		(mapping->count / 2) > ATTRMAPSIZE) {
	      config_error(err_ldap_badvalue, opt_ldap_secondary_appendmap);
	      return -1;
	    }
	    /*
	     * step through the items in the appendmap,
	     * assigning them to the "append" field of the
	     * map structure, where necessary
	     */
	    for (i = 0; i < mapping->count; i++) {
	      for (j = 0; secondaryconfig.map[j].field != NULL ; j++) {
		if (strcmp(mapping->item[i], secondaryconfig.map[j].field) == 0) {
		  i++;
		  secondaryconfig.map[j].append = strdup(mapping->item[i]);
		}
	      }
	    }
	  }

	  secondaryconfig.configured = 1;
	} else {
	  /* no secondary search defined */
	}
        config.configured = 1;
    }
    
    return 0;
}

/* Convert an IMSP search specification to an LDAP search filter.
 * Returns 0 on success, setting "filter" to the resulting filter.
 * Returns -1 if none of the IMSP fields could be converted to an
 * LDAP attribute.
 */
static int
imsp_to_ldap_filter(abook_fielddata *flist, int fcount, char **filter,
		    struct ldap_config ldapconfig)
{
    int i, j;
    static char filt[2048];
    int filter_is_empty = 1;

    strlcpy(filt, "(&", sizeof(filt));
    strlcat(filt, ldapconfig.defaultfilter, sizeof(filt));

    for (i = 0; i < fcount; i++) {
	for (j = 0; ldapconfig.map[j].field != NULL; j++) {
	    if ((strcasecmp(flist[i].field, ldapconfig.map[j].field) == 0)) {
		if (ldapconfig.map[j].attr == NULL) {
		    syslog(LOG_ERR, "imsp_to_ldap_filter: skipping unmapped"
			   " field '%s'", flist[i].field);
		} else {
		    filter_is_empty = 0;
		    strlcat(filt, "(", sizeof(filt));
		    strlcat(filt, ldapconfig.map[j].attr, sizeof(filt));
		    strlcat(filt, "=", sizeof(filt));
		    strlcat(filt, flist[i].data, sizeof(filt));
		    strlcat(filt, ")", sizeof(filt));
		}
		break;
	    }
	}
	if (ldapconfig.map[j].field == NULL) {
	    syslog(LOG_ERR, "imsp_to_ldap_filter: skipping unknown"
		   " field '%s'", flist[i].field);
	}
    }

    strlcat(filt, ")", sizeof(filt));
    /* syslog(LOG_NOTICE, "Filter: %s", filt); */

    if (filter_is_empty) {
	return -1;
    } else {
	*filter = filt;
	return 0;
    }
}


int
abook_ldap_searchstart(abook_ldap_state **ldap_state, 
		       abook_fielddata *flist, int fcount)
{
    abook_ldap_state *mystate;
    int msgid, rc;
    int sizelimit;
    char *msg;
    char *attrs[20];
    LDAP *ld;
    LDAPMessage *result;
    char *filter, *secondaryfilter;

    int searching_secondary = 0;

    if (config_ldap() < 0) {
	syslog(LOG_ERR, "abook_ldap_searchstart: failed to configure LDAP");
	return -1;
    }
    
    if (imsp_to_ldap_filter(flist, fcount, &filter, config) < 0) {
	syslog(LOG_ERR, "abook_ldap_searchstart: failed to convert filter");
	return -1;
    }

    ld = ldap_init(config.ldaphost, config.ldapport);
    if (ld == NULL) {
	syslog(LOG_ERR, "abook_ldap_searchstart: LDAP init failed: %s",
	       strerror(errno));
	return -1;
    }

    rc = ldap_simple_bind_s(ld, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "abook_ldap_searchstart: simple bind failed: %s",
	       ldap_err2string(rc));
	return -1;
    }

    /* For testing the error handlers...
      sizelimit = 4;
      ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
    */
    attrs[0] = config.fullnameattr;
    attrs[1] = config.uniqueattr;
    attrs[2] = NULL;

    msgid = ldap_search(ld, config.searchbase, config.scope, 
			filter, attrs, 0/*attrs-only*/);
    if (msgid == -1) {
	syslog(LOG_ERR, "abook_ldap_searchstart: LDAP search failed");
	ldap_unbind(ld);
	return -1;
    }

    rc = ldap_result(ld, msgid, 0, NULL, &result);

    switch (rc) {
    case LDAP_RES_SEARCH_ENTRY:
      /* Do nothing here. The abook_search function will pull out this
       * entry and send it back for display to the user.
       * The result is freed later.
       */
      break;
      
    case LDAP_RES_SEARCH_RESULT:
      rc = ldap_result2error(ld, result, 1 /* free result */);
      if (rc == LDAP_SUCCESS) {
	/* 
	 * Search returned successfully, but with no matching entries.
	 * 
	 * Try to do the secondary search, if configured to do so.
	 * fails, then set the prevresult to NULL.
	 */
	if (secondaryconfig.ldaphost) {
	  searching_secondary = 1;

	  /* close the connection to the primary ldap server */
	  ldap_unbind(ld);
	  
	  if (imsp_to_ldap_filter(flist, fcount, &secondaryfilter, 
				  secondaryconfig) < 0) {
	    syslog(LOG_ERR, "abook_ldap_searchstart: failed to convert filter");
	      return -1;
	  }
	  
	  /* open connection to the secondary server */
	  ld = ldap_init(secondaryconfig.ldaphost, secondaryconfig.ldapport);
	  if (ld == NULL) {
	      syslog(LOG_ERR, "abook_ldap_searchstart: LDAP init failed: %s",
		     strerror(errno));
	      return -1;
	  }
	  
	  rc = ldap_simple_bind_s(ld, NULL, NULL);
	  if (rc != LDAP_SUCCESS) {
	    syslog(LOG_ERR, "abook_ldap_searchstart: simple bind failed: %s",
		   ldap_err2string(rc));
	    return -1;
	  }
	  
	  attrs[0] = secondaryconfig.fullnameattr;
	  attrs[1] = secondaryconfig.uniqueattr;
	  attrs[2] = NULL;
	  
	  msgid = ldap_search(ld, secondaryconfig.searchbase, 
			      secondaryconfig.scope, secondaryfilter, 
			      attrs, 0 /*attrs-only*/);
	  if (msgid == -1) {
	    syslog(LOG_ERR, "abook_ldap_searchstart: LDAP search failed");
	    ldap_unbind(ld);
	    return -1;
	  }
	  
	  rc = ldap_result(ld, msgid, 0, NULL, &result);
	  
	  switch (rc) {
	  case LDAP_RES_SEARCH_ENTRY:
	    /* Do nothing here. The abook_search function will pull out this
	     * entry and send it back for display to the user.
	     * The result is freed later.
	     */
	    break;
	    
	  case LDAP_RES_SEARCH_RESULT:
	    /* Still didn't get any data.  Send a null "prevresult" to the
	     * abook_search function.
	     */
	    result = NULL;
	    break;
	    
	  default:
	    syslog(LOG_ERR, "abook_ldap_searchstart: ldap_result failed: %s (%d)",
		   ldap_err2string(rc), rc);
	    (void) ldap_msgfree(result);  /* ignore message type return value */
	    ldap_unbind(ld); 
	    return -1;
	  }

	} /* if (secondaryconfig.ldaphost) */

      } else {
	syslog(LOG_ERR,"abook_ldap_searchstart: search returned error: %s",
	       ldap_err2string(rc));
	ldap_unbind(ld);
	return -1;
      }
      break;
      
    default:
      syslog(LOG_ERR, "abook_ldap_searchstart: ldap_result failed: A1 SEARCHADDRESS %s",
	     ldap_err2string(rc));
      (void) ldap_msgfree(result);  /* ignore message type return value */
      ldap_unbind(ld);
      return -1;
    }
    
    mystate = (abook_ldap_state *) malloc (sizeof (abook_ldap_state));
    *ldap_state = mystate;
    
    if (mystate == NULL) {
      syslog(LOG_ERR, "abook_ldap_searchstart: Out of memory");
      (void) ldap_msgfree(result);  /* ignore message type return value */
      ldap_unbind(ld);
      return -1;
    }
    
    mystate->ld = ld;
    mystate->msgid = msgid;
    mystate->prevresult = result;

    if (searching_secondary == 0) {
      mystate->ldapconfig = &config;
    } else {
      mystate->ldapconfig = &secondaryconfig;
    }
    
    return 0;
}


static int
count_identical_fullnames(abook_ldap_state *ldap_state, char *alias)
{
    int rc, count = 0;
    char filter[1024];
    LDAPMessage *results;

    /* 
     * To limit the work done for this search, look for some bogus attribute 
     * that's probably not in the entry and don't return any values.
     */
    char *attrs[] = {"c", NULL};

    snprintf(filter, sizeof(filter), "(&%s(%s=%s))", config.defaultfilter, 
	    config.fullnameattr, alias);
    rc = ldap_search_s(ldap_state->ld, config.searchbase, config.scope,
		       filter, attrs, 1 /*attrs-only*/, &results);
    if (rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "count_identical_fullnames: search failed: %s",
	       ldap_err2string(rc));
	count = -1;
    } else {
	count = ldap_count_entries(ldap_state->ld, results);
	/* Returns -1 on error, so just pass that back to the caller */
	(void) ldap_msgfree(results);  /* ignore message type return value */
    }

    return count;
}

char *
abook_ldap_search(abook_ldap_state *ldap_state)
{
    int rc, count;
    LDAP *ld;
    int msgid;
    LDAPMessage *result, *entry;
    char *dn;
    static char alias[1024];
    char **values;
    struct ldap_config* ldapconfig;

    if (ldap_state->prevresult == NULL) {
      /* prevresult is set to NULL when the prior call to ldap_result 
       * indicated that the search ended successfully.
       */
      return NULL;
      
    } else {
      ld = ldap_state->ld;
      msgid = ldap_state->msgid;
      result = ldap_state->prevresult;
      ldapconfig = ldap_state->ldapconfig;
      
      /* Find the full name associated with this matching entry so we
       * can return a pointer to it.
       */
      
      entry = ldap_first_entry(ld, result);
      if (entry == NULL) {
	syslog(LOG_ERR, "abook_ldap_search: ldap_first_entry failed");
	return NULL;
      }

      values = ldap_get_values(ld, entry, ldapconfig->fullnameattr);
      if (values == NULL || values[0] == NULL) {
	syslog(LOG_ERR, "abook_ldap_search: ldap_get_values (%s) failed", ldapconfig->fullnameattr);
	return NULL;
      }
      
      strlcpy(alias, values[0], sizeof(alias));
      
      ldap_value_free(values);
      
      values = ldap_get_values(ld, entry, ldapconfig->uniqueattr);
      if (values == NULL || values[0] == NULL) {
	syslog(LOG_ERR, "abook_ldap_search: ldap_get_values (%s) failed", ldapconfig->uniqueattr);
	syslog(LOG_ERR, "abook_ldap_search: previous value (%s) was %s", ldapconfig->fullnameattr, alias);
	return NULL;
      }

      /* always uniqify the fullname, even if we don't have to */
      strlcat(alias, "[", sizeof(alias));
      strlcat(alias, ldapconfig->uniqueattr, sizeof(alias));
      strlcat(alias, ":", sizeof(alias));
      strlcat(alias, values[0], sizeof(alias));
      strlcat(alias, "]", sizeof(alias));
      ldap_value_free(values);
      
#if 0
      count = count_identical_fullnames(ldap_state, alias);
      if (count > 1) {
	/* Find the uid for this entry */
	values = ldap_get_values(ld, entry, ldapconfig->uniqueattr);
	if (values == NULL || values[0] == NULL) {
	  syslog(LOG_ERR, "abook_ldap_search: ldap_get_values failed for attr '%s'", ldapconfig->uniqueattr);
	  return NULL;
	}
	strlcat(alias, "[", sizeof(alias));
	strlcat(alias, ldapconfig->uniqueattr, sizeof(alias));
	strlcat(alias, ":", sizeof(alias));
	strlcat(alias, values[0], sizeof(alias));
	strlcat(alias, "]", sizeof(alias));
	ldap_value_free(values);
      }
#endif
      
      ldap_msgfree(result);
      
      /* Now fetch the next result to get ready for the next iteration
       * of this function.
       */
      
      rc = ldap_result(ld, msgid, 0, NULL, &result);
      
      switch (rc) {
      case LDAP_RES_SEARCH_ENTRY:
	ldap_state->prevresult = result;
	break;
	
      case LDAP_RES_SEARCH_RESULT:
	rc = ldap_result2error(ld, result, 1 /* free result */);
	/* This result had no entries, but indicated success or failure.
	 * Return the alias corresponding to the previous entry,
	 * but set "prevresult" to NULL to indicate to the next 
	 * iteration that searching is completed.
	 */
	if (rc != LDAP_SUCCESS) {
	  syslog(LOG_ERR,"abook_ldap_search: search completed with"
		 " error: %s", ldap_err2string(rc));
	}
	ldap_state->prevresult = NULL;
	break;
	
      default:
	syslog(LOG_ERR, "abook_ldap_search: ldap_result failed: 3: %s",
	       ldap_err2string(rc));
	(void) ldap_msgfree(result); /* ignore message type return value */
	ldap_state->prevresult = NULL;
      }
      
      return alias;
    }
}


void
abook_ldap_searchdone(abook_ldap_state *ldap_state)
{
    ldap_unbind(ldap_state->ld);
    free(ldap_state);
}


abook_fielddata *
abook_ldap_fetch(char *alias, int *count)
{
  int i, rc, ldapcount, mappedfieldcount;
  char *ptr;
  char prefix[1024];
  char filter[1024];
  abook_fielddata *fdata, *fptr;
  char *searchattr;
  char *searchkey;
  LDAP *ld;
  LDAPMessage *results, *entry;
  char **values;
  
  if (config_ldap() < 0) {
    syslog(LOG_ERR, "abook_ldap_fetch: failed to configure LDAP");
    return NULL;
  }
  
  /*
   * Decide how to search for the user.
   */
  
  snprintf(prefix, sizeof(prefix), "[%s:", config.uniqueattr);
  ptr = strstr(alias, prefix);
  if (ptr != NULL) {
    *ptr = '\0';
    ptr += 1 /*[*/ + strlen(config.uniqueattr) + 1 /*:*/;
    searchkey = ptr;
    ptr += strlen(ptr) - 1 /*]*/;
    *ptr = '\0';
    searchattr = config.uniqueattr;
  } else {
    searchkey  = alias;
    searchattr = config.fullnameattr;
  }
  snprintf(filter, sizeof(filter), "(&%s(%s=%s))", config.defaultfilter, 
	  searchattr, searchkey);
  
  ld = ldap_init(config.ldaphost, config.ldapport);
  if (ld == NULL) {
    syslog(LOG_ERR, "abook_ldap_fetch: LDAP init failed: %s",
	   strerror(errno));
    return NULL;
  }
  
  rc = ldap_simple_bind_s(ld, NULL, NULL);
  if (rc != LDAP_SUCCESS) {
    syslog(LOG_ERR, "abook_ldap_fetch: simple bind failed: %s",
	   ldap_err2string(rc));
    return NULL;
  }
  
  rc = ldap_search_s(ld, config.searchbase, config.scope, filter, 
		     NULL/*get all attrs*/, 0/*attrs-only*/, &results);
  if (rc != LDAP_SUCCESS) {
    syslog(LOG_ERR, "abook_ldap_fetch: LDAP search failed: %s",
	   ldap_err2string(rc));
    ldap_unbind(ld);
    return NULL;
    }
  
  ldapcount = ldap_count_entries(ld, results);

  if (ldapcount == 0) {
    /* no matches on primary search, try secondary search if configured */
    
    if (secondaryconfig.ldaphost) {
      
      /* close the connection to the primary server */
      ldap_unbind(ld);

      snprintf(prefix, sizeof(prefix), "[%s:", secondaryconfig.uniqueattr);
      ptr = strstr(alias, prefix);
      if (ptr != NULL) {
	*ptr = '\0';
	ptr += 1 /*[*/ + strlen(secondaryconfig.uniqueattr) + 1 /*:*/;
	searchkey = ptr;
	ptr += strlen(ptr) - 1 /*]*/;
	*ptr = '\0';
	searchattr = secondaryconfig.uniqueattr;
      } else {
	searchkey  = alias;
	searchattr = secondaryconfig.fullnameattr;
      }
      snprintf(filter, sizeof(filter), "(&%s(%s=%s))", secondaryconfig.defaultfilter, 
	      searchattr, searchkey);
      
      ld=ldap_init(secondaryconfig.ldaphost, secondaryconfig.ldapport);
      if (ld == NULL){
	syslog(LOG_ERR, "abook_ldap_fetch: LDAP secondary init failed: %s",
	       strerror(errno));
	return NULL;
      }
      
      rc = ldap_simple_bind_s(ld, NULL, NULL);
      if (rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "abook_ldap_fetch: simple secondary bind failed: %s",
	       ldap_err2string(rc));
	return NULL;
      }
      
      rc = ldap_search_s(ld, secondaryconfig.searchbase, secondaryconfig.scope, filter, 
			 NULL/*get all attrs*/, 0/*attrs-only*/, &results);
      
      if (rc != LDAP_SUCCESS) {
	syslog(LOG_ERR, "abook_ldap_fetch: LDAP secondary search failed: %s",
	       ldap_err2string(rc));
	ldap_unbind(ld);
	return NULL;
      }
      
      ldapcount = ldap_count_entries(ld, results);
      
      if (ldapcount != 1) {
	syslog(LOG_ERR, "abook_ldap_fetch: unexpected count of secondary search"
	       " hits: %d", ldapcount);
	(void) ldap_msgfree(results);  /* ignore message type return value */
	ldap_unbind(ld);
	return NULL;
      }	       
      
      entry = ldap_first_entry(ld, results);
      if (entry == NULL) {
	  syslog(LOG_ERR, "abook_ldap_fetch: ldap_first_entry failed");
	  (void) ldap_msgfree(results);  /* ignore message type return value */
	  ldap_unbind(ld);
	  return NULL;
      }
      
      /* This memory is freed by abook_fetchdone() which is called by 
       * show_address() after it's finished sending the field/data pairs 
       * back to the IMSP client
       */
      
      mappedfieldcount = 0;
      for (i = 0; secondaryconfig.map[i].field != NULL; i++) {
	if (secondaryconfig.map[i].attr != NULL)
	  mappedfieldcount++;
      }
      
      fdata = (abook_fielddata *) 
	malloc(sizeof (abook_fielddata) * mappedfieldcount);
      if (fdata == NULL) {
	syslog(LOG_ERR, "abook_ldap_fetch: Out of memory");
	(void) ldap_msgfree(results);  /* ignore message type return value */
	ldap_unbind(ld);
	return NULL;
      }
      
      *count = 0;
      fptr = fdata;
      
      for (i = 0; secondaryconfig.map[i].field != NULL; i++) {
	if ((secondaryconfig.map[i].attr != NULL) &&
	    (strcmp(secondaryconfig.map[i].attr, secondaryconfig.fullnameattr) != 0)) {
	  values = ldap_get_values(ld, entry, secondaryconfig.map[i].attr);
	  if (values != NULL && values[0] != NULL) {
	    fptr->field = strdup(secondaryconfig.map[i].field);
	    if (secondaryconfig.map[i].append != NULL) {
	      int fptrdatalen = strlen(values[0])+strlen(secondaryconfig.map[i].append)+1;
	      fptr->data=malloc(fptrdatalen);
	      if(!fptr->data) fatal("out of memory", EC_TEMPFAIL);
	      strlcpy(fptr->data, values[0], fptrdatalen);
	      strlcat(fptr->data, secondaryconfig.map[i].append, fptrdatalen);
	    } else {
	      fptr->data  = strdup(values[0]);
	      if(!fptr->data) fatal("out of memory", EC_TEMPFAIL);
	    }
	    (*count)++;
	    fptr++;
	  }
	  if (values != NULL)
	    ldap_value_free(values);
	}
      }
      
      (void) ldap_msgfree(results);  /* ignore message type return value */
      ldap_unbind(ld);
      
      return (fdata);
    }
  }

  if (ldapcount != 1) {
	syslog(LOG_ERR, "abook_ldap_fetch: unexpected count of search"
	       " hits: %d", ldapcount);
	(void) ldap_msgfree(results);  /* ignore message type return value */
	ldap_unbind(ld);
	return NULL;
    }	       

    entry = ldap_first_entry(ld, results);
    if (entry == NULL) {
	syslog(LOG_ERR, "abook_ldap_fetch: ldap_first_entry failed");
	(void) ldap_msgfree(results);  /* ignore message type return value */
	ldap_unbind(ld);
	return NULL;
    }

    /* This memory is freed by abook_fetchdone() which is called by 
     * show_address() after it's finished sending the field/data pairs 
     * back to the IMSP client
     */
    
    mappedfieldcount = 0;
    for (i = 0; config.map[i].field != NULL; i++) {
	if (config.map[i].attr != NULL)
	    mappedfieldcount++;
    }

    fdata = (abook_fielddata *) 
	malloc(sizeof (abook_fielddata) * mappedfieldcount);
    if (fdata == NULL) {
	syslog(LOG_ERR, "abook_ldap_fetch: Out of memory");
	(void) ldap_msgfree(results);  /* ignore message type return value */
	ldap_unbind(ld);
	return NULL;
    }

    *count = 0;
    fptr = fdata;
    
    for (i = 0; config.map[i].field != NULL; i++) {
	if ((config.map[i].attr != NULL) &&
	    (strcmp(config.map[i].attr, config.fullnameattr) != 0)) {
	    values = ldap_get_values(ld, entry, config.map[i].attr);
	    if (values != NULL && values[0] != NULL) {
		fptr->field = strdup(config.map[i].field);
		if (config.map[i].append != NULL) {
		  printf("appending %s to field: %s value: %s\n", config.map[i].append, config.map[i].field,values[0]);

		  fptr->data=malloc(strlen(values[0])+strlen(config.map[i].append)+1);
		  fptr->data=strcat(fptr->data, values[0]);
		  fptr->data=strcat(fptr->data, config.map[i].append);
		} else {
		  fptr->data  = strdup(values[0]);
		}
		(*count)++;
		fptr++;
	    }
	    if (values != NULL)
		ldap_value_free(values);
	}
    }

    (void) ldap_msgfree(results);  /* ignore message type return value */
    ldap_unbind(ld);

    return (fdata);
}
