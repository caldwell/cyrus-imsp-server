/* sasl_support.c -- support routines needed by the SASL API
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 * Author: Joseph Jackson <jackson@CMU.EDU>
 * Start Date: 2/15/00
 */

#include <config.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <sasl/sasl.h>
#include <netinet/in.h>

#include "dispatch.h"
#include "option.h"
#include "syncdb.h"
#include "util.h"
#include "xmalloc.h"

extern struct sockaddr_in imspd_localaddr, imspd_remoteaddr;

static char opt_login_srvtab[] = "imsp.login.srvtab";
static char opt_login_realms[] = "imsp.login.realms";
static char opt_sasl_prefix[]  = "imsp.sasl.";
static char opt_plaintext[]    = "imsp.sasl.allowplaintext";
extern char opt_alladmin[];	/* defined in authize.c */

/* Minimum and maximum security strength factors (how many bits) */
static char opt_min_ssf[]      = "imsp.sasl.minimum_ssf";
static char opt_max_ssf[]      = "imsp.sasl.maximum_ssf";
/* defaults in case the above two options aren't set */
#define MIN_SSF 0
#define MAX_SSF 256

static char err_nocrossrealm[] = "cross-realm login from %s denied";
static char err_noproxy[] = "user is not authorized to proxy for another user";


/*
 * This creates a structure that defines the allowable security properties 
 */
static sasl_security_properties_t *
mysasl_make_secprops(void)
{
    char *value;
    int min, max;
    sasl_security_properties_t *prop;

    prop = (sasl_security_properties_t *) 
	xmalloc(sizeof(sasl_security_properties_t));

    /* Set minimum and maximum security strength factors (how many bits) */
    value = option_get("", opt_min_ssf, 1, NULL);
    if (value) {
	min = atoi(value);
	free(value);
    } else {
	min = MIN_SSF;
    }
    value = option_get("", opt_max_ssf, 1, NULL);
    if (value) {
	max = atoi(value);
	free(value);
    } else {
	max = MAX_SSF;
    }
    if (min < 0 || max <= 0) {
	syslog(LOG_ERR, 
	       "Security strength factor limits look bogus: min=%d, max=%d",
	       min, max);
	/* let it continue with just that warning */
    }

    prop->min_ssf = min;
    prop->max_ssf = max;

    prop->maxbufsize = MAX_BUF;

    prop->security_flags = 0;
#ifndef ANONYMOUS_LOGIN
    prop->security_flags |= SASL_SEC_NOANONYMOUS;
#endif

    /* Check the global options file to see if plaintext is allowed.
     * Defaults to no plaintext logins if the option is not present.
     */
    if (! option_test("", opt_plaintext, 1, NULL))
	prop->security_flags |= SASL_SEC_NOPLAINTEXT;

    prop->property_names = NULL;
    prop->property_values = NULL;

    return prop;
}

/* Initialize the state of SASL for a given server thread.
 */
int
mysasl_server_init(char *name,
		   sasl_conn_t **imsp_saslconn_p,
		   const char **errstr)
{
    int result;
    char remoteip[60], localip[60];
    
    result = sasl_server_new(name, /* service name */ 
			     NULL, /* hostname */
			     NULL, /* user realm */
			     NULL, /* local ip */
			     NULL, /* remote ip */
			     NULL, /* callbacks */
			     0, 
			     imsp_saslconn_p);
    if (result != SASL_OK) {
	*errstr = sasl_errstring(result, NULL, NULL);
	return -1;
    }

    sasl_setprop(*imsp_saslconn_p, SASL_SEC_PROPS, mysasl_make_secprops());

    if(iptostring((struct sockaddr *)&imspd_remoteaddr,
		  sizeof(struct sockaddr_in),
		  remoteip, 60) == 0) {
	sasl_setprop(*imsp_saslconn_p, SASL_IPREMOTEPORT, remoteip);
    }
    
    if(iptostring((struct sockaddr *)&imspd_localaddr,
		     sizeof(struct sockaddr_in),
		     localip, 60) == 0) {
	sasl_setprop(*imsp_saslconn_p, SASL_IPLOCALPORT, localip);
    }


    return 0;
}

/* This is a callback to fetch SASL configuration details from the
 * IMSP global options file.
 */
static int
mysasl_config(void *context /*__attribute__((unused))*/, 
	      const char *plugin_name,
	      const char *option,
	      const char **result,
	      unsigned *len)
{
    char opt[1024];
    
    /* XXX need to downcase plugin_name or is it already taken care of? */

    /* prepend "imsp.sasl." to the option we're looking for */
    strncpy(opt, opt_sasl_prefix, sizeof(opt));
    /* add a null to make sure that the following strlen(opt) calls are okay */
    opt[sizeof(opt)-1] = '\0';
    if (plugin_name) {
	strncat(opt, plugin_name, sizeof(opt) - strlen(opt) - 1);
	strncat(opt, ".",	  sizeof(opt) - strlen(opt) - 1);
    }
    strncat(opt, option, sizeof(opt) - strlen(opt) - 1);

    *result = option_get("", opt, 1, NULL);

    /* For backwards compatibility, we'll also look at this option
     * for the name of the srvtab file
     */
    if ((*result == NULL) && 
	strcmp(option, "srvtab") == 0) {
	strncpy(opt, opt_login_srvtab, sizeof(opt));
	*result = option_get("", opt, 1, NULL);
    }

    if (*result != NULL) {
	if (len != NULL) {
	    *len = strlen(*result);
	}
	return SASL_OK;
    }

    return SASL_FAIL;
}

/* This is a callback to let SASL decide if we should we allow 
 * users to proxy as another user. (Is this an administrator who
 * can perform a "switch-user" operation?)
 * Returns SASL_OK if yes, SASL_BADAUTH otherwise.
 */
static
mysasl_authproc(sasl_conn_t *conn,
		void *context,
		const char *requested_user, unsigned rlen,
		const char *auth_identity, unsigned alen,
		const char *def_realm, unsigned urlen,
		struct propctx *propctx)
{
    char replybuf[150];
    char *realm;
    
    /* check if remote realm */
    if (realm = strchr(auth_identity, '@')) {
	realm++;
	if (!option_lookup("", opt_login_realms, 1, realm)) {
	    snprintf(replybuf, sizeof(replybuf),
		     err_nocrossrealm, auth_identity);
	    sasl_seterror(conn, 0, replybuf);
	    return SASL_BADAUTH;
	}
    }

    if (strcmp(auth_identity, requested_user)) {
	/* user wants to proxy; should we let them? */
	if (option_lookup("", opt_alladmin, 1, auth_identity)) {
	    return SASL_OK;
	} else {
	    /* no proxy! */
	    sasl_seterror(conn, 0, err_noproxy);
	    return SASL_BADAUTH;
	}
    }

    return SASL_OK;
}

/* Our callbacks */
static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int
mysasl_init(char *name, const char **errstr)
{
    int result;

    *errstr = NULL;
    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* Make a SASL connection and setup some properties for it */
    if ((result = sasl_server_init(mysasl_cb, name)) != SASL_OK)
	{
	    *errstr = sasl_errstring(result, NULL, NULL);
	    return -1;
	}
    return 0;
}
