/* proxy_krb.c -- Kerberos proxy login authentication
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
#include <stdio.h>
#include <ctype.h>
#include <sysexits.h>
#include <krb.h>
#include <sys/param.h>
#include <acte.h>
#include "authize.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

extern struct acte_client krb_acte_client;

extern char *krb_get_phost();

static char lrealm[REALM_SZ];

/*
 * Kerberos-authenticated proxy
 */
int proxy_init(id, hostname, admin, user, pass, mech)
    auth_id *id;
    char *hostname;
    int admin;
    char **user;
    char **pass;
    struct acte_client **mech;
{
    char *val;
    int rwflag, result;
    char lhost[MAXHOSTNAMELEN];
    char phost[MAXHOSTNAMELEN];

    /* make sure this is the right mechanism */
    val = option_get("", "imsp.proxy.authtype", 1, &rwflag);
    if (val) {
	result = strcasecmp(val, krb_acte_client.auth_type);
	free(val);
	if (result) return (-1);
    }
    
    /* check current auth_id */
    if (!admin && auth_level(id) <= AUTH_USER) {
	*mech = 0;
	return (auth_proxy(id, hostname, user, pass));
    }
    *user = admin ? NULL : auth_username(id);
    *pass = "";
    *mech = &krb_acte_client;
    
    /* get the realm */
    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
    }
    val = option_get("", "imsp.login.srvtab", 1, &rwflag);

    /* authenticate server */
    gethostname(lhost, sizeof (lhost));
    strcpy(phost, krb_get_phost(lhost));
    result = krb_get_svc_in_tkt("imap", phost, lrealm,
				"krbtgt", lrealm, DEFAULT_TKT_LIFE,
				val ? val : "/etc/srvtab");
    if (val) free(val);
				
    return (result);
}
