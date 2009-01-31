/* login_krb.c -- Kerberos login authentication
 *
 *	(C) Copyright 1994-1996 by Carnegie Mellon University
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
#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif
#include <krb.h>
#include <acte.h>
#include "util.h"
#include "syncdb.h"
#include "option.h"

#ifndef EX_OK
#define EX_OK		0
#endif
#ifndef EX_OSFILE
#define EX_OSFILE	72
#endif

static login_authproc();

extern struct acte_server krb_acte_server;

static char lrealm[REALM_SZ];

/*
 * Kerberos-authenticated login
 */

int
login_plaintext(user, pass, reply)
char *user;
char *pass;
char **reply;
{
    char *val;
    int rwflag;

    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
	if ((val = option_get("", "imsp.login.srvtab", 1, &rwflag))) {
	    kerberos_set_srvtab(val);
	}
    }

    if (kerberos_verify_password(user, pass, "imap", reply) == 0) {
	return 1;
    }

    return 0;
}

int
login_authenticate(authtype, mech, authproc)
char *authtype;
struct acte_server **mech;
int (**authproc)();
{
    char *val;
    int rwflag;

    if (strcmp(authtype, "kerberos_v4") != 0) return 1;

    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
	if ((val = option_get("", "imsp.login.srvtab", 1, &rwflag))) {
	    kerberos_set_srvtab(val);
	}
    }

    *mech = &krb_acte_server;
    *authproc = login_authproc;
    return 0;
}

static int
login_authproc(user, auth_identity, reply)
char *user;
char *auth_identity;
char **reply;
{
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char auth_aname[ANAME_SZ];
    char auth_inst[INST_SZ];
    char auth_realm[REALM_SZ];
    static char replybuf[100];

    aname[0] = inst[0] = realm[0] = '\0';
    auth_aname[0] = auth_inst[0] = auth_realm[0] = '\0';
    if (kname_parse(aname, inst, realm, user) != 0) {
	*reply = "unparsable user name";
	return 1;
    }
    if (kname_parse(auth_aname, auth_inst, auth_realm, auth_identity) != 0) {
	*reply = "unparsable Kerberos identity";
	return 1;
    }

    /* If remote realm, check configuration to ensure they're allowed in */
    if (realm[0] && !option_lookup("", "imsp.login.realms", 1, realm)) {
	snprintf(replybuf, sizeof(replybuf), "cross-realm login from %s%s%s@%s denied",
		auth_aname, auth_inst[0] ? "." : "",
		auth_inst, auth_realm);
	*reply = replybuf;
	return 1;
    }

    /* Logging in as the user in the authenticator? */
    if (strcmp(auth_aname, aname) == 0 &&
	strcmp(auth_inst, inst) == 0 &&
	strcmp(auth_realm, realm[0] ? realm : lrealm) == 0) {

	return 0;
    }

    snprintf(replybuf, sizeof(replybuf), "login as %s%s%s@%s denied",
	    auth_aname, auth_inst[0] ? "." : "",
	    auth_inst, auth_realm);
    *reply = replybuf;
    return 1;
}

