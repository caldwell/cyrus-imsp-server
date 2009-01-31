/* imsp_server.c -- Interactive Mail Support Protocol Server
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
 * Start Date: 2/16/93
 */

#include <config.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <syslog.h>
#include <fcntl.h>
#include <sasl/sasl.h>
#include <netdb.h>
#include "version.h"
#include "dispatch.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"
#include "glob.h"
#include "authize.h"
#include "abook.h"
#include "imsp_server.h"
#include "im_util.h"
#include "acl.h"
#include "alock.h"
#include "sasl_support.h"

/* import from OS */
extern char *malloc(), *realloc();

/* structure used for command dispatch list */
typedef struct command_t {
    char *word;
    int id;
    void (*proc)();
} command_t;

/* The IMSP server also respects the IMAP shutdown file */
#define SHUTDOWNFILENAME "/var/imap/msg/shutdown"

#define MAX_IDLE_TIME (30*60)	/* 30 minutes */
#define MAX_WRITE_WAIT (30)	/* 30 seconds */

/* IMSP commands */
#define IMSP_LOGIN         0
#define IMSP_LOGOUT        1
#define IMSP_NOOP          2
#define IMSP_GET           3
#define IMSP_SET           4
#define IMSP_UNSET         5
#define IMSP_SUBSCRIBE     6
#define IMSP_UNSUBSCRIBE   7
#define IMSP_CREATE        8
#define IMSP_DELETE        9
#define IMSP_RENAME        10
#define IMSP_REPLACE	   11
#define IMSP_MOVE          12
#define IMSP_FETCHADDRESS  13
#define IMSP_SEARCHADDRESS 14
#define IMSP_STOREADDRESS  15
#define IMSP_DELETEADDRESS 16
#define IMSP_SETACL        17
#define IMSP_DELETEACL     18
#define IMSP_GETACL        19
#define IMSP_MYRIGHTS      20
#define IMSP_LOCK          21
#define IMSP_UNLOCK        22
#define IMSP_ADDRESSBOOK   23
#define IMSP_CREATEABOOK   24
#define IMSP_DELETEABOOK   25
#define IMSP_RENAMEABOOK   26
#define IMSP_CAPABILITY    27
#define IMSP_AUTHENTICATE  28
#define IMSP_LIST          29
#define IMSP_LSUB          30
#define IMSP_LMARKED	   31
#define IMSP_LAST	   32
#define IMSP_SEEN	   33

/* IMSP find options */
#define FIND_MAILBOXES        0
#define FIND_ALL_MAILBOXES    1
#define FIND_UNSEEN_MAILBOXES 2
#define FIND_BBOARDS          3
#define FIND_ALL_BBOARDS      4
#define FIND_UNSEEN_BBOARDS   5

/* IMSP ACL options */
#define ACL_ADDRESSBOOK  0
#define ACL_MAILBOX      1
static char *aclopt[] = {
    "addressbook", "mailbox", NULL
};

/* IMSP LOCK/UNLOCK options */
#define LOCK_OPTION	 0
#define LOCK_ADDRESSBOOK 1
static char *lockopt[] = {
    "option", "addressbook", NULL
};

/* predefined options */
static char opt_newuser[]   = "imsp.create.new.users";
static char opt_required[]  = "imsp.required.bbsubs";

/* user information */
static auth_id *imsp_id;

/* the sasl connection context */
sasl_conn_t *imsp_saslconn; 

/* file buffer used by idle procedure */
static fbuf_t im_fbuf;

/* login & logout messages */
static char msg_greeting[] = "* OK Cyrus IMSP version %s ready\r\n";
static char msg_autologout[] = "* BYE user was idle for too long, closing\r\n";
static char msg_logout[] = "* BYE Logging user out\r\n";
static char msg_alert[] = "* BYE [ALERT] %s\r\n";
static char msg_svrexit[] = "* BYE IMSP server exiting (probably out of memory)\r\n";
static char msg_capability[] = "* CAPABILITY";
static char txt_logoutuser[] = "Logging user out";
/* generic command parse errors */
static char msg_badtag[] = "* BAD 7-bit ASCII tag required\r\n";
static char rpl_badcommand[] = "BAD 7-bit ASCII command required\r\n";
static char rpl_invalcommand[] = "BAD command '%s' unknown\r\n";
static char rpl_wrongargs[] =
    "BAD command '%s' requires %d properly formed argument(s)\r\n";
static char rpl_wrongargopt[] =
    "BAD command '%s' requires a string and an optional %s\r\n";
static char rpl_noargs[] = "BAD command '%s' requires no arguments\r\n";
static char rpl_noauth[] = "NO User must LOGIN to execute command '%s'\r\n";
static char rpl_badauth[] = "NO User not authorized to execute that command\r\n";
/* generic errors */
static char err_nomem[] = "IMSP server out of memory";
static char err_quota[] = "operation failed: IMSP user quota exceeded";
/* generic replies */
static char rpl_ok[] = "OK %s\r\n";
static char rpl_complete[] = "OK %s completed\r\n";
static char rpl_generic[] = "%s\r\n";
static char rpl_no[] = "NO %s\r\n";
static char rpl_badopt[] = "BAD Invalid option '%s' to command '%s'\r\n";
static char rpl_internalerr[] = "NO Internal error in routine '%s'\r\n";
static char rpl_notsupported[] = "NO %s not suppported at this site\r\n";
/* authorization messages */
static char msg_bbaccess[] = "* NO Unable to create subscription list: LIST/LSUB commands will fail\r\n";
static char err_nologin[] = "Login incorrect";
static char err_invaluser[] = "User does not have an account on this server";
static char rpl_bad64[] = "BAD Invalid base64 string\r\n";
/* GET responses, errors, strings */
static char msg_option[] = "* OPTION %a %s [READ-%a]\r\n";
static char err_optiondb[] = "options database unavailable";
static char txt_readwrite[] = "WRITE";
static char txt_readonly[] = "ONLY";
/* SET/UNSET errors */
static char rpl_noset[] = "%a NO User '%p' not authorized to change option '%p'\r\n";
static char rpl_isunset[] = "%a NO option '%p' was already unset\r\n";
/* LIST options, errors */
static char rpl_nosubs[] = "%a NO user '%p' is not subscribed to any bboards\r\n";
static char txt_mailbox[] = "MAILBOX";
static char txt_marked[] = "\\Marked";
static char txt_unmarked[] = "\\Unmarked";
static char txt_noinfer[] = "\\Noinferiors";
static char txt_noselect[] = "\\Noselect";
static char msg_list[] = "* LIST (%a%a%a) %a %s %.*a\r\n";
static char msg_lsub[] = "* LSUB (%a%a%a) %a %s %.*a\r\n";
static char msg_deletebb[] = "* NO The bboard '%p' has been deleted.\r\n";
static char msg_renamebb[] = "* NO The bboard '%p' has been renamed to '%p'.\r\n";
static char msg_mergebb[] = "* NO The bboard '%p' has been merged into '%p'.\r\n";
/* subscribe/unsubscribe errors */
static char rpl_notexists[] = "%a NO %a '%p' does not exist\r\n";
static char rpl_alreadydid[] = "%a NO Already %ad to %a '%p'\r\n";
static char rpl_required[] = "%a NO bboard '%p' is required; you may not unsubscribe.\r\n";
/* create text */
static char txt_splist[] = "server/partition list";
/* delete text */
static char txt_hostname[] = "hostname";

/* address book messages */
static char err_noabooksearch[] = "Unable to search address book list";
static char rpl_badfetchaddr[] = "BAD fetchaddress requires properly formatted address book name and entry\r\n";
static char rpl_badastr[] = "BAD address book entry names must be properly formed strings\r\n";
static char rpl_abookexists[] = "%a NO address book '%p' already exists\r\n";
static char rpl_noentry[] = "%a NO entry '%p' not found\r\n";
static char rpl_abookauth[] = "%a NO User '%p' not permitted to %a address book '%p'\r\n";
static char txt_create[] = "create";
static char txt_access[] = "access";
static char txt_modify[] = "modify";
static char txt_delete[] = "delete";
static char txt_list[] = "list all entries of";
static char rpl_norename[] = "%a NO User '%p' not permitted to rename address book '%p' to '%p'\r\n";
static char rpl_badsearchaddr[] = "BAD searchaddress requires a properly formatted name string\r\n";
static char rpl_badpairs[] = "BAD %s %s must be valid atom/string pairs\r\n";
static char txt_lookupcrit[] = "lookup criteria";
static char txt_fielddata[] = "field data";
static char err_badsearch[] = "Address book search failed";
static char rpl_badstoreaddr[] = "BAD storeaddress requires a properly formatted name, alias and field data\r\n";
static char err_badstore[] = "Failed to modify address book";
static char err_badcreate[] = "Failed to create new address book";
static char err_baddelete[] = "Failed to delete address book";
static char err_badrename[] = "Failed to rename address book";
static char rpl_noabook[] = "%a NO ADDRESSBOOK '%p' does not exist\r\n";
static char msg_addressbook[] = "* ADDRESSBOOK () \".\" %s\r\n";
static char msg_searchaddr[] = "* SEARCHADDRESS %s\r\n";
static char msg_fetchaddr[] = "* FETCHADDRESS %s %s";
static char msg_fielddata[] = " %a %s";
static char txt_addressbook[] = "ADDRESSBOOK";
/* ACL messages */
static char txt_acls[] = "ACL command";
static char txt_setacl[] = "modify ACL for";
static char rpl_badacl[] = "%a NO Failed to %a access control list for %a '%p'\r\n";
static char rpl_noacl[] = "%a NO No ACL entry for identity '%p' in address book '%p'\r\n";
static char msg_acl[] = "* ACL %a %s %s %s\r\n";
static char msg_myrights[] = "* MYRIGHTS %a %s %s\r\n";
/* LOCK messages */
static char rpl_badlock[] = "BAD command '%s' requires an option and one or two valid arguments\r\n";
static char rpl_locked[] = "%a NO [LOCKED] %a%a '%p' already locked by %p\r\n";
static char txt_entry[] = " entry";
static char rpl_notlock[] = "%a NO %a%a '%p' not locked by current client\r\n";
static char rpl_lockfail[] = "%a NO failed to %a %a%a '%p'\r\n";
/* SEEN/LAST messages */
static char rpl_dbfail[] = "NO failed to update mailbox database\r\n";

/* macros to send messages */
#define SEND_STRING(fbuf, str) dispatch_write((fbuf), (str), sizeof (str) - 1)
#define SEND_STRING_LEN(fbuf, str, len) dispatch_write((fbuf), (str), len)
#define SEND_RESPONSE(fbuf, tag, str) \
    sprintf((tag) + strlen(tag), " %s", (str)); \
    dispatch_write((fbuf), (tag), 0);
#define SEND_RESPONSE1(fbuf, tag, str, arg1) \
    strcat((tag), " "); \
    sprintf((tag) + strlen(tag), (str), (arg1)); \
    dispatch_write((fbuf), (tag), 0);
#define SEND_RESPONSE2(fbuf, tag, str, arg1, arg2) \
    strcat((tag), " "); \
    sprintf((tag) + strlen(tag), (str), (arg1), (arg2)); \
    dispatch_write((fbuf), (tag), 0);

/* clean abort procedure
 */
static void imsp_clean_abort()
{
    /* release all advisory locks */
    alock_unlock();

    /* release all database locks and resources */
    sdb_done();

    /* notify user */
    if (im_fbuf.fd >= 0) {
	SEND_STRING(&im_fbuf, msg_svrexit);
	dispatch_close(&im_fbuf);
    }
    
    /* clean up authorization */
    auth_free(imsp_id);

    exit(0);
}

/* fatal abort (called from xmalloc.c)
 */
void fatal(s, type)
    char *s;
    int type;
{
  static int recurse_code = 0;

  if (recurse_code) {
    exit(recurse_code);
  }
  recurse_code = type;

  syslog(LOG_ERR, "%s", s);
  
  imsp_clean_abort();
}

/* signal manager which clears out passwords
 */
static void imsp_signal_handler(sig)
    int sig;
{
    signal(sig, SIG_DFL);
    auth_free(imsp_id);
    kill(getpid(), sig);
}

/* set signals to nuke password before core dumping
 */
static void imsp_set_signals()
{
#ifdef SIGQUIT
    signal(SIGQUIT, imsp_signal_handler);
#endif
    signal(SIGILL, imsp_signal_handler);
    signal(SIGTRAP, imsp_signal_handler);
    signal(SIGIOT, imsp_signal_handler);
#ifdef SIGEMT
    signal(SIGEMT, imsp_signal_handler);
#endif
    signal(SIGFPE, imsp_signal_handler);
#ifdef SIGBUS
    signal(SIGBUS, imsp_signal_handler);
#endif
    signal(SIGSEGV, imsp_signal_handler);
#ifdef SIGSYS
    signal(SIGSYS, imsp_signal_handler);
#endif
    signal(SIGURG, imsp_signal_handler);
    signal(SIGCHLD, imsp_signal_handler);
    signal(SIGIO, imsp_signal_handler);
    signal(SIGWINCH, imsp_signal_handler);
}

/* err procedure for server
 */
int im_err(type)
    int type;
{
  static int recurse_code = 0;

  if (type != DISPATCH_READ_ERR) {
    if (recurse_code) {
      exit(recurse_code);
    }
    recurse_code = type;

    if (type == DISPATCH_READ_IDLE) {
      SEND_STRING(&im_fbuf, msg_autologout);
    }
    dispatch_close(&im_fbuf);
    imsp_clean_abort();
  }
    
  return (1);
}

/* get the option number for an acl
 */
static int lookupopt(atom, optarray)
    char *atom;
    char *optarray[];
{
    int opt;

    for (opt = 0; optarray[opt] && strcasecmp(atom, optarray[opt]); ++opt);

    return (optarray[opt] ? opt : -1);
}

/* convert from base64 to a binary buffer
 */
static char index_64[128] = {
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
    52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1,-1,-1,-1,
    -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
    -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
};
#define CHAR64(c)  (((c) < 0 || (c) > 127) ? -1 : index_64[(c)])
int from64(out, in)
    char *out, *in;
{
    int len = 0;
    int c1, c2, c3, c4;

    if (*in == '\0' || *in == '\r' || *in == '\n') return (0);
    do {
	c1 = in[0];
	if (CHAR64(c1) == -1) return (-1);
	c2 = in[1];
	if (CHAR64(c2) == -1) return (-1);
	c3 = in[2];
	if (c3 != '=' && CHAR64(c3) == -1) return (-1); 
	c4 = in[3];
	if (c4 != '=' && CHAR64(c4) == -1) return (-1);
	in += 4;
	*out++ = (CHAR64(c1) << 2) | (CHAR64(c2) >> 4);
	++len;
	if (c3 != '=') {
	    *out++ = ((CHAR64(c2) << 4) & 0xf0) | (CHAR64(c3) >> 2);
	    ++len;
	    if (c4 != '=') {
		*out++ = ((CHAR64(c3) << 6) & 0xc0) | CHAR64(c4);
		++len;
	    }
	}
    } while (*in && c4 != '=');

    return (len);
}

/* authenticate the user
 */
static void imsp_authenticate(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *auth_type;
    char at[128];
    const char *reply = NULL;
    int result;
    int (*authproc)();
    char *output;
    int len, olen;
    const char *user;
    int protlevel;

    int sasl_result;

    const char *serverout;
    unsigned int serveroutlen;
    const char *errstr;    

    /* parse command */
    if ((auth_type = get_atom(fbuf)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
	return;
    }
    lcase(auth_type);

    /* save this for future logging */
    if (strlen(auth_type) > 127) {
	strncpy(at, auth_type, 127);
    } else {
	strcpy(at, auth_type);
    }

    /* start authentication process */
    sasl_result = sasl_server_start(imsp_saslconn, auth_type,
				    NULL, 0,
				    &serverout, &serveroutlen);    

    /* sasl_server_start will return SASL_OK or SASL_CONTINUE on success */

    while (sasl_result == SASL_CONTINUE)
    {
	/* print the message to the user */
	im_send(fbuf, NULL, "+ %b\r\n", serveroutlen, serverout);
	dispatch_flush(fbuf);      

	/* get string from user */
	if (dispatch_readline(fbuf) == NULL) {
	    result = SASL_FAIL;
	} else if ((len = from64(fbuf->upos, fbuf->upos)) < 0) {
	    SEND_RESPONSE(fbuf, tag, rpl_bad64);
	    return;
	} else {
	    sasl_result = sasl_server_step(imsp_saslconn,
					   fbuf->upos,
					   len,
					   &serverout, &serveroutlen);
	}
    }

    if (sasl_result != SASL_OK) {
	/* failed authentication */
	if (reply == NULL)
	    reply = sasl_errstring(sasl_result, NULL, NULL);
	if (reply == NULL)
	    reply = err_nologin;
	SEND_RESPONSE1(fbuf, tag, rpl_no, reply);
	syslog(LOG_NOTICE, "badlogin: %s %s %s %s", 
	       host, "-", at, reply);
	return;
    }

    /* successful login! */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    sasl_result = sasl_getprop(imsp_saslconn, SASL_USERNAME,
			       (const void **) &user);
    if (sasl_result != SASL_OK) {
	syslog(LOG_ERR, "Unexpected SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	SEND_RESPONSE1(fbuf, tag, rpl_internalerr, "imsp_authenticate");
	dispatch_flush(fbuf);      
	return;
    }    

    /* get authorization structure for this user */
    if (auth_login(&id, user, NULL, &reply) < 0) {
	syslog(LOG_ERR, "Unexpected error from auth_login(): %s", 
	       reply);
	SEND_RESPONSE1(fbuf, tag, rpl_internalerr, "imsp_authenticate(2)");
	dispatch_flush(fbuf);      
	return;
    }

    /* check for valid user */
    if (option_check(auth_username(id)) < 0 &&
	(!option_test("", opt_newuser, 1, 0)
	 || option_create(auth_username(id)) < 0)) {
	SEND_RESPONSE1(fbuf, tag, rpl_no, err_invaluser);
	syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
	       host, user, at, "invalid user");
	return;
    }

    dispatch_telemetry(fbuf, auth_username(id));
    SEND_RESPONSE1(fbuf, tag, rpl_ok, reply);
    syslog(LOG_NOTICE, "login: %s %s %s %s", 
	   host, user, at, reply);
    dispatch_flush(fbuf);

    /* tell dispatch layer, ignoring any errors */
    dispatch_addsasl(fbuf, imsp_saslconn);

    imsp_id = id;
}

/* login the user
 */
static void imsp_login(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *user, *pass, *olduser = NULL;
    int result;
    const char *reply;
    int loginok = 0; /* assume it will fail */

    /* check the arguments on the LOGIN command */
    if ((user = copy_astring(fbuf, 1)) == NULL
	|| (pass = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 2);
	loginok = -1; /* indicates that a reply was already sent */
    }
    /* Try the supplied username and password
     * If verification fails, maybe this is an administrator trying to
     * switch to another user-id (Admins must supply a blank password)
     */
    else if (((result = sasl_checkpass(imsp_saslconn,
				       user, 0,
				       pass, 0)) != SASL_OK) &&
		(pass[0] != '\0' ||
		 !auth_switchuser(id, user, &olduser))
	    ) {
	/* Checkpass failed and switchuser either wasn't tried or also failed*/
	/* Make sure "reply" has a reasonable error message */
	reply = err_nologin;
    } 
    /* sasl_checkpass or auth_switchuser was successful 
     * so we need to call auth_login to tell imspd the user-id
     */
    else if (auth_login(&id, user, olduser, &reply) != 0) {
	    syslog(LOG_ERR, "Internal error calling auth_login(%s): %s",
		   user, reply);
    }
    /* Verify that an options file exists or can be created */
    else if (option_check(auth_username(id)) < 0 &&
	     (!option_test("", opt_newuser, 1, 0)
	      || option_create(auth_username(id)) < 0)) {
	reply = err_invaluser;
    } 
    /* If it got this far, everything went okay */
    else {
	loginok = 1;
	imsp_id = id;
    }

    /* Report the successful or unsuccessful login */
    if (loginok == 0 || loginok == 1) {
	if (loginok)
	    dispatch_telemetry(fbuf, auth_username(id));
	SEND_RESPONSE1(fbuf, tag, loginok ? rpl_ok : rpl_no, reply);
	syslog(LOG_NOTICE, "%slogin: %s %s %s %s", loginok ? "" : "bad",
	       host, user, "plaintext", reply);
    }

    /* Free any leftover strings */
    if (pass) {
	memset(pass, 0, strlen(pass));
	free(pass);
    }
    if (user) free(user);
    if (olduser) free(olduser);
}

/* logout the user
 */
static void imsp_logout(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    if (fbuf->upos != fbuf->lend) {
	SEND_RESPONSE1(fbuf, tag, rpl_noargs, cp->word);
    } else {
	SEND_STRING(fbuf, msg_logout);
	SEND_RESPONSE1(fbuf, tag, rpl_ok, txt_logoutuser);
	dispatch_close(fbuf);
	imsp_clean_abort();
    }
}

/* do a noop
 */
static void imsp_noop(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    if (fbuf->upos != fbuf->lend) {
	SEND_RESPONSE1(fbuf, tag, rpl_noargs, cp->word);
    } else {
	SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
    }
}

/* do the "GET" command
 */
static void imsp_get(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt, *name, *value, *user;
    int rwflag;
    option_state ostate;

    if ((opt = copy_astring(fbuf, 3)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
    } else {
	user = auth_level(id) >= AUTH_USER ? auth_username(id) : "";
	if (option_matchstart(&ostate, user, opt) < 0) {
	    SEND_RESPONSE1(fbuf, tag, rpl_no, err_optiondb);
	} else {
	    while (option_match(&ostate, user, &name, &value, &rwflag,
				auth_level(id) == AUTH_ADMIN) != NULL) { 
		im_send(fbuf, NULL, msg_option, name, value,
			  rwflag ? txt_readwrite : txt_readonly);
	    }
	    option_matchdone(&ostate);
	    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
	}
    }
    if (opt != NULL) free(opt);
}

/* do the "SET" command
 */
static void imsp_set(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt, *value = NULL, *user;
    int auth, result;

    if ((opt = copy_astring(fbuf, 1)) == NULL
	|| (value = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 2);
    } else if (auth_level(id) < AUTH_USER) {
	SEND_RESPONSE1(fbuf, tag,
		       auth_level(id) ? rpl_badauth : rpl_noauth, cp->word);
    } else {
	auth = auth_level(id) == AUTH_ADMIN;
	user = auth_username(id);
	if ((result = option_set(user, opt, auth, value)) < 0) {
	    if (result == -2) {
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_quota);
	    } else {
		im_send(fbuf, NULL, rpl_noset, tag, user, opt);
	    }
	} else {
	    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
	}
    }
    if (opt) free(opt);
    if (value) free(value);
}

/* do the "UNSET" command
 */
static void imsp_unset(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt, *newval, *user;
    int result, auth, rwflag;

    if ((opt = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
    } else if (auth_level(id) < AUTH_USER) {
	SEND_RESPONSE1(fbuf, tag,
		       auth_level(id) ? rpl_badauth : rpl_noauth, cp->word);
    } else {
	auth = auth_level(id) == AUTH_ADMIN;
	user = auth_username(id);
	result = option_unset(user, opt, auth);
	if (result < 0) {
	    im_send(fbuf, NULL, rpl_noset, tag, user, opt);
	} else if (!result) {
	    im_send(fbuf, NULL, rpl_isunset, tag, opt);
	} else {
	    while (*opt == '*' || *opt == '%') ++opt;
	    newval = option_get(user, opt, auth, &rwflag);
	    if (newval) {
		im_send(fbuf, NULL, msg_option, opt, newval,
			  rwflag ? txt_readwrite : txt_readonly);
		free(newval);
	    }
	    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
	}
    }
    if (opt != NULL) free(opt);
}

/* do the "ADDRESSBOOK" command
 */
static void imsp_addressbook(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *pat, *abook;
    int attrs;
    abook_state astate;

    if ((pat = copy_astring(fbuf, 3)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
    } else if (abook_findstart(&astate, id, pat) < 0) {
	SEND_RESPONSE1(fbuf, tag, rpl_no, err_noabooksearch);
    } else {
	while (abook_find(&astate, id, &abook, &attrs)) {
	    im_send(fbuf, NULL, msg_addressbook, abook);
	}
	abook_finddone(&astate);
	SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
    }

    if (pat) free(pat);
}

/* do the "LIST", "LSUB" and "LMARKED" commands
 */
static void imsp_list(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "SUBSCRIBE" and "UNSUBSCRIBE" commands
 */
static void imsp_subscribe(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "CREATE" command
 */
static void imsp_create(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "DELETE" command
 */
static void imsp_delete(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "RENAME" and "REPLACE" commands
 */
static void imsp_rename(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "MOVE" command
 */
static void imsp_move(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "CREATEADDRESSBOOK" command
 */
static void imsp_createabook(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name, *user;

    user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
    if ((name = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
    } else {
	lcase(name);
	switch (abook_create(id, name)) {
	    case AB_EXIST:
		im_send(fbuf, NULL, rpl_abookexists, tag, name);
		break;
	    case AB_PERM:
		im_send(fbuf, NULL, rpl_abookauth, tag, user, txt_create,
			name);
		break;
	    case AB_FAIL:
		SEND_RESPONSE(fbuf, tag, err_badcreate);
		break;
	    default:
		SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		break;
	}
    }
    if (name) free(name);
}

/* do the "DELETEADDRESSBOOK" command
 */
static void imsp_deleteabook(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name, *user;

    user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
    if ((name = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 1);
    } else {
	lcase(name);
	switch (abook_delete(id, name)) {
	    case AB_NOEXIST:
		im_send(fbuf, NULL, rpl_noabook, tag, name);
		break;
	    case AB_PERM:
		im_send(fbuf, NULL, rpl_abookauth, tag, user, txt_delete,
			name);
		break;
	    case AB_FAIL:
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_baddelete);
		break;
	    default:
		SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		break;
	}
    }
    if (name) free(name);
}

/* do the "RENAMEADDRESSBOOK" command
 */
static void imsp_renameabook(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name, *newname, *user;

    user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
    if ((name = copy_astring(fbuf, 1)) == NULL
	|| (newname = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 2);
    } else {
	lcase(name);
	lcase(newname);
	switch (abook_rename(id, name, newname)) {
	    case AB_NOEXIST:
		im_send(fbuf, NULL, rpl_noabook, tag, name);
		break;
	    case AB_EXIST:
		im_send(fbuf, NULL, rpl_abookexists, tag, newname);
		break;
	    case AB_QUOTA:
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_quota);
		break;
	    case AB_PERM:
		im_send(fbuf, NULL, rpl_norename, tag, user, name,
			newname);
		break;
	    case AB_FAIL:
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_badrename);
		break;
	    default:
		SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		break;
	}
    }
    if (name) free(name);
    if (newname) free(newname);
}

/* display an address book entry
 */
static int show_address(fbuf, id, name, alias)
    fbuf_t *fbuf;
    auth_id *id;
    char *name, *alias;
{
    abook_state astate;
    abook_fielddata *fetch;
    int count, i, freedata;
    
    if ((fetch = abook_fetch(&astate, id, name, alias, &count, &freedata))) {
	im_send(fbuf, NULL, msg_fetchaddr, name, alias);
	for (i = 0; i < count; ++i) {
	    im_send(fbuf, NULL, msg_fielddata,
				fetch[i].field, fetch[i].data);
	}
	SEND_STRING(fbuf, "\r\n");
	abook_fetchdone(&astate, fetch, count, freedata);
    }

    return (fetch ? 0 : -1);
}


/* do the "FETCHADDRESS" command
 */
static void imsp_fetchaddress(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name = NULL, *alias = NULL, *user;
    int result;

    user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
    if ((name = copy_astring(fbuf, 1)) == NULL
	|| (alias = copy_astring(fbuf, 1)) == NULL) {
	SEND_RESPONSE(fbuf, tag, rpl_badfetchaddr);
    } else if (!abook_canfetch(id, name)) {
	im_send(fbuf, NULL, rpl_abookauth, tag, user, txt_access, name);
    } else {
	lcase(name);
	do {
	    if ((result = show_address(fbuf, id, name, alias)) < 0) break;
	    free(alias);
	    alias = copy_astring(fbuf, 1);
	} while (alias);
	if (result == -1) {
	    im_send(fbuf, NULL, rpl_noentry, tag, alias);
	} else if (alias == NULL && fbuf->upos != fbuf->lend) {
	    SEND_RESPONSE(fbuf, tag, rpl_badastr);
	} else {
	    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
	}
    }
    if (alias) free(alias);
    if (name) free(name);
}


/* do the "SEARCHADDRESS" and "STOREADDRESS" commands
 */
static void imsp_searchaddress(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name = NULL, *alias = NULL, *myalias, *user;
    int fused = 0, fsize = 0, abortflag = 0, result;
    abook_fielddata *flist = NULL;
    abook_state astate;
    void *ldap_state;

    if ((name = copy_astring(fbuf, 1)) == NULL ||
	(cp->id == IMSP_STOREADDRESS
	 && ((alias = copy_astring(fbuf, 1)) == NULL
	     || fbuf->upos == fbuf->lend))) {
	SEND_RESPONSE(fbuf, tag,
		      cp->id == IMSP_STOREADDRESS ?
		      rpl_badstoreaddr : rpl_badsearchaddr);
    } else {
	lcase(name);
	while (fbuf->upos < fbuf->lend) {
	    if (fused == fsize) {
		if (!fsize) {
		    flist = (abook_fielddata *)
			malloc((fsize = 32) * sizeof (abook_fielddata));
		} else {
		    flist = (abook_fielddata *)
			realloc((char *) flist,
				(fsize *= 2) * sizeof (abook_fielddata));
		}
	    }
	    if (flist == NULL) {
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_nomem);
		abortflag = 1;
		break;
	    }
	    if ((flist[fused].field = copy_atom(fbuf)) == NULL
		|| (flist[fused].data = copy_astring(fbuf, 1)) == NULL) {
		SEND_RESPONSE2(fbuf, tag, rpl_badpairs, cp->word,
			       alias ? txt_fielddata : txt_lookupcrit);
		if (flist[fused].field) free(flist[fused].field);
		abortflag = 1;
		break;
	    }
	    ++fused;
	}
	if (!abortflag) {
	    user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
	    if (cp->id == IMSP_STOREADDRESS) {
		result = abook_store(id, name, alias, flist, fused);
		if (result == AB_SUCCESS && abook_canfetch(id, name)) {
		    show_address(fbuf, id, name, alias);
		}
	    } else {
		result = abook_searchstart(&astate, &ldap_state, 
					   id, name, flist, fused);
		if (result == AB_SUCCESS) {
		    while ((myalias = abook_search(&astate, ldap_state))) {
			im_send(fbuf, NULL, msg_searchaddr, myalias);
		    }
		    abook_searchdone(&astate, ldap_state);
		}
	    }
	    switch (result) {
		case AB_NOEXIST:
		    im_send(fbuf, NULL, rpl_noabook, tag, name);
		    break;
		case AB_QUOTA:
		    SEND_RESPONSE1(fbuf, tag, rpl_no, err_quota);
		    break;
		case AB_PERM:
		    im_send(fbuf, NULL, rpl_abookauth, tag, user,
			    alias ? txt_modify : txt_access, name);
		    break;
		case AB_PERM_LIST:
		    im_send(fbuf, NULL, rpl_abookauth, tag, user,
			    txt_list, name);
		    break;
		case AB_FAIL:
		    SEND_RESPONSE1(fbuf, tag, rpl_no,
				   alias ? err_badstore : err_badsearch);
		    break;
		default:
		    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		    break;
	    }
	}
    }
    if (flist) {
	while (fused--) {
	    free(flist[fused].data);
	    free(flist[fused].field);
	}
	free((char *) flist);
    }
    if (alias) free(alias);
    if (name) free(name);
}

/* do the "DELETEADDRESS" command
 */
static void imsp_deleteaddress(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *name = NULL, *alias = NULL, *user;
    int result;

    if ((name = copy_astring(fbuf, 1)) == NULL
	|| (alias = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 2);
    } else {
	lcase(name);
	user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
	result = abook_deleteent(id, name, alias);
	switch (result) {
	    case AB_PERM:
		im_send(fbuf, NULL, rpl_abookauth, tag,
			user, txt_modify, name);
		break;
	    case AB_FAIL:
		SEND_RESPONSE1(fbuf, tag, rpl_no, err_badstore);
		break;
	    case AB_NOEXIST:
		im_send(fbuf, NULL, rpl_noentry, tag, alias);
		break;
	    default:
		SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		break;
	}
    }
    if (alias) free(alias);
    if (name) free(name);
}

/* do the "SETACL" and "DELETEACL" commands
 */
static void imsp_setacl(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt = NULL, *item = NULL, *ident = NULL, *rights = NULL;
    char *user, *ahost = NULL, *resp;
    int result = 3, optnum;

    if ((opt = copy_atom(fbuf)) == NULL
	|| (item = copy_astring(fbuf, 1)) == NULL
	|| (ident = copy_astring(fbuf, 1)) == NULL
	|| (cp->id == IMSP_SETACL && (rights = copy_astring(fbuf, 1)) == NULL)
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word,
		       cp->id == IMSP_SETACL ? 4 : 3);
    } else {
	user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
	switch (optnum = lookupopt(opt, aclopt)) {
	    case ACL_ADDRESSBOOK:
		lcase(item);
		result = abook_setacl(id, item, ident, rights);
		switch (result) {
		    case AB_NOEXIST:
			im_send(fbuf, NULL, rpl_noabook, tag, item,
				txt_setacl, item);
			break;
		    case AB_PERM:
			im_send(fbuf, NULL, rpl_abookauth, tag, user,
				txt_setacl, item);
			break;
		    case AB_FAIL:
			im_send(fbuf, NULL, rpl_badacl, tag, txt_modify,
				opt, item);
			break;
		    case AB_SUCCESS:
			SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
			break;
		    case 1:
			im_send(fbuf, NULL, rpl_noacl, tag, ident, item);
			break;
		}
		break;
	    case ACL_MAILBOX:
		SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
		break;
	}
    }
    if (ahost) free(ahost);
    if (rights) free(rights);
    if (ident) free(ident);
    if (item) free(item);
    if (opt) free(opt);
}

/* do the "GETACL" and "MYRIGHTS" commands
 */
static void imsp_getacl(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt = NULL, *item = NULL, *ident, *rights, *user;
    char *acl, tmp, *defacl = NULL;
    char rbuf[ACL_MAXSTR];
    int result = 2, optnum;

    if ((opt = copy_atom(fbuf)) == NULL
	|| (item = copy_astring(fbuf, 1)) == NULL
	|| fbuf->upos != fbuf->lend) {
	SEND_RESPONSE2(fbuf, tag, rpl_wrongargs, cp->word, 2);
    } else {
	user = auth_username(auth_level(id) >= AUTH_USER ? id : NULL);
	lcase(item);
	optnum = lookupopt(opt, aclopt);
	if (optnum == ACL_MAILBOX) {
		SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
		return;
	} else if (cp->id == IMSP_GETACL) {
	    if (optnum == ACL_ADDRESSBOOK) {
		acl = abook_getacl(id, item);
		if ((acl != NULL) && (*acl == '\0')) {
		    int defacllen = strlen(user) + 32;
		    defacl = malloc(defacllen);
		    if (defacl) {
			snprintf(acl = defacl, defacllen, "%s\t%s\t", user,
				acl_masktostr(ACL_ALL, rbuf));
		    }
		}
	    }
	    if (acl != NULL) {
		result = 0;
		do {
		    ident = acl;
		    for (rights = ident; *rights && *rights != '\t'; ++rights);
		    if (*rights) ++rights;
		    for (acl = rights; *acl && *acl != '\t'; ++acl);
		    if (*rights) {
			rights[-1] = '\0';
			tmp = *acl;
			*acl = '\0';
			im_send(fbuf, NULL, msg_acl, optnum == ACL_MAILBOX
				? txt_mailbox : txt_addressbook,
				item, ident, rights);
			*acl = tmp;
			rights[-1] = '\t';
		    }
		    if (*acl == '\t') ++acl;
		} while (*acl != '\0');
	    } else {
		result = 3;
	    }
	} else {
	    if (optnum == ACL_ADDRESSBOOK) {
		result = abook_myrights(id, item, rbuf);
	    } else if (optnum == ACL_MAILBOX) {
		SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
		return;
	    }
	    if (!result) {
		im_send(fbuf, NULL, msg_myrights, opt, item, rbuf);
	    }
	}
	switch (result) {
	    default:
		/* XXX why not a SEND_ macro? */
		im_send(fbuf, NULL, rpl_badacl, tag, txt_access,
			opt, item);
		break;
	    case 0:
		SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		break;
	    case 1:
		SEND_RESPONSE1(fbuf, tag, rpl_notsupported, txt_acls);
		break;
	    case 2:
		SEND_RESPONSE2(fbuf, tag, rpl_badopt, opt, cp->word);
		break;
	    case 3:
		/* XXX why not a SEND_ macro? */
		im_send(fbuf, NULL, rpl_notexists, tag, opt, item);
		break;
	}
    }
    if (defacl) free(defacl);
    if (item) free(item);
    if (opt) free(opt);
}

/* do the "LOCK" and "UNLOCK" commands
 */
static void imsp_lock(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    char *opt, *item1 = NULL, *item2 = NULL, *value = NULL, *lstr, *user;
    int optnum, perm, rwflag;
    
    if ((opt = get_atom(fbuf)) == NULL) {
	SEND_RESPONSE1(fbuf, tag, rpl_badlock, cp->word);
    } else if ((optnum = lookupopt(opt, lockopt)) < 0) {
	SEND_RESPONSE2(fbuf, tag, rpl_badopt, opt, cp->word);
    } else if ((item1 = copy_astring(fbuf, 1)) == NULL
	       || (optnum == 1 && (item2 = copy_astring(fbuf, 1)) == NULL)
	       || fbuf->upos != fbuf->lend) {
	SEND_RESPONSE1(fbuf, tag, rpl_badlock, cp->word);
    } else {
	perm = 1;
	user = auth_username(id);
	if (optnum) {
	    lcase(item1);
	    if (!abook_canlock(id, item1)) {
		im_send(fbuf, NULL, rpl_abookauth, tag, user, txt_modify,
			item1);
		perm = 0;
	    }
	} else {
	    value = option_get(user, item1, 1, &rwflag);
	    if (auth_level(id) == AUTH_NONE || !rwflag) {
		im_send(fbuf, NULL, rpl_noset, tag, user, item1);
		perm = 0;
	    }
	}
	if (perm) {
	    lstr = host;
	    switch (alock_dolock(user, item1, item2,
				 cp->id == IMSP_LOCK, &lstr)) {
		case -1:	/* failure */
		    im_send(fbuf, NULL, rpl_lockfail, tag, cp->word,
			    lockopt[optnum], optnum ? txt_entry : "",
			    item2 ? item2 : item1);
		    break;
		case 0:		/* no error */
		    if (cp->id == IMSP_LOCK) {
			if (optnum) {
			    if (abook_canfetch(id, item1)) {
				show_address(fbuf, id, item1, item2);
			    }
			} else if (value) {
			    im_send(fbuf, NULL, msg_option, item1, value,
				    txt_readwrite);
			}
		    }
		    SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
		    break;
		case 1:		/* already locked/unlocked */
		    im_send(fbuf, NULL,
			    cp->id == IMSP_LOCK ? rpl_locked : rpl_notlock,
			    tag, lockopt[optnum], optnum ? txt_entry : "",
			    item2 ? item2 : item1, lstr);
		    break;
	    }
	}
    }
    if (value) free(value);
    if (item2) free(item2);
    if (item1) free(item1);
}

/* do the "CAPABILITY" command
 */
static void imsp_capability(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
  const char *sasllist; /* the list of SASL mechanisms */
  unsigned mechcount;
  unsigned strlength;

  /* send the first part */
  SEND_STRING(fbuf, msg_capability);

  /* maybe send the sasl stuff */
  if (sasl_listmech(imsp_saslconn, NULL, 
		    " AUTH=", " AUTH=", "",
		    &sasllist,
		    &strlength, &mechcount) == SASL_OK && mechcount > 0) {
      SEND_STRING_LEN(fbuf, sasllist, strlength);
  } else {
    /* else don't show anything */
  }

  /* send the newline */
  SEND_STRING(fbuf," LITERAL+\r\n");

  SEND_RESPONSE1(fbuf, tag, rpl_complete, cp->word);
}

/* do the "LAST" command
 */
static void imsp_last(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* do the "SEEN" command
 */
static void imsp_seen(fbuf, cp, tag, id, host)
    fbuf_t *fbuf;
    command_t *cp;
    char *tag, *host;
    auth_id *id;
{
    SEND_RESPONSE1(fbuf, tag, rpl_notsupported, "IMSP bboard commands");
}

/* list of commands & procedures to manage them
 */
static command_t com_list[] = {
    {"login", IMSP_LOGIN, imsp_login},
    {"logout", IMSP_LOGOUT, imsp_logout},
    {"noop", IMSP_NOOP, imsp_noop},
    {"get", IMSP_GET, imsp_get},
    {"set", IMSP_SET, imsp_set},
    {"unset", IMSP_UNSET, imsp_unset},
    {"subscribe", IMSP_SUBSCRIBE, imsp_subscribe},
    {"unsubscribe", IMSP_UNSUBSCRIBE, imsp_subscribe},
    {"create", IMSP_CREATE, imsp_create},
    {"delete", IMSP_DELETE, imsp_delete},
    {"rename", IMSP_RENAME, imsp_rename},
    {"replace", IMSP_REPLACE, imsp_rename},
    {"move", IMSP_MOVE, imsp_move},
    {"fetchaddress", IMSP_FETCHADDRESS, imsp_fetchaddress},
    {"searchaddress", IMSP_SEARCHADDRESS, imsp_searchaddress},
    {"storeaddress", IMSP_STOREADDRESS, imsp_searchaddress},
    {"deleteaddress", IMSP_DELETEADDRESS, imsp_deleteaddress},
    {"setacl", IMSP_SETACL, imsp_setacl},
    {"deleteacl", IMSP_DELETEACL, imsp_setacl},
    {"getacl", IMSP_GETACL, imsp_getacl},
    {"myrights", IMSP_MYRIGHTS, imsp_getacl},
    {"lock", IMSP_LOCK, imsp_lock},
    {"unlock", IMSP_UNLOCK, imsp_lock},
    {"addressbook", IMSP_ADDRESSBOOK, imsp_addressbook},
    {"createaddressbook", IMSP_CREATEABOOK, imsp_createabook},
    {"deleteaddressbook", IMSP_DELETEABOOK, imsp_deleteabook},
    {"renameaddressbook", IMSP_RENAMEABOOK, imsp_renameabook},
    {"capability", IMSP_CAPABILITY, imsp_capability},
    {"authenticate", IMSP_AUTHENTICATE, imsp_authenticate},
    {"list", IMSP_LIST, imsp_list},
    {"lsub", IMSP_LSUB, imsp_list},
    {"lmarked", IMSP_LMARKED, imsp_list},
    {"last", IMSP_LAST, imsp_last},
    {"seen", IMSP_SEEN, imsp_seen},
    {NULL, 0, NULL}
};

/* start the protocol exchange
 */
void im_start(int fd, char *host)
{
    FILE *shutdown;
    char *tag, *command;
    command_t *cp;
    fbuf_t *fbuf = &im_fbuf;
    char tagbuf[MAX_BUF * 3];
    char *p;
    const char *errstr;

    /* if the IMAP shutdown file exists, send its contents as an alert and exit
     */
    if ((shutdown = fopen(SHUTDOWNFILENAME, "r")) != NULL) {
        char buf[sizeof(tagbuf)-sizeof(msg_alert)];

        fgets(buf, sizeof(buf), shutdown);
	fclose(shutdown);
	if (p = strchr(buf, '\r')) *p = '\0';
	if (p = strchr(buf, '\n')) *p = '\0';
	/* can't have [ be first char, sigh */
	for(p = buf; *p == '['; p++);
	snprintf(tagbuf, sizeof(tagbuf), msg_alert, p);

	if (write(fd, tagbuf, strlen(tagbuf)) < 0) {
	  perror("write shutdown alert");
	}
	close(fd);
	return;
    }

    /* send greeting, setup idle autologout */
    snprintf(tagbuf, sizeof(tagbuf), msg_greeting, VERSION);
    if (write(fd, tagbuf, strlen(tagbuf)) < 0) {
	perror("write greeting");
	close(fd);
	return;
    }
    (void) dispatch_err(MAX_IDLE_TIME, MAX_WRITE_WAIT, im_err);
    dispatch_initbuf(fbuf, fd);

    /* start SASL and set properties for this server thread 
     */
    if (mysasl_server_init("imap", &imsp_saslconn, &errstr) < 0) {
	syslog(LOG_ERR, "SASL server init failed: %s", errstr);
	close(fd);
	return;
    }

    /* initialize user authentication information */
    imsp_id = NULL;

    /* initialize signal handlers to nuke password */
    imsp_set_signals();

    /* main protocol loop */
    while (dispatch_readline(fbuf) != NULL) {
	/* get the tag - must not be NULL or greater than 64 characters long */
	tag = get_atom(fbuf);
	if ((tag == (char *) NULL) || (strlen(tag) > 64)) {
	    SEND_STRING(fbuf, msg_badtag);
	} else {
	    /* copy tag into tag-response buffer */
	    strcpy(tagbuf, tag);
	    
	    /* get the command */
	    command = get_atom(fbuf);
	    if (command == (char *) NULL) {
		SEND_RESPONSE(fbuf, tagbuf, rpl_badcommand);
	    } else {
		/* look up the command */
		lcase(command);
		cp = com_list;
		while (cp->word != NULL && strcmp(cp->word, command)) {
		    ++cp;
		}
		if (cp->proc) {
		    (*cp->proc)(fbuf, cp, tagbuf, imsp_id, host);
		} else {
		    SEND_RESPONSE1(fbuf, tagbuf, rpl_invalcommand, command);
		}
	    }
	}
	dispatch_flush(fbuf);
    }
    dispatch_close(fbuf);
    imsp_clean_abort();
}
