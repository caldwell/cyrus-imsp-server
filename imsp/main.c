/* main.c -- main entry point for imsp server
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
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include "version.h"
#include "dispatch.h"
#include "imsp.h"
#include "imsp_server.h"
#include "authize.h"
#include "util.h"
#include "syncdb.h"
#include "option.h"
#include "sasl_support.h"

int imspd_debug = 0;

struct sockaddr_in imspd_localaddr, imspd_remoteaddr;

static char msg_forkfailed[] = "* BYE IMSP server is currently overloaded\r\n";

/* cleanup a child
 */
static void cleanup_child(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);

    /* NOTE: some stupid Unix varients (Solaris) reset the signal handler
     * every time it is called.  This sets it back to avoid endless zombies.
     */
    signal(SIGCHLD, cleanup_child);
}

/* get host info for a connection
 */
static char *gethinfo(int fd)
{
    int socksz;
    struct hostent *hent;
    char *iaddr;
    static char host[MAXHOSTNAMELEN];

    /* find out hostname of client */
    strcpy(host, "unknown-host");
    socksz = sizeof (struct sockaddr_in);
    if (getpeername(fd, (struct sockaddr *) &imspd_remoteaddr, &socksz) < 0) {
	return (NULL);
    }
    socksz = sizeof (struct sockaddr_in);
    getsockname(fd, (struct sockaddr *) &imspd_localaddr, &socksz);
    if ((iaddr = inet_ntoa(imspd_remoteaddr.sin_addr))) {
	strcpy(host, iaddr);
    }
    if ((hent = gethostbyaddr((char *) &imspd_remoteaddr.sin_addr,
			      sizeof (struct in_addr), AF_INET)) != NULL) {
	strcpy(host, hent->h_name);
    }

    return (host);
}

/* start server socket
 */
static void start_server(int port_number)
{
    int sock, len, pid, newfd, tries = 0;
    struct sockaddr_in server;
    struct servent *svent;
    char *host;


    if (imspd_debug && 
	(setsid((pid_t)0) < 0)) {
	syslog(LOG_INFO, "imspd: warning: unable to disassocate from parent: %m");
    }

    syslog(LOG_NOTICE, "imspd: start");

    /* set up signal handler for child processes */
    signal(SIGCHLD, cleanup_child);

    /* open IMSP service port */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      syslog(LOG_ERR, "imspd exiting: socket: %m");
	exit(1);
    }

    {
      int foo = 1;
      
      if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&foo, sizeof(foo)) < 0) {
	syslog(LOG_INFO, "imspd: warning: unable to set socket option SO_REUSEADDR: %m");
      }
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    if (port_number) {
	server.sin_port = htons(port_number);
    } else {
	svent = getservbyname(IMSP_PORTNAME, IMSP_PROTOCOL);
	server.sin_port = svent ? svent->s_port : htons(IMSP_PORT);
    }
    while (bind(sock, (struct sockaddr *) &server, sizeof (server)) < 0) {
	if (errno != EADDRINUSE || ++tries > 30) {
	  syslog(LOG_ERR, "imspd exiting: bind: %m");
	  exit(1);
	}
	syslog(LOG_INFO, "imspd: temporary bind error: %m");
	sleep(1);
    }
    (void) listen(sock, 10);

    for (;;) {
	/* wait for connection */
	if (dispatch_loop(sock, 0) < 0) {
	  syslog(LOG_ERR, "imspd exiting: dispatch loop: %m");
	  exit(1);
	}

	/* accept connection */
	len = sizeof (struct sockaddr_in);
	newfd = accept(sock, (struct sockaddr *) &server, &len);
	if (newfd < 0) {
	  syslog(LOG_ERR, "imspd abandoning connection: accept (0x%x): %m",
		 server.sin_addr.s_addr); /* maybe it'll set this... */
	  continue;
	}

	/* fork server process */
	if (!imspd_debug) {
	  pid = fork();
	  if (pid == 0) {
	    (void) close(sock);

	    /* get host info */
	    host = gethinfo(newfd);

	    im_start(newfd, host);
	    exit(0);
	  } else if (pid < 0) {
	    (void) write(newfd, msg_forkfailed, sizeof (msg_forkfailed));
	    syslog(LOG_ERR, "imspd: unable to start worker: %m");
	  }
	  (void) close(newfd);
	} else {
	  (void) close(sock);

	  /* get host info */
	  host = gethinfo(newfd);

	  im_start(newfd, host);
	}
    }
}

int
main(int argc, char **argv)
{
    char *host;
    extern optind;
    extern char *optarg;
    int c, errflag = 0, port_number = 0;
    const char *errstr;

    while ((c = getopt(argc, argv, "dp:")) != EOF) {
      switch (c) {
      case 'd':
	imspd_debug = 1;
	break;
      case 'p':
	port_number = atoi(optarg);
	break;
      default:
	errflag = 1;
	break;
      }
    }
    if (optind != argc) errflag = 1;
    
    if (errflag) {
      fprintf(stderr, 
	      "Usage: %s [-d] [-p port]\n"
	      "use -d to prevent forking and to print extra debugging info\n"
	      "use -p to specify a port number\n", 
	      argv[0]);
      exit(-1);
    }
    (void)openlog("imsp", LOG_PID, LOG_LOCAL6);
    host = gethinfo(0);
    if (!host) printf("Cyrus IMSP server version %s\n", VERSION);
    if (sdb_init() < 0) {
	fprintf(stderr, "imspd: Failed to initialize database module.\n"
		"You may need to create the IMSP runtime database directory\n"
		"and you must run as root.\n");
	syslog(LOG_ERR,"imspd: Failed to initialize database module.\n"
	       "You may need to create the IMSP runtime database directory\n"
	       "and you must run as root.\n");
	exit(1);
    }
    sdb_create("abooks");
    dispatch_init();

    if (mysasl_init("imspd", &errstr) < 0) {
	syslog(LOG_ERR,"imspd: failed to initialize SASL from main(): %s",
	       errstr ? errstr : "<null>");
	exit(1);
    }

    if (!host) {
	start_server(port_number);
    } else {
	im_start(0, host);
    }
}

