#define STATEDIR	"/var/imsp"

@TOP@

#undef HAS_STRERROR
#undef HAVE_DB_185_H
#undef HAVE_KRB
#undef HAVE_LDAP
#undef HAVE_LIBDB
#undef HAVE_GSSAPI_H
#undef HAVE_GSS_C_NT_HOSTBASED_SERVICE
#undef HAVE_STRLCAT
#undef HAVE_STRLCPY

@BOTTOM@

/* getaddrinfo things */
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef HAVE_GETADDRINFO
#define getaddrinfo     sasl_getaddrinfo
#define freeaddrinfo    sasl_freeaddrinfo
#define getnameinfo     sasl_getnameinfo
#define gai_strerror    sasl_gai_strerror
#include "gai.h"
#endif

#ifndef NI_WITHSCOPEID
#define NI_WITHSCOPEID  0
#endif

