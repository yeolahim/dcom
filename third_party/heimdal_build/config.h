/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

#ifndef HAVE_HEIMDAL_CONFIG_H
#define HAVE_HEIMDAL_CONFIG_H

#include "include/config.h"
#include "../replace/replace.h"
#include "../lib/util/attr.h"

#define VERSIONLIST {"Lorikeet-Heimdal, Modified for Samba4"}

#define VERSION "Samba"

#define PACKAGE VERSION
#define PACKAGE_BUGREPORT "https://bugzilla.samba.org/"
#define PACKAGE_VERSION VERSION

#define RCSID(msg) struct __rcsid { int __rcsdi; }
#define KRB5

/* This needs to be defined for roken too */
#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#define HDB_DB_DIR ""

#undef HAVE_KRB5_ENCRYPT_BLOCK

/* Because it can't be defined in roken.h */
#ifndef USE_HCRYPTO_IMATH
#define USE_HCRYPTO_IMATH
#endif

/*Workaround for heimdal define vs samba define*/
#if defined(HAVE_LIBINTL_H) && defined(HAVE_BINDTEXTDOMAIN) &&\
    defined(HAVE_TEXTDOMAIN)
#define LIBINTL
#endif

/* heimdal now wants some atomic ops - ask for the non-atomic ones for Samba */
#define HEIM_BASE_NON_ATOMIC 1

/* lib/replace provides an XSI Compatable strerror_r so use that */
#define STRERROR_R_PROTO_COMPATIBLE

/* lib/replace provides a closefrom */
#ifndef HAVE_CLOSEFROM
#define HAVE_CLOSEFROM 1
#endif

/* lib/replace provides a getprogname */
#ifndef HAVE_GETPROGNAME
#define HAVE_GETPROGNAME 1
#endif

/* lib/replace provides a strsep */
#ifndef HAVE_STRSEP
#define HAVE_STRSEP 1
#endif

#define HEIM_FALLTHROUGH FALL_THROUGH

#endif
