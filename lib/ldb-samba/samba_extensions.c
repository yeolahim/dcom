/*
   ldb database library - samba extensions

   Copyright (C) Andrew Tridgell  2010

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/


#include "includes.h"
#include "ldb_module.h"
#include "lib/cmdline/cmdline.h"
#include "auth/gensec/gensec.h"
#include "auth/auth.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "ldb_wrap.h"
#include "popt.h"


static bool is_popt_table_end(const struct poptOption *o)
{
	if (o->longName == NULL &&
	    o->shortName =='\0' &&
	    o->arg == NULL) {
		return true;
	}

	return false;
}

/*
  work out the length of a popt array
 */
static size_t calculate_popt_array_length(struct poptOption *opts)
{
	size_t i = 0;

	for (i = 0; i < UINT32_MAX; i++) {
		struct poptOption *o = &(opts[i]);

		if (is_popt_table_end(o)) {
			break;
		}
	}

	return i;
}

/*
  called to register additional command line options
 */
static int extensions_hook(struct ldb_context *ldb, enum ldb_module_hook_type t)
{
	switch (t) {
	case LDB_MODULE_HOOK_CMDLINE_OPTIONS: {
		size_t len1, len2;
		struct poptOption **popt_options = ldb_module_popt_options(ldb);
		struct poptOption *new_array = NULL;
		bool ok;

		struct poptOption cmdline_extensions[] = {
			POPT_COMMON_SAMBA_LDB
			POPT_COMMON_CONNECTION
			POPT_COMMON_CREDENTIALS
			POPT_LEGACY_S4
			POPT_COMMON_VERSION
			POPT_TABLEEND
		};

		ok = samba_cmdline_init(ldb,
					SAMBA_CMDLINE_CONFIG_CLIENT,
					false /* require_smbconf */);
		if (!ok) {
			return ldb_oom(ldb);
		}

		len1 = calculate_popt_array_length(*popt_options);
		len2 = calculate_popt_array_length(cmdline_extensions);
		new_array = talloc_array(ldb,
					 struct poptOption,
					 len1 + len2 + 1);
		if (NULL == new_array) {
			return ldb_oom(ldb);
		}

		memcpy(new_array, *popt_options, len1*sizeof(struct poptOption));
		memcpy(new_array+len1, cmdline_extensions, (1+len2)*sizeof(struct poptOption));

#ifdef DEVELOPER
		ok = samba_cmdline_sanity_check(new_array);
		if (!ok) {
			talloc_free(new_array);
			return ldb_error(ldb,
					 LDB_ERR_OPERATIONS_ERROR,
					 "Duplicate cmdline options detected!");
		}
#endif

		(*popt_options) = new_array;
		return LDB_SUCCESS;
	}

	case LDB_MODULE_HOOK_CMDLINE_PRECONNECT: {
		struct loadparm_context *lp_ctx = NULL;
		struct cli_credentials *creds = NULL;

		int r = ldb_register_samba_handlers(ldb);
		if (r != LDB_SUCCESS) {
			return ldb_operr(ldb);
		}
		gensec_init();

		lp_ctx = samba_cmdline_get_lp_ctx();
		creds = samba_cmdline_get_creds();

		if (ldb_set_opaque(
			ldb,
			DSDB_SESSION_INFO,
			system_session(lp_ctx))) {

			return ldb_operr(ldb);
		}
		if (ldb_set_opaque(ldb, "credentials", creds)) {
			return ldb_operr(ldb);
		}
		if (ldb_set_opaque(ldb, "loadparm", lp_ctx)) {
			return ldb_operr(ldb);
		}

		ldb_set_utf8_fns(ldb, NULL, wrap_casefold);
		break;
	}

	case LDB_MODULE_HOOK_CMDLINE_POSTCONNECT:
		/* get the domain SID into the cache for SDDL processing */
		samdb_domain_sid(ldb);
		break;
	}

	return LDB_SUCCESS;
}


/*
  initialise the module
 */
_PUBLIC_ int ldb_samba_extensions_init(const char *ldb_version)
{
	ldb_register_hook(extensions_hook);

	return LDB_SUCCESS;
}
