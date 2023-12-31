/*
   Unix SMB/CIFS implementation.

   Samba KDB plugin for MIT Kerberos

   Copyright (c) 2010      Simo Sorce <idra@samba.org>.
   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

#include "system/kerberos.h"

#include <profile.h>
#include <kdb.h>

#include "kdc/mit_samba.h"
#include "kdb_samba.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_KERBEROS

struct mit_samba_context *ks_get_context(krb5_context kcontext)
{
	struct mit_samba_context *mit_ctx = NULL;
	void *db_ctx = NULL;
	krb5_error_code code;

	code = krb5_db_get_context(kcontext, &db_ctx);
	if (code != 0) {
		return NULL;
	}

	mit_ctx = talloc_get_type_abort(db_ctx, struct mit_samba_context);

	/*
	 * This is nomrally the starting point for Kerberos operations in
	 * MIT KRB5, so reset errno to 0 for possible com_err debug messages.
	 */
	errno = 0;

	return mit_ctx;
}

bool ks_data_eq_string(krb5_data d, const char *s)
{
	int rc;

	if (d.length != strlen(s) || d.length == 0) {
		return false;
	}

	rc = memcmp(d.data, s, d.length);
	if (rc != 0) {
		return false;
	}

	return true;
}

krb5_boolean ks_is_kadmin(krb5_context context,
			  krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) >= 1 &&
	       ks_data_eq_string(princ->data[0], "kadmin");
}

krb5_boolean ks_is_kadmin_history(krb5_context context,
				  krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) == 2 &&
	       ks_data_eq_string(princ->data[0], "kadmin") &&
	       ks_data_eq_string(princ->data[1], "history");
}

krb5_boolean ks_is_kadmin_changepw(krb5_context context,
				   krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) == 2 &&
	       ks_data_eq_string(princ->data[0], "kadmin") &&
	       ks_data_eq_string(princ->data[1], "changepw");
}

krb5_boolean ks_is_kadmin_admin(krb5_context context,
				krb5_const_principal princ)
{
	return krb5_princ_size(context, princ) == 2 &&
	       ks_data_eq_string(princ->data[0], "kadmin") &&
	       ks_data_eq_string(princ->data[1], "admin");
}
