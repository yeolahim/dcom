/*
   Unix SMB/CIFS implementation.
   Authentication utility functions

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017

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
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_auth.h"
#include "auth_util.h"

struct auth_session_info *copy_session_info(TALLOC_CTX *mem_ctx,
					    const struct auth_session_info *src)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct auth_session_info *dst;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(
		&blob,
		frame,
		src,
		(ndr_push_flags_fn_t)ndr_push_auth_session_info);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("copy_session_info(): ndr_push_auth_session_info "
			"failed: %s\n",
			ndr_errstr(ndr_err));
		TALLOC_FREE(frame);
		return NULL;
	}

	dst = talloc_zero(mem_ctx, struct auth_session_info);
	if (dst == NULL) {
		DBG_ERR("talloc failed\n");
		TALLOC_FREE(frame);
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(
		&blob,
		dst,
		dst,
		(ndr_pull_flags_fn_t)ndr_pull_auth_session_info);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("copy_session_info(): ndr_pull_auth_session_info "
			"failed: %s\n",
			ndr_errstr(ndr_err));
		TALLOC_FREE(dst);
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	return dst;
}
