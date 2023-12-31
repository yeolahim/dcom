/*
 *  idmap_rid: static map between Active Directory/NT RIDs and RFC 2307 accounts
 *  Copyright (C) Guenther Deschner, 2004
 *  Copyright (C) Sumit Bose, 2004
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "includes.h"
#include "winbindd.h"
#include "idmap.h"
#include "../libcli/security/dom_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_rid_context {
	uint32_t base_rid;
};

/******************************************************************************
  compat params can't be used because of the completely different way
  we support multiple domains in the new idmap
 *****************************************************************************/

static NTSTATUS idmap_rid_initialize(struct idmap_domain *dom)
{
	struct idmap_rid_context *ctx;

	ctx = talloc_zero(dom, struct idmap_rid_context);
	if (ctx == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	ctx->base_rid = idmap_config_int(dom->name, "base_rid", 0);

	dom->private_data = ctx;

	return NT_STATUS_OK;
}

static NTSTATUS idmap_rid_id_to_sid(struct idmap_domain *dom, struct id_map *map)
{
	struct idmap_rid_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_rid_context);

	/* apply filters before checking */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		return NT_STATUS_NONE_MAPPED;
	}

	if (is_null_sid(&dom->dom_sid)) {
		DBG_INFO("idmap domain '%s' without SID\n", dom->name);
		return NT_STATUS_NONE_MAPPED;
	}

	sid_compose(map->sid, &dom->dom_sid,
		    map->xid.id - dom->low_id + ctx->base_rid);

	map->status = ID_MAPPED;
	map->xid.type = ID_TYPE_BOTH;

	return NT_STATUS_OK;
}

/**********************************
 Single sid to id lookup function.
**********************************/

static NTSTATUS idmap_rid_sid_to_id(struct idmap_domain *dom, struct id_map *map)
{
	uint32_t rid;
	struct idmap_rid_context *ctx;

	ctx = talloc_get_type(dom->private_data, struct idmap_rid_context);

	sid_peek_rid(map->sid, &rid);
	map->xid.id = rid - ctx->base_rid + dom->low_id;
	map->xid.type = ID_TYPE_BOTH;

	/* apply filters before returning result */

	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	map->status = ID_MAPPED;

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of unix ids.
**********************************/

static NTSTATUS idmap_rid_unixids_to_sids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {

		ret = idmap_rid_id_to_sid(dom, ids[i]);

		if (( ! NT_STATUS_IS_OK(ret)) &&
		    ( ! NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			/* some fatal error occurred, log it */
			DBG_NOTICE("Unexpected error resolving an ID "
				   "(%d): %s\n", ids[i]->xid.id,
				   nt_errstr(ret));
		}
	}

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of sids.
**********************************/

static NTSTATUS idmap_rid_sids_to_unixids(struct idmap_domain *dom, struct id_map **ids)
{
	NTSTATUS ret;
	int i;

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {

		ret = idmap_rid_sid_to_id(dom, ids[i]);

		if (( ! NT_STATUS_IS_OK(ret)) &&
		    ( ! NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			struct dom_sid_buf buf;
			/* some fatal error occurred, log it */
			DEBUG(3, ("Unexpected error resolving a SID (%s)\n",
				  dom_sid_str_buf(ids[i]->sid, &buf)));
		}
	}

	return NT_STATUS_OK;
}

static const struct idmap_methods rid_methods = {
	.init = idmap_rid_initialize,
	.unixids_to_sids = idmap_rid_unixids_to_sids,
	.sids_to_unixids = idmap_rid_sids_to_unixids,
};

static_decl_idmap;
NTSTATUS idmap_rid_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "rid", &rid_methods);
}

