/*
   Unix SMB/CIFS implementation.
   Main DCOM functionality
   Copyright (C) 2004 Jelmer Vernooij <jelmer@samba.org>
   Copyright (C) 2006 Andrzej Hajda <andrzej.hajda@wp.pl>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/epmapper.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "librpc/gen_ndr/dcom.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/com/dcom/dcom.h"
#include "librpc/ndr/ndr_table.h"
#include "../lib/util/dlinklist.h"
#include "auth/credentials/credentials.h"
#include "libcli/composite/composite.h"

#undef strncasecmp

#define DCOM_NEGOTIATED_PROTOCOLS { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB, EPM_PROTOCOL_NCALRPC }

#if 0
static CLSID CLSID_InstantiationInfo       = {0x000001ab, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static CLSID CLSID_ServerLocationInfo      = {0x000001a4, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static CLSID CLSID_ScmRequestInfo          = {0x000001aa, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static CLSID CLSID_ActivationContextInfo   = {0x000001a5, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static CLSID CLSID_ActivationPropertiesIn  = {0x00000338, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static CLSID CLSID_ActivationPropertiesOut = {0x00000339, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static IID IID_IActivationPropertiesIn   = {0x000001a2, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static IID IID_IActivationPropertiesOut  = {0x000001a3, 0x0000, 0x0000, {0xc0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static uint16_t DCOM_NEGOTIATED_PROTOCOLS_SEQ[] = DCOM_NEGOTIATED_PROTOCOLS;

typedef struct tagInstantiationInfoData {
    CLSID classId;
    uint32_t classCtx;
    uint32_t actvflags;
    int32_t  fIsSurrogate;
    uint32_t cIID; //[range(1, MAX_REQUESTED_INTERFACES)]
    uint32_t instFlag;
    IID* pIID; //[size_is(cIID)]
    uint32_t thisSize;
    COMVERSION clientCOMVersion;
} InstantiationInfoData;

typedef struct _customREMOTE_REQUEST_SCM_INFO {
    uint32_t ClientImpLevel;
    unsigned short cRequestedProtseqs; // [range(0, MAX_REQUESTED_PROTSEQS)]
    unsigned short pRequestedProtseqs[ARRAY_SIZE(DCOM_NEGOTIATED_PROTOCOLS_SEQ)]; // [size_is(cRequestedProtseqs)]
} customREMOTE_REQUEST_SCM_INFO;

typedef struct tagScmRequestInfoData {
   uint32_t* pdwReserved;
   customREMOTE_REQUEST_SCM_INFO remoteRequest;
 } ScmRequestInfoData;

typedef struct tagLocationInfoData {
    char* machineName;
    uint32_t processId;
    uint32_t apartmentId;
    uint32_t contextId;
} LocationInfoData;

typedef struct tagActivationContextInfoData {
    int32_t clientOK;
    int32_t bReserved1;
    uint32_t dwReserved1;
    uint32_t dwReserved2;
    struct MInterfacePointer* pIFDClientCtx;
    struct MInterfacePointer* pIFDPrototypeCtx;
} ActivationContextInfoData;

typedef struct tagCustomHeader {
    uint32_t totalSize;
    uint32_t headerSize;
    uint32_t dwReserved;
    uint32_t destCtx;
    uint32_t cIfs; // [range(MIN_ACTPROP_LIMIT, MAX_ACTPROP_LIMIT)]
    CLSID classInfoClsid;
    CLSID* pclsid; // [size_is(cIfs)]
    uint32_t* pSizes; // [size_is(cIfs)]
    uint32_t* pdwReserved;
} CustomHeader;

typedef struct tagActivationPropertiesIn {
    uint32_t dwSize;
    uint32_t dwReserved;
    CustomHeader customHeader;
    InstantiationInfoData instantiationInfo;
    ScmRequestInfoData scmRequestInfo;
    LocationInfoData locationInfo;
    ActivationContextInfoData activationContextInfo;
} ActivationPropertiesIn;
#endif

static NTSTATUS dcerpc_binding_from_STRINGBINDING(TALLOC_CTX *mem_ctx, struct dcerpc_binding **b_out, struct STRINGBINDING *bd)
{
	const char *tstr;
	char *bstr;
	enum dcerpc_transport_t transport;
	struct dcerpc_binding *b;
    NTSTATUS status;

	transport = dcerpc_transport_by_endpoint_protocol(bd->wTowerId);
	if (transport == NCA_UNKNOWN) {
		DEBUG(1, ("Can't find transport match endpoint protocol %d\n", bd->wTowerId));
		return NT_STATUS_NOT_SUPPORTED;
	}

	tstr = derpc_transport_string_by_transport(transport);
	bstr = talloc_asprintf(mem_ctx, "%s:%s", tstr, bd->NetworkAddr);
	if (bstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_parse_binding(mem_ctx, bstr, &b);
	TALLOC_FREE(bstr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*b_out = b;
	return NT_STATUS_OK;
}

struct cli_credentials *dcom_get_server_credentials(struct com_context *ctx, const char *server)
{
	struct dcom_server_credentials *c;
	struct cli_credentials *d;

	d = NULL;
	for (c = ctx->dcom->credentials; c; c = c->next) {
		if (c->server == NULL) {
			d = c->credentials;
			continue;
		}
		if (server && !strcmp(c->server, server)) return c->credentials;
	}
	return d;
}

/**
 * Register credentials for a specific server.
 *
 * @param ctx COM context
 * @param server Name of server, can be NULL
 * @param credentials Credentials object
 */
void dcom_add_server_credentials(struct com_context *ctx, const char *server,
								 struct cli_credentials *credentials)
{
	struct dcom_server_credentials *c;

	/* FIXME: Don't use talloc_find_parent_bytype */
	for (c = ctx->dcom->credentials; c; c = c->next) {
		if ((server == NULL && c->server == NULL) ||
			(server != NULL && c->server != NULL &&
			 !strcmp(c->server, server))) {
			if (c->credentials && c->credentials != credentials) {
				talloc_unlink(c, c->credentials);
				c->credentials = credentials;
				if (talloc_find_parent_bytype(c->credentials, struct dcom_server_credentials))
					(void)talloc_reference(c, c->credentials);
				else
					talloc_steal(c, c->credentials);
			}

			return;
		}
	}

	c = talloc(ctx->event_ctx, struct dcom_server_credentials);
	c->server = talloc_strdup(c, server);
	c->credentials = credentials;
	if (talloc_find_parent_bytype(c->credentials, struct dcom_server_credentials))
		(void)talloc_reference(c, c->credentials);
	else
		talloc_steal(c, c->credentials);

	DLIST_ADD(ctx->dcom->credentials, c);
}

void dcom_update_credentials_for_aliases(struct com_context *ctx,
										 const char *server,
										 struct DUALSTRINGARRAY *pds)
{
	struct cli_credentials *cc;
	struct dcerpc_binding *b;
	uint32_t i;
	NTSTATUS status;

	cc = dcom_get_server_credentials(ctx, server);
        for (i = 0; pds->stringbindings[i]; ++i) {
                if (pds->stringbindings[i]->wTowerId != EPM_PROTOCOL_TCP)
					continue;
                status = dcerpc_binding_from_STRINGBINDING(ctx, &b, pds->stringbindings[i]);
		if (!NT_STATUS_IS_OK(status))
			continue;
		dcom_add_server_credentials(ctx, b->host, cc);
		talloc_free(b);
	}
}

struct dcom_client_context *dcom_client_init(struct com_context *ctx, struct cli_credentials *credentials)
{
	ctx->dcom = talloc_zero(ctx, struct dcom_client_context);
	if (!credentials) {
                credentials = cli_credentials_init(ctx);
                cli_credentials_set_conf(credentials, ctx->lp_ctx);
                cli_credentials_parse_string(credentials, "%", CRED_SPECIFIED);
	}
	dcom_add_server_credentials(ctx, NULL, credentials);
	return ctx->dcom;
}

static NTSTATUS dcom_connect_host(struct com_context *ctx,
								  struct dcerpc_pipe **p, const char *server)
{
	struct dcerpc_binding *bd;
	const char * available_transports[] = { "ncacn_ip_tcp", "ncacn_np" };
	int i;
	NTSTATUS status;
	TALLOC_CTX *loc_ctx;

	if (server == NULL) { 
		return dcerpc_pipe_connect(ctx->event_ctx, p, "ncalrpc",
								   &ndr_table_IRemoteActivation,
								   dcom_get_server_credentials(ctx, NULL), ctx->event_ctx, ctx->lp_ctx);
	}
	loc_ctx = talloc_new(ctx);

	/* Allow server name to contain a binding string */
	if (strchr(server, ':') &&
		NT_STATUS_IS_OK(dcerpc_parse_binding(loc_ctx, server, &bd))) {
		if (DEBUGLVL(11))
			bd->flags |= DCERPC_DEBUG_PRINT_BOTH;
		status = dcerpc_pipe_connect_b(ctx->event_ctx, p, bd,
									   &ndr_table_IRemoteActivation,
								   dcom_get_server_credentials(ctx, bd->host), ctx->event_ctx, ctx->lp_ctx);
		goto end;
	}

	for (i = 0; i < ARRAY_SIZE(available_transports); i++)
	{
		char *binding = talloc_asprintf(loc_ctx, "%s:%s", available_transports[i], server);
		if (!binding) {
			status = NT_STATUS_NO_MEMORY;
			goto end;
		}
		status = dcerpc_pipe_connect(ctx->event_ctx, p, binding,
									 &ndr_table_IRemoteActivation,
									 dcom_get_server_credentials(ctx, server),
									 ctx->event_ctx, ctx->lp_ctx);

		if (NT_STATUS_IS_OK(status)) {
			if (DEBUGLVL(11))
				(*p)->conn->flags |= DCERPC_DEBUG_PRINT_BOTH;
			goto end;
		} else {
			DEBUG(1,(__location__": dcom_connect_host : %s\n", get_friendly_nt_error_msg(status)));
		}
	}

end:
	talloc_free(loc_ctx);
	return status;
}

struct dcom_object_exporter *object_exporter_by_oxid(struct com_context *ctx,
													 uint64_t oxid)
{
	struct dcom_object_exporter *ox;
	for (ox = ctx->dcom->object_exporters; ox; ox = ox->next) {
		if (ox->oxid == oxid) {
			return ox;
		}
	}

	return NULL; 
}

struct dcom_object_exporter *object_exporter_update_oxid(struct com_context *ctx, uint64_t oxid, struct DUALSTRINGARRAY *bindings)
{
	struct dcom_object_exporter *ox;
	ox = object_exporter_by_oxid(ctx, oxid);
	if (!ox) {
		ox = talloc_zero(ctx, struct dcom_object_exporter);
		DLIST_ADD(ctx->dcom->object_exporters, ox);
		ox->oxid = oxid;
	} else {
		talloc_free(ox->bindings);
	}
	ox->bindings = bindings;
	talloc_steal(ox, bindings);
	return ox;
}

struct dcom_object_exporter *object_exporter_by_ip(struct com_context *ctx, struct IUnknown *ip)
{
	return object_exporter_by_oxid(ctx, ip->obj.u_objref.u_standard.std.oxid);
}

HRESULT dcom_create_object(struct com_context *ctx, struct GUID *clsid, const char *server, int num_ifaces, struct GUID *iid, struct IUnknown ***ip, HRESULT *results)
{
	uint16_t protseq[] = DCOM_NEGOTIATED_PROTOCOLS;
	struct dcerpc_pipe *p = NULL;
	struct dcom_object_exporter *m = NULL;
	NTSTATUS status;
//	struct RemoteActivation r;
	struct DUALSTRINGARRAY *pds = NULL;
	int i;
	HRESULT hr;
	uint64_t oxid = 0;
	struct GUID ipidRemUnknown;
	struct IUnknown *ru_template = NULL;
	struct ORPCTHAT that;
	uint32_t AuthnHint;
	struct COMVERSION ServerVersion;
	struct MInterfacePointer **ifaces = NULL;
	TALLOC_CTX *loc_ctx = NULL;
    WERROR result;
    struct ORPCTHIS this_object;

	status = dcom_connect_host(ctx, &p, server);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to connect to %s - %s\n", server, get_friendly_nt_error_msg(status)));
		return HRES_ERROR(W_ERROR_V(ntstatus_to_werror(status)));
	}
	loc_ctx = talloc_new(ctx);

	ifaces = talloc_array(loc_ctx, struct MInterfacePointer *, num_ifaces);

	// ZERO_STRUCT(r.in);
	// r.in.this_object.version.MajorVersion = COM_MAJOR_VERSION;
	// r.in.this_object.version.MinorVersion = COM_MINOR_VERSION;
	// r.in.this_object.cid = GUID_random();
	// r.in.Clsid = *clsid;
	// r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	// r.in.num_protseqs = ARRAY_SIZE(protseq);
	// r.in.protseq = protseq;
	// r.in.Interfaces = num_ifaces;
	// r.in.pIIDs = iid;
	// r.out.that = &that;
	// r.out.pOxid = &oxid;
	// r.out.pdsaOxidBindings = &pds;
	// r.out.ipidRemUnknown = &ipidRemUnknown;
	// r.out.AuthnHint = &AuthnHint;
	// r.out.ServerVersion = &ServerVersion;
	// r.out.hr = &hr;
	// r.out.ifaces = ifaces;
	// r.out.results = results;

#if 1
///////
    ZERO_STRUCT(this_object);
	this_object.version.MajorVersion = COM_MAJOR_VERSION;
	this_object.version.MinorVersion = COM_MINOR_VERSION;
    this_object.flags = 1;
	this_object.cid = GUID_random();
    this_object.extensions = NULL;
    //struct MInterfacePointer objectStorage;
    printf("Running RemoteActivation\n"); //DCOM_TODO_REMOVE_ME

	status = dcerpc_RemoteActivation(p->binding_handle, loc_ctx
        , this_object
        , &that
        , *clsid
        , NULL // pwszObjectName
        , NULL // pObjectStorage
        , RPC_C_IMP_LEVEL_IDENTIFY
        , 0 // Mode
        , num_ifaces
        , iid
        , ARRAY_SIZE(protseq)
        , protseq
        , &oxid
        , &pds
        , &ipidRemUnknown
        , &AuthnHint
        , &ServerVersion
        , &hr
        , ifaces
        , results
        , &result);
#else

// CLSID_InstantiationInfo       = string_to_bin('000001ab-0000-0000-c000-000000000046')
// CLSID_ScmRequestInfo          = string_to_bin('000001aa-0000-0000-c000-000000000046')
// CLSID_ServerLocationInfo      = string_to_bin('000001a4-0000-0000-c000-000000000046')
// CLSID_ActivationContextInfo   = string_to_bin('000001a5-0000-0000-c000-000000000046') // Optional

//IID_IActivationPropertiesIn   = uuidtup_to_bin(('000001a2-0000-0000-c000-000000000046','0.0'))
//IID_IActivationPropertiesOut  = uuidtup_to_bin(('000001a3-0000-0000-c000-000000000046','0.0'))

//CLSID_ActivationPropertiesIn  = string_to_bin('00000338-0000-0000-c000-000000000046')
//CLSID_ActivationPropertiesOut = string_to_bin('00000339-0000-0000-c000-000000000046')
///////
    struct ORPCTHIS this_object;
    ZERO_STRUCT(this_object);
	this_object.version.MajorVersion = COM_MAJOR_VERSION;
	this_object.version.MinorVersion = COM_MINOR_VERSION;
    this_object.flags = 1;
	this_object.cid = GUID_random();
    this_object.extensions = NULL;

    ActivationPropertiesIn activationProperties;
    activationProperties.dwSize = 0; /// !!!!!!!!!!!
    activationProperties.dwReserved = 0;
    activationProperties.customHeader.destCtx = 2; // ?
    activationProperties.customHeader.pdwReserved = NULL;
    //
    activationProperties.instantiationInfo.classId = *clsid;
    activationProperties.instantiationInfo.classCtx = 0;
    activationProperties.instantiationInfo.actvflags = 0;
    activationProperties.instantiationInfo.fIsSurrogate = 0;
    activationProperties.instantiationInfo.cIID = num_ifaces;
    activationProperties.instantiationInfo.pIID = iid;
    activationProperties.instantiationInfo.thisSize = 0;
	activationProperties.instantiationInfo.clientCOMVersion.MajorVersion = COM_MAJOR_VERSION;
	activationProperties.instantiationInfo.clientCOMVersion.MinorVersion = COM_MINOR_VERSION;
    //
    activationProperties.scmRequestInfo.pdwReserved = NULL;
    activationProperties.scmRequestInfo.remoteRequest.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
    activationProperties.scmRequestInfo.remoteRequest.cRequestedProtseqs = ARRAY_SIZE(DCOM_NEGOTIATED_PROTOCOLS_SEQ);
    memcpy(activationProperties.scmRequestInfo.remoteRequest.pRequestedProtseqs
        , DCOM_NEGOTIATED_PROTOCOLS_SEQ, sizeof(activationProperties.scmRequestInfo.remoteRequest.pRequestedProtseqs));
    //
    activationProperties.locationInfo.machineName = NULL;
    activationProperties.locationInfo.processId = 0;
    activationProperties.locationInfo.apartmentId = 0;
    activationProperties.locationInfo.contextId = 0;
    //
    activationProperties.activationContextInfo.clientOK = 0;
    activationProperties.activationContextInfo.bReserved1 = 0;
    activationProperties.activationContextInfo.dwReserved1 = 0;
    activationProperties.activationContextInfo.dwReserved2 = 0;
    activationProperties.activationContextInfo.pIFDClientCtx = NULL;
    activationProperties.activationContextInfo.pIFDPrototypeCtx = NULL;

    struct MInterfacePointer actProperties;
    actProperties.size = 0; /// !!!!!!!!!!!
    actProperties.obj.signature = 0x574f454d;
    actProperties.obj.flags = OBJREF_CUSTOM;
    actProperties.obj.iid = IID_IActivationPropertiesIn;
    struct u_custom* u_custom = &actProperties.obj.u_objref.u_custom;
    u_custom->clsid = CLSID_ActivationPropertiesIn;
    u_custom->cbExtension = 0;
    u_custom->size = sizeof(activationProperties); // unused. This can be set to any arbitrary value when sent and MUST be ignored on receipt.
    u_custom->pData = (uint8_t*)&activationProperties;

    struct MInterfacePointer *outActProperties;
    printf("Running RemoteCreateInstance\n"); //DCOM_TODO_REMOVE_ME
    status = dcerpc_RemoteCreateInstance(p->binding_handle, loc_ctx
        , this_object
        , &that
        , NULL
        , &actProperties
        , &outActProperties
        , &result
    );
// 416
    // [77, 69, 79, 87, 4, 0, 0, 0, 162, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 56, 3, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 0, 0, 0, 0, 120, 1, 0, 0, 104, 1, 0, 0, 0, 0, 0, 0, 1, 16, 8, 0, 204, 204, 204, 204, 136, 0, 0, 0, 204, 204, 204, 204, 104, 1, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 210, 224, 0, 0, 109, 71, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 171, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 165, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 164, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 170, 1, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70, 4, 0, 0, 0, 88, 0, 0, 0, 40, 0, 0, 0, 32, 0, 0, 0, 48, 0, 0, 0, 1, 16, 8, 0, 204, 204, 204, 204, 68, 0, 0, 0, 204, 204, 204, 204, 94, 240, 195, 139, 107, 216, 208, 17, 160, 117, 0, 192, 79, 182, 136, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 74, 239, 0, 0, 0, 0, 0, 0, 5, 0, 7, 0, 1, 0, 0, 0, 24, 173, 9, 243, 106, 216, 208, 17, 160, 117, 0, 192, 79, 182, 136, 32, 250, 250, 250, 250, 1, 16, 8, 0, 204, 204, 204, 204, 24, 0, 0, 0, 204, 204, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 16, 8, 0, 204, 204, 204, 204, 16, 0, 0, 0, 204, 204, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 16, 8, 0, 204, 204, 204, 204, 26, 0, 0, 0, 204, 204, 204, 204, 0, 0, 0, 0, 245, 132, 0, 0, 0, 0, 0, 0, 1, 0, 170, 170, 24, 153, 0, 0, 1, 0, 0, 0, 7, 0, 250, 250, 250, 250, 250, 250]
    // signature: [           '0x4d', '0x45', '0x4f', '0x57'
    // flags: OBJREF_CUSTOM , '0x4', '0x0', '0x0', '0x0'
    // iid: IID_IActivationPropertiesIn , '0xa2', '0x1', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // clsid: CLSID_ActivationPropertiesIn , '0x38', '0x3', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // cbExtension: , '0x0', '0x0', '0x0', '0x0'
    // size: , '0x78', '0x1', '0x0', '0x0'
//  368=0x170
    /// blob
    // activationProperties
    // dwSize: , '0x68', '0x1', '0x0', '0x0'
    // dwReserved:, '0x0', '0x0', '0x0', '0x0'
// 360=0x168
    //
    // , '0x1', '0x10', '0x8', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // , '0x88', '0x0', '0x0', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // CustomHeader
    // totalSize:, '0x68', '0x1', '0x0', '0x0'
    // headerSize:, '0x98', '0x0', '0x0', '0x0'
    // dwReserved: , '0x0', '0x0', '0x0', '0x0'
    // destCtx: , '0x2', '0x0', '0x0', '0x0'
    // cIfs: , '0x4', '0x0', '0x0', '0x0'
    // classInfoClsid: , '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0'
    // pclsid:, '0xd2', '0xe0', '0x0', '0x0'
    // pSizes: , '0x6d', '0x47', '0x0', '0x0'
    // pdwReserved:, '0x0', '0x0', '0x0', '0x0'
    //
    // pclsid array
    // , '0x4', '0x0', '0x0', '0x0'
    // CLSID_InstantiationInfo , '0xab', '0x1', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // CLSID_ActivationContextInfo, '0xa5', '0x1', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // CLSID_ServerLocationInfo, '0xa4', '0x1', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // CLSID_ScmRequestInfo, '0xaa', '0x1', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0xc0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x0', '0x46'
    // pSizes array
    // , '0x4', '0x0', '0x0', '0x0'
    // , '0x58', '0x0', '0x0', '0x0'
    // , '0x28', '0x0', '0x0', '0x0'
    // , '0x20', '0x0', '0x0', '0x0'
    // , '0x30', '0x0', '0x0', '0x0'
    //
    // , '0x1', '0x10', '0x8', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // , '0x44', '0x0', '0x0', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // InstantiationInfoData
    // classId: CLSID_WbemLevel1Login, '0x5e', '0xf0', '0xc3', '0x8b', '0x6b', '0xd8', '0xd0', '0x11', '0xa0', '0x75', '0x0', '0xc0', '0x4f', '0xb6', '0x88', '0x20'
    // classCtx: , '0x0', '0x0', '0x0', '0x0'
    // actvflags: , '0x0', '0x0', '0x0', '0x0'
    // fIsSurrogate: , '0x0', '0x0', '0x0', '0x0'
    // cIID: , '0x1', '0x0', '0x0', '0x0'
    // instFlag: , '0x0', '0x0', '0x0', '0x0'
    // , '0x4a', '0xef', '0x0', '0x0'
    // , '0x0', '0x0', '0x0', '0x0'
    // , '0x5', '0x0', '0x7', '0x0'
    // iid array
    // , '0x1', '0x0', '0x0', '0x0'
    // IID_IWbemLevel1Login , '0x18', '0xad', '0x9', '0xf3', '0x6a', '0xd8', '0xd0', '0x11', '0xa0', '0x75', '0x0', '0xc0', '0x4f', '0xb6', '0x88', '0x20'
    // pad: , '0xfa', '0xfa', '0xfa', '0xfa'
    //
    // , '0x1', '0x10', '0x8', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // , '0x18', '0x0', '0x0', '0x0'
    // , '0xcc', '0xcc', '0xcc', '0xcc'
    // ActivationContextInfoData
    // clientOK:, '0x0', '0x0', '0x0', '0x0'
    // bReserved1:, '0x0', '0x0', '0x0', '0x0'
    // dwReserved1:, '0x0', '0x0', '0x0', '0x0'
    // dwReserved2:, '0x0', '0x0', '0x0', '0x0'
    // pIFDClientCtx:, '0x0', '0x0', '0x0', '0x0'
    // pIFDPrototypeCtx:, '0x0', '0x0', '0x0', '0x0'
    //
    //, '0x1', '0x10', '0x8', '0x0'
    //, '0xcc', '0xcc', '0xcc', '0xcc'
    //, '0x10', '0x0', '0x0', '0x0'
    //, '0xcc', '0xcc', '0xcc', '0xcc'
    // LocationInfoData
    //, '0x0', '0x0', '0x0', '0x0'
    //, '0x0', '0x0', '0x0', '0x0'
    //, '0x0', '0x0', '0x0', '0x0'
    //, '0x0', '0x0', '0x0', '0x0'
    //
    //, '0x1', '0x10', '0x8', '0x0'
    //, '0xcc', '0xcc', '0xcc', '0xcc'
    //, '0x1a', '0x0', '0x0', '0x0'
    //, '0xcc', '0xcc', '0xcc', '0xcc'
    // ScmRequestInfoData
    // pdwReserved: , '0x0', '0x0', '0x0', '0x0'
    // remoteRequest:, '0xf5', '0x84', '0x0', '0x0'
    //, '0x0', '0x0', '0x0', '0x0'
    //, '0x1', '0x0', ///  '0xaa', '0xaa'
    //, '0x18', '0x99', '0x0', '0x0'
    //, pRequestedProtseqs array
    //, '0x1', '0x0', '0x0', '0x0'
    //, '0x7', '0x0'
    // pad: , '0xfa', '0xfa', '0xfa', '0xfa', '0xfa', '0xfa']
#endif
    printf("Had run RemoteActivation %p\n", p->binding_handle); //DCOM_TODO_REMOVE_ME

	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Error while running RemoteActivation %s\n", nt_errstr(status)));
        printf("Error 0 while running RemoteActivation %s\n", nt_errstr(status)); //DCOM_TODO_REMOVE_ME
		hr = HRES_ERROR(W_ERROR_V(ntstatus_to_werror(status)));
		goto end;
	}

	if(!W_ERROR_IS_OK(result)) {
		hr = HRES_ERROR(W_ERROR_V(result));
        printf("Error 1 while running RemoteActivation 0x%d\n", W_ERROR_V(result)); //DCOM_TODO_REMOVE_ME
		goto end;
	}

	if(!HRES_IS_OK(hr)) {
        printf("Error 2 while running RemoteActivation 0x%x\n", HRES_ERROR_V(hr)); //DCOM_TODO_REMOVE_ME
		goto end;
	}
    // talloc_report_full(pds->stringbindings, stdout);
    // printf("pds %p\n", pds);
    // printf("pds.stringbindings %p\n", pds->stringbindings);
	m = object_exporter_update_oxid(ctx, oxid, pds);
    // printf("bindings %p\n", m->bindings);
    // printf("bindings.stringbindings %p\n", m->bindings->stringbindings);
    // talloc_report_full(pds->stringbindings, stdout);
	ru_template = NULL;
	*ip = talloc_array(ctx, struct IUnknown *, num_ifaces);
	for (i = 0; i < num_ifaces; i++) {
		(*ip)[i] = NULL;
		if (HRES_IS_OK(results[i])) {
			status = NT_STATUS(W_ERROR_V(dcom_IUnknown_from_OBJREF(ctx, &(*ip)[i], &ifaces[i]->obj)));
			if (!NT_STATUS_IS_OK(status)) {
				results[i] = HRES_ERROR(W_ERROR_V(ntstatus_to_werror(status)));
			} else if (!ru_template)
				ru_template = (*ip)[i];
		}
	}

	/* TODO:avg check when exactly oxid should be updated,its lifetime etc */
	if (m->rem_unknown && memcmp(&m->rem_unknown->obj.u_objref.u_standard.std.ipid, &ipidRemUnknown, sizeof(ipidRemUnknown))) {
		talloc_free(m->rem_unknown);
		m->rem_unknown = NULL;
	}
	if (!m->rem_unknown) {
		if (!ru_template) {
			DEBUG(1,("dcom_create_object: Cannot Create IRemUnknown - template interface not available\n"));
			hr = HRES_ERROR(W_ERROR_V(WERR_GEN_FAILURE));
		}
		m->rem_unknown = talloc_zero(m, struct IRemUnknown);
        // printf("rem_unknown %p\n", m->rem_unknown);
        // talloc_report_full(m->rem_unknown, stdout);
		memcpy(m->rem_unknown, ru_template, sizeof(struct IUnknown));
		GUID_from_string(COM_IREMUNKNOWN_UUID, &m->rem_unknown->obj.iid);
		m->rem_unknown->obj.u_objref.u_standard.std.ipid = ipidRemUnknown;
		m->rem_unknown->vtable = (struct IRemUnknown_vtable *)dcom_proxy_vtable_by_iid(&m->rem_unknown->obj.iid);
		/* TODO:avg copy stringbindigs?? */
	}
    // talloc_report_full(pds->stringbindings, stdout);
	dcom_update_credentials_for_aliases(ctx, server, pds);
	{
		char *c;
		c = strchr(server, '[');
		if (m->host) talloc_free(m->host);
		m->host = c ? talloc_strndup(m, server, c - server) : talloc_strdup(m, server);
	}
	hr = HRES_ERROR(W_ERROR_V(WERR_OK));
end:
	talloc_free(loc_ctx);
	return hr;
}

int find_similar_binding(struct STRINGBINDING **sb, const char *host)
{
	int i, l;
	l = strlen(host);
	for (i = 0; sb[i]; ++i) {
		if ((sb[i]->wTowerId == EPM_PROTOCOL_TCP) && !strncasecmp(host, sb[i]->NetworkAddr, l) && (sb[i]->NetworkAddr[l] == '['))
		break;
	}
	return i;
}

WERROR dcom_query_interface(struct IUnknown *d, uint32_t cRefs, uint16_t cIids, struct GUID *iids, struct IUnknown **ip, WERROR *results)
{
	struct dcom_object_exporter *ox;
	struct REMQIRESULT *rqir;
	WERROR result;
	NTSTATUS status;
	int i;
	TALLOC_CTX *loc_ctx;
	struct IUnknown ru;

    (void)rqir;
	loc_ctx = talloc_new(d);
	ox = object_exporter_by_ip(d->ctx, d);
    result = WERR_GEN_FAILURE;
	//DCOM_TODO: result = IRemUnknown_RemQueryInterface(ox->rem_unknown, loc_ctx, &IUnknown_ipid(d), cRefs, cIids, iids, &rqir);
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(1, ("dcom_query_interface failed: %08X\n", W_ERROR_V(result)));
		talloc_free(loc_ctx);
		return result;
	}
	ru = *(struct IUnknown *)ox->rem_unknown;
	for (i = 0; i < cIids; ++i) {
		ip[i] = NULL;
		//DCOM_TODO: results[i] = rqir[i].hResult;
		if (W_ERROR_IS_OK(results[i])) {
			ru.obj.iid = iids[i];
			//DCOM_TODO: ru.obj.u_objref.u_standard.std = rqir[i].std;
			status = NT_STATUS(W_ERROR_V(dcom_IUnknown_from_OBJREF(d->ctx, &ip[i], &ru.obj)));
			if (!NT_STATUS_IS_OK(status)) {
				results[i] = ntstatus_to_werror(status);
			}
		}
	}

	talloc_free(loc_ctx);
	return WERR_OK;
}

int is_ip_binding(const char* s)
{
	while (*s && (*s != '[')) {
		if (((*s >= '0') && (*s <= '9')) || *s == '.')
			++s;
		else
		    return 0;
	}
	return 1;
}

static NTSTATUS dcom_get_pipe_impl(struct com_context *ctx, struct OBJREF* obj, struct GUID* iid, struct dcerpc_pipe **pp)
{
  struct dcerpc_binding *binding;
	//DCOM_TODO: uint64_t oxid;
	NTSTATUS status;
	int i, j, isimilar;
	struct dcerpc_pipe *p;
	struct dcom_object_exporter *ox;
	const struct ndr_interface_table *table;

	ox = object_exporter_by_oxid(ctx, obj->u_objref.u_standard.std.oxid);
	if (!ox) {
		DEBUG(0, ("dcom_get_pipe: OXID not found\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}
	p = ox->pipe;
  DEBUG(0, ("dcom_get_pipe_impl ox->pipe ok %p\n", (void*)p));
	table = ndr_table_by_uuid(iid);
	if (table == NULL) {
		char *guid_str;
		guid_str = GUID_string(NULL, iid);
		DEBUG(0,(__location__": dcom_get_pipe - unrecognized interface{%s}\n", guid_str));
		talloc_free(guid_str);
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (p && p->last_fault_code) {
		talloc_free(p);
		ox->pipe = p = NULL;
	}

	if (p) {
		if (!GUID_equal(&p->syntax.uuid, iid)) {
			ox->pipe->syntax.uuid = *iid;
      DEBUG(0, ("dcom_get_pipe_impl interface will always be present\n"));
			/* interface will always be present, so
			 * idl_iface_by_uuid can't return NULL */
      //memset(&p->conn->security_state.tmp_auth_info, 0, sizeof(p->conn->security_state.tmp_auth_info));
			//*pp = p;
			//status = dcerpc_pipe_auth(ctx, pp, p->binding, ndr_table_by_uuid(iid), ctx->dcom->credentials->credentials, ctx->lp_ctx);
			status = dcerpc_secondary_context(p, pp, ndr_table_by_uuid(iid));
      ox->pipe = *pp;
			//status = dcerpc_alter_context(p, ctx, &ndr_table_by_uuid(iid)->syntax_id, &p->transfer_syntax);
      // status = NT_STATUS_OK;
		  //*pp = p;
		}
    else {
			status = NT_STATUS_OK;
		  *pp = p;
    }
		return status;
	}

	status = NT_STATUS_NO_MORE_ENTRIES;

	/* To avoid delays whe connecting nonroutable bindings we 1st check binding starting with hostname */
	/* FIX:low create concurrent connections to all bindings, fastest wins - Win2k and newer does this way???? */
	isimilar = find_similar_binding(ox->bindings->stringbindings, ox->host);
	DEBUG(0, (__location__": dcom_get_pipe: host=%s, similar=%s\n", ox->host, ox->bindings->stringbindings[isimilar] ? ox->bindings->stringbindings[isimilar]->NetworkAddr : "None"));
	j = isimilar - 1;
	for (i = 0; ox->bindings->stringbindings[i]; ++i) {
		if (!ox->bindings->stringbindings[++j]) j = 0;
		/* FIXME:LOW Use also other transports if possible */
		if ((j != isimilar) && (ox->bindings->stringbindings[j]->wTowerId != EPM_PROTOCOL_TCP || !is_ip_binding(ox->bindings->stringbindings[j]->NetworkAddr))) {
			DEBUG(9, ("dcom_get_pipe: Skipping stringbinding %24.24s\n", ox->bindings->stringbindings[j]->NetworkAddr));
			continue;
		}
		DEBUG(9, ("dcom_get_pipe: Trying stringbinding %s\n", ox->bindings->stringbindings[j]->NetworkAddr));
		status = dcerpc_binding_from_STRINGBINDING(ctx, &binding,
							   ox->bindings->stringbindings[j]);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Error parsing string binding"));
		} else {
			/* FIXME:LOW Make flags more flexible */
			binding->flags |= DCERPC_AUTH_NTLM | DCERPC_SIGN;
			if (DEBUGLVL(11))
				binding->flags |= DCERPC_DEBUG_PRINT_BOTH;
			status = dcerpc_pipe_connect_b(ctx->event_ctx, &p, binding,
						       ndr_table_by_uuid(iid),
						       dcom_get_server_credentials(ctx, binding->host),
							   ctx->event_ctx, ctx->lp_ctx);
			talloc_unlink(ctx, binding);
		}
		if (NT_STATUS_IS_OK(status)) break;
	}

	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Unable to connect to remote host - %s\n", nt_errstr(status)));
		return status;
	}

	//DCOM_TODO: DEBUG(2, ("Successfully connected to OXID %llx\n", (long long)oxid));

	ox->pipe = *pp = p;
    DEBUG(0, ("dcom_get_pipe_impl ok\n"));
	return NT_STATUS_OK;
}

NTSTATUS dcom_binding_handle(struct com_context *ctx, struct OBJREF* obj, struct GUID* iid, struct dcerpc_binding_handle **ph)
{
    struct dcerpc_pipe *p = NULL;
    NTSTATUS status = dcom_get_pipe_impl(ctx, obj, iid, &p);
    if (NT_STATUS_IS_OK(status)) {
        *ph = p->binding_handle;
    }
    return status;
}

NTSTATUS dcom_get_pipe(struct IUnknown *iface, struct dcerpc_pipe **pp)
{
    return dcom_get_pipe_impl(iface->ctx, &iface->obj, &iface->vtable->iid, pp);
}

WERROR dcom_OBJREF_from_IUnknown(TALLOC_CTX *mem_ctx, struct OBJREF *o, struct IUnknown *p)
{
	/* FIXME: Cache generated objref objects? */
	ZERO_STRUCTP(o);
	
	if (!p) {
		o->signature = OBJREF_SIGNATURE;
		o->flags = OBJREF_NULL;
	} else {
		*o = p->obj;
		switch(o->flags) {
		case OBJREF_CUSTOM: {
			marshal_fn marshal;

			marshal = dcom_marshal_by_clsid(&o->u_objref.u_custom.clsid);
			if (marshal) {
				return W_ERROR(marshal(mem_ctx, p, o));
			} else {
				return W_ERROR(NT_STATUS_V(NT_STATUS_NOT_SUPPORTED));
			}
		}
		}
	}

	return W_ERROR(NT_STATUS_V(NT_STATUS_OK));
}

WERROR dcom_IUnknown_from_MIP(struct com_context *ctx, struct IUnknown **_p, struct MInterfacePointer *_mi)
{
    return dcom_IUnknown_from_OBJREF(ctx, _p, &_mi->obj);
}

WERROR dcom_IUnknown_from_OBJREF(struct com_context *ctx, struct IUnknown **_p, struct OBJREF *o)
{
	struct IUnknown *p;
	struct dcom_object_exporter *ox;
	unmarshal_fn unmarshal;

	switch(o->flags) {
	case OBJREF_NULL:
		*_p = NULL;
		return W_ERROR(NDR_ERR_SUCCESS);

	case OBJREF_STANDARD:
		p = talloc_zero(ctx, struct IUnknown);
		p->ctx = ctx;
		p->obj = *o;
		p->vtable = dcom_proxy_vtable_by_iid(&o->iid);

		if (!p->vtable) {
			DEBUG(0, ("Unable to find proxy class for interface with IID %s\n", GUID_string(ctx, &o->iid)));
			return W_ERROR(NDR_ERR_INVALID_POINTER);
		}

		p->vtable->Release = dcom_release;

		ox = object_exporter_by_oxid(ctx, o->u_objref.u_standard.std.oxid);
		/* FIXME: Add object to list of objects to ping */
		*_p = p;
		return W_ERROR(NDR_ERR_SUCCESS);
		
	case OBJREF_HANDLER:
		p = talloc_zero(ctx, struct IUnknown);
		p->ctx = ctx;	
		p->obj = *o;
		ox = object_exporter_by_oxid(ctx, o->u_objref.u_handler.std.oxid );
		/* FIXME: Add object to list of objects to ping */
/*FIXME		p->vtable = dcom_vtable_by_clsid(&o->u_objref.u_handler.clsid);*/
		/* FIXME: Do the custom unmarshaling call */

		*_p = p;
		return W_ERROR(NDR_ERR_BAD_SWITCH);
		
	case OBJREF_CUSTOM:
		p = talloc_zero(ctx, struct IUnknown);
		p->ctx = ctx;	
		p->vtable = NULL;
		p->obj = *o;
		unmarshal = dcom_unmarshal_by_clsid(&o->u_objref.u_custom.clsid);
		*_p = p;
		if (unmarshal) {
		    return W_ERROR(unmarshal(ctx, o, _p));
		} else {
		    return W_ERROR(NDR_ERR_BAD_SWITCH);
		}
	}
    (void)ox;
	return W_ERROR(NDR_ERR_BAD_SWITCH);
}

uint64_t dcom_get_current_oxid(void)
{
	return getpid();
}

/* FIXME:Fake async dcom_get_pipe_* */
struct composite_context *dcom_get_pipe_send(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
        struct composite_context *c;

        c = composite_create(0, d->ctx->event_ctx);
        if (c == NULL) return NULL;
        c->private_data = d;
        /* composite_done(c); bugged - callback is triggered twice by composite_continue and composite_done */
        c->state = COMPOSITE_STATE_DONE; /* this is workaround */

        return c;
}

NTSTATUS dcom_get_pipe_recv(struct composite_context *c, struct dcerpc_pipe **pp)
{
        NTSTATUS status;

        status = dcom_get_pipe((struct IUnknown *)c->private_data, pp);
        talloc_free(c);

        return status;
}

/* FIXME:avg put IUnknown_Release_out into header */
struct IUnknown_Release_out {
        uint32_t result;
};

void dcom_release_continue(struct composite_context *cr)
{
	struct composite_context *c;
	struct IUnknown *d;
	struct IUnknown_Release_out *out;
	//DCOM_TODO: WERROR r;

	c = talloc_get_type(cr->async.private_data, struct composite_context);
	d = c->private_data;
	//DCOM_TODO: r = IRemUnknown_RemRelease_recv(cr);
	talloc_free(d);
	out = talloc_zero(c, struct IUnknown_Release_out);
	//DCOM_TODO: out->result = W_ERROR_V(r);
	c->private_data = out;
	composite_done(c);
}

struct composite_context *dcom_release_send(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
        struct composite_context *c, *cr;
	struct REMINTERFACEREF iref;
	struct dcom_object_exporter *ox;

        c = composite_create(d->ctx, d->ctx->event_ctx);
        if (c == NULL) return NULL;
        c->private_data = d;

	ox = object_exporter_by_ip(d->ctx, d);
	iref.ipid = IUnknown_ipid(d);
	iref.cPublicRefs = 5;
	iref.cPrivateRefs = 0;
	//DCOM_TODO: cr = IRemUnknown_RemRelease_send(ox->rem_unknown, mem_ctx, 1, &iref);
    (void)ox;
    (void)iref;
    (void)cr;
	//DCOM_TODO: composite_continue(c, cr, dcom_release_continue, c);
	return c;
}

uint32_t dcom_release_recv(struct composite_context *c)
{
	NTSTATUS status;
	WERROR r;

	status = composite_wait(c);
	if (!NT_STATUS_IS_OK(status))
		r = ntstatus_to_werror(status);
	else
		W_ERROR_V(r) = ((struct IUnknown_Release_out *)c->private_data)->result;
	talloc_free(c);
	return W_ERROR_IS_OK(r) ? 0 : W_ERROR_V(r);
}

uint32_t dcom_release(struct IUnknown *interface, TALLOC_CTX *mem_ctx)
{
	struct composite_context *c;

	c = dcom_release_send(interface, mem_ctx);
	return dcom_release_recv(c);
}

// void dcom_proxy_async_call_recv_pipe_send_rpc(struct composite_context *c_pipe)
// {
//         struct composite_context *c;
//         struct dcom_proxy_async_call_state *s;
//         struct dcerpc_pipe *p;
//         struct rpc_request *req;
//         NTSTATUS status;

//         c = c_pipe->async.private_data;
//         s = talloc_get_type(c->private_data, struct dcom_proxy_async_call_state);

//         status = dcom_get_pipe_recv(c_pipe, &p);
//         if (!NT_STATUS_IS_OK(status)) {
//                 composite_error(c, NT_STATUS_RPC_NT_CALL_FAILED);
//                 return;
//         }
// /*TODO: FIXME - for now this unused anyway */
//         req = dcerpc_ndr_request_send(p, &s->d->obj.u_objref.u_standard.std.ipid, s->table, s->opnum, s, s->r);
//         composite_continue_rpc(c, req, s->continuation, c);
// }
