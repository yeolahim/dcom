/*
   WMI Sample client
   Copyright (C) 2006 Andrzej Hajda <andrzej.hajda@wp.pl>
   Copyright (C) 2008 Jelmer Vernooij <jelmer@samba.org>

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
#include "auth/credentials/credentials.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "lib/com/dcom/dcom.h"
#include "librpc/gen_ndr/wmi.h"
#include "librpc/gen_ndr/com_wmi.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/ndr/ndr_table.h"
#include "lib/wmi/wmi.h"

struct IWbemServices;
struct IWbemContext;

const char *wmi_errstr(WERROR werror);

#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
                            DEBUG(0, ("ERROR: %s -> %x\n", msg, W_ERROR_V(result))); \
                            goto end; \
                        } else { \
                            DEBUG(1, ("OK   : %s\n", msg)); \
                        }

extern NTSTATUS dcom_proxy_init_IUnknown(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemServices(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IEnumWbemClassObject(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemLevel1Login(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemWCOSmartEnum(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemFetchSmartEnum(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemCallResult(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IWbemObjectSink(TALLOC_CTX *ctx);
extern NTSTATUS dcom_proxy_init_IRemUnknown(TALLOC_CTX *ctx);

extern NTSTATUS dcom_proxy_IWbemClassObject_init(TALLOC_CTX *ctx);

void wmi_init(struct com_context **ctx, struct cli_credentials *credentials,
			  struct loadparm_context *lp_ctx)
{
	dcerpc_init();
	ndr_table_init();

    com_init_ctx(ctx, lp_ctx, NULL);
    /* FIXME: Register DCOM proxies? */
    dcom_proxy_init_IUnknown(*ctx);
    dcom_proxy_init_IWbemServices(*ctx);
    dcom_proxy_init_IEnumWbemClassObject(*ctx);
    dcom_proxy_init_IWbemLevel1Login(*ctx);
    dcom_proxy_init_IWbemWCOSmartEnum(*ctx);
    dcom_proxy_init_IWbemFetchSmartEnum(*ctx);
    dcom_proxy_init_IWbemCallResult(*ctx);
    dcom_proxy_init_IWbemObjectSink(*ctx);
    dcom_proxy_init_IRemUnknown(*ctx);

    dcom_proxy_IWbemClassObject_init(*ctx);

	dcom_client_init(*ctx, credentials);
}

/** FIXME: Use credentials struct rather than user/password here */
WERROR WBEM_ConnectServer(struct com_context *ctx, const char *server, char *nspace,
			  struct cli_credentials *credentials,
			  uint16_t *locale, uint32_t flags, const char *authority,
			  struct IWbemContext* wbem_ctx, struct IWbemServices** services)
{
        struct GUID clsid;
        struct GUID iid;
        WERROR result;
        HRESULT hresult;
        HRESULT coresult;
        struct IUnknown **mqi;
        struct IWbemLevel1Login *pL;

        GUID_from_string(CLSID_WBEMLEVEL1LOGIN, &clsid);
        GUID_from_string(COM_IWBEMLEVEL1LOGIN_UUID, &iid);
        hresult = dcom_create_object(ctx, &clsid, server, 1, &iid, &mqi, &coresult);
        result = W_ERROR(HRES_ERROR_V(hresult));
        WERR_CHECK("dcom_create_object.");
        result = W_ERROR(HRES_ERROR_V(coresult));
        WERR_CHECK("Create remote WMI object.");
        pL = (struct IWbemLevel1Login *)mqi[0];
        talloc_free(mqi);

        result = IWbemLevel1Login_NTLMLogin(pL, ctx, ((uint16_t*)nspace), locale, flags, wbem_ctx, services);
        //DEBUG(0, ("IWbemServices: %p\n", *services));
        //result = IWbemLevel1Login_NTLMLogin(pL, ctx, 0, locale, flags, wbem_ctx, services);
        WERR_CHECK("Login to remote object.");
	//DCOM_TODO:    result = W_ERROR(IUnknown_Release((struct IUnknown *)pL, ctx));
        WERR_CHECK("Release Login.");
        //DEBUG(0, ("Done: %p\n",*services));
end:
        return result;
}

struct werror_code_struct {
        const char *dos_errstr;
        WERROR werror;
};

static const struct werror_code_struct wmi_errs[] =
{
	{ "RPC_S_CALL_FAILED", W_ERROR(RPC_S_CALL_FAILED) },

        { "WBEM_NO_ERROR", W_ERROR(WBEM_NO_ERROR) },
        { "WBEM_S_NO_ERROR", W_ERROR(WBEM_S_NO_ERROR) },
        { "WBEM_S_SAME", W_ERROR(WBEM_S_SAME) },
        { "WBEM_S_FALSE", W_ERROR(WBEM_S_FALSE) },
        { "WBEM_S_ALREADY_EXISTS", W_ERROR(WBEM_S_ALREADY_EXISTS) },
        { "WBEM_S_RESET_TO_DEFAULT", W_ERROR(WBEM_S_RESET_TO_DEFAULT) },
        { "WBEM_S_DIFFERENT", W_ERROR(WBEM_S_DIFFERENT) },
        { "WBEM_S_TIMEDOUT", W_ERROR(WBEM_S_TIMEDOUT) },
        { "WBEM_S_NO_MORE_DATA", W_ERROR(WBEM_S_NO_MORE_DATA) },
        { "WBEM_S_OPERATION_CANCELLED", W_ERROR(WBEM_S_OPERATION_CANCELLED) },
        { "WBEM_S_PENDING", W_ERROR(WBEM_S_PENDING) },
        { "WBEM_S_DUPLICATE_OBJECTS", W_ERROR(WBEM_S_DUPLICATE_OBJECTS) },
        { "WBEM_S_ACCESS_DENIED", W_ERROR(WBEM_S_ACCESS_DENIED) },
        { "WBEM_S_PARTIAL_RESULTS", W_ERROR(WBEM_S_PARTIAL_RESULTS) },
        { "WBEM_S_NO_POSTHOOK", W_ERROR(WBEM_S_NO_POSTHOOK) },
        { "WBEM_S_POSTHOOK_WITH_BOTH", W_ERROR(WBEM_S_POSTHOOK_WITH_BOTH) },
        { "WBEM_S_POSTHOOK_WITH_NEW", W_ERROR(WBEM_S_POSTHOOK_WITH_NEW) },
        { "WBEM_S_POSTHOOK_WITH_STATUS", W_ERROR(WBEM_S_POSTHOOK_WITH_STATUS) },
        { "WBEM_S_POSTHOOK_WITH_OLD", W_ERROR(WBEM_S_POSTHOOK_WITH_OLD) },
        { "WBEM_S_REDO_PREHOOK_WITH_ORIGINAL_OBJECT", W_ERROR(WBEM_S_REDO_PREHOOK_WITH_ORIGINAL_OBJECT) },
        { "WBEM_S_SOURCE_NOT_AVAILABLE", W_ERROR(WBEM_S_SOURCE_NOT_AVAILABLE) },
        { "WBEM_E_FAILED", W_ERROR(WBEM_E_FAILED) },
        { "WBEM_E_NOT_FOUND", W_ERROR(WBEM_E_NOT_FOUND) },
        { "WBEM_E_ACCESS_DENIED", W_ERROR(WBEM_E_ACCESS_DENIED) },
        { "WBEM_E_PROVIDER_FAILURE", W_ERROR(WBEM_E_PROVIDER_FAILURE) },
        { "WBEM_E_TYPE_MISMATCH", W_ERROR(WBEM_E_TYPE_MISMATCH) },
        { "WBEM_E_OUT_OF_MEMORY", W_ERROR(WBEM_E_OUT_OF_MEMORY) },
        { "WBEM_E_INVALID_CONTEXT", W_ERROR(WBEM_E_INVALID_CONTEXT) },
        { "WBEM_E_INVALID_PARAMETER", W_ERROR(WBEM_E_INVALID_PARAMETER) },
        { "WBEM_E_NOT_AVAILABLE", W_ERROR(WBEM_E_NOT_AVAILABLE) },
        { "WBEM_E_CRITICAL_ERROR", W_ERROR(WBEM_E_CRITICAL_ERROR) },
        { "WBEM_E_INVALID_STREAM", W_ERROR(WBEM_E_INVALID_STREAM) },
        { "WBEM_E_NOT_SUPPORTED", W_ERROR(WBEM_E_NOT_SUPPORTED) },
        { "WBEM_E_INVALID_SUPERCLASS", W_ERROR(WBEM_E_INVALID_SUPERCLASS) },
        { "WBEM_E_INVALID_NAMESPACE", W_ERROR(WBEM_E_INVALID_NAMESPACE) },
        { "WBEM_E_INVALID_OBJECT", W_ERROR(WBEM_E_INVALID_OBJECT) },
        { "WBEM_E_INVALID_CLASS", W_ERROR(WBEM_E_INVALID_CLASS) },
        { "WBEM_E_PROVIDER_NOT_FOUND", W_ERROR(WBEM_E_PROVIDER_NOT_FOUND) },
        { "WBEM_E_INVALID_PROVIDER_REGISTRATION", W_ERROR(WBEM_E_INVALID_PROVIDER_REGISTRATION) },
        { "WBEM_E_PROVIDER_LOAD_FAILURE", W_ERROR(WBEM_E_PROVIDER_LOAD_FAILURE) },
        { "WBEM_E_INITIALIZATION_FAILURE", W_ERROR(WBEM_E_INITIALIZATION_FAILURE) },
        { "WBEM_E_TRANSPORT_FAILURE", W_ERROR(WBEM_E_TRANSPORT_FAILURE) },
        { "WBEM_E_INVALID_OPERATION", W_ERROR(WBEM_E_INVALID_OPERATION) },
        { "WBEM_E_INVALID_QUERY", W_ERROR(WBEM_E_INVALID_QUERY) },
        { "WBEM_E_INVALID_QUERY_TYPE", W_ERROR(WBEM_E_INVALID_QUERY_TYPE) },
        { "WBEM_E_ALREADY_EXISTS", W_ERROR(WBEM_E_ALREADY_EXISTS) },
        { "WBEM_E_OVERRIDE_NOT_ALLOWED", W_ERROR(WBEM_E_OVERRIDE_NOT_ALLOWED) },
        { "WBEM_E_PROPAGATED_QUALIFIER", W_ERROR(WBEM_E_PROPAGATED_QUALIFIER) },
        { "WBEM_E_PROPAGATED_PROPERTY", W_ERROR(WBEM_E_PROPAGATED_PROPERTY) },
        { "WBEM_E_UNEXPECTED", W_ERROR(WBEM_E_UNEXPECTED) },
        { "WBEM_E_ILLEGAL_OPERATION", W_ERROR(WBEM_E_ILLEGAL_OPERATION) },
        { "WBEM_E_CANNOT_BE_KEY", W_ERROR(WBEM_E_CANNOT_BE_KEY) },
        { "WBEM_E_INCOMPLETE_CLASS", W_ERROR(WBEM_E_INCOMPLETE_CLASS) },
        { "WBEM_E_INVALID_SYNTAX", W_ERROR(WBEM_E_INVALID_SYNTAX) },
        { "WBEM_E_NONDECORATED_OBJECT", W_ERROR(WBEM_E_NONDECORATED_OBJECT) },
        { "WBEM_E_READ_ONLY", W_ERROR(WBEM_E_READ_ONLY) },
        { "WBEM_E_PROVIDER_NOT_CAPABLE", W_ERROR(WBEM_E_PROVIDER_NOT_CAPABLE) },
        { "WBEM_E_CLASS_HAS_CHILDREN", W_ERROR(WBEM_E_CLASS_HAS_CHILDREN) },
        { "WBEM_E_CLASS_HAS_INSTANCES", W_ERROR(WBEM_E_CLASS_HAS_INSTANCES) },
        { "WBEM_E_QUERY_NOT_IMPLEMENTED", W_ERROR(WBEM_E_QUERY_NOT_IMPLEMENTED) },
        { "WBEM_E_ILLEGAL_NULL", W_ERROR(WBEM_E_ILLEGAL_NULL) },
        { "WBEM_E_INVALID_QUALIFIER_TYPE", W_ERROR(WBEM_E_INVALID_QUALIFIER_TYPE) },
        { "WBEM_E_INVALID_PROPERTY_TYPE", W_ERROR(WBEM_E_INVALID_PROPERTY_TYPE) },
        { "WBEM_E_VALUE_OUT_OF_RANGE", W_ERROR(WBEM_E_VALUE_OUT_OF_RANGE) },
        { "WBEM_E_CANNOT_BE_SINGLETON", W_ERROR(WBEM_E_CANNOT_BE_SINGLETON) },
        { "WBEM_E_INVALID_CIM_TYPE", W_ERROR(WBEM_E_INVALID_CIM_TYPE) },
        { "WBEM_E_INVALID_METHOD", W_ERROR(WBEM_E_INVALID_METHOD) },
        { "WBEM_E_INVALID_METHOD_PARAMETERS", W_ERROR(WBEM_E_INVALID_METHOD_PARAMETERS) },
        { "WBEM_E_SYSTEM_PROPERTY", W_ERROR(WBEM_E_SYSTEM_PROPERTY) },
        { "WBEM_E_INVALID_PROPERTY", W_ERROR(WBEM_E_INVALID_PROPERTY) },
        { "WBEM_E_CALL_CANCELLED", W_ERROR(WBEM_E_CALL_CANCELLED) },
        { "WBEM_E_SHUTTING_DOWN", W_ERROR(WBEM_E_SHUTTING_DOWN) },
        { "WBEM_E_PROPAGATED_METHOD", W_ERROR(WBEM_E_PROPAGATED_METHOD) },
        { "WBEM_E_UNSUPPORTED_PARAMETER", W_ERROR(WBEM_E_UNSUPPORTED_PARAMETER) },
        { "WBEM_E_MISSING_PARAMETER_ID", W_ERROR(WBEM_E_MISSING_PARAMETER_ID) },
        { "WBEM_E_INVALID_PARAMETER_ID", W_ERROR(WBEM_E_INVALID_PARAMETER_ID) },
        { "WBEM_E_NONCONSECUTIVE_PARAMETER_IDS", W_ERROR(WBEM_E_NONCONSECUTIVE_PARAMETER_IDS) },
        { "WBEM_E_PARAMETER_ID_ON_RETVAL", W_ERROR(WBEM_E_PARAMETER_ID_ON_RETVAL) },
        { "WBEM_E_INVALID_OBJECT_PATH", W_ERROR(WBEM_E_INVALID_OBJECT_PATH) },
        { "WBEM_E_OUT_OF_DISK_SPACE", W_ERROR(WBEM_E_OUT_OF_DISK_SPACE) },
        { "WBEM_E_BUFFER_TOO_SMALL", W_ERROR(WBEM_E_BUFFER_TOO_SMALL) },
        { "WBEM_E_UNSUPPORTED_PUT_EXTENSION", W_ERROR(WBEM_E_UNSUPPORTED_PUT_EXTENSION) },
        { "WBEM_E_UNKNOWN_OBJECT_TYPE", W_ERROR(WBEM_E_UNKNOWN_OBJECT_TYPE) },
        { "WBEM_E_UNKNOWN_PACKET_TYPE", W_ERROR(WBEM_E_UNKNOWN_PACKET_TYPE) },
        { "WBEM_E_MARSHAL_VERSION_MISMATCH", W_ERROR(WBEM_E_MARSHAL_VERSION_MISMATCH) },
        { "WBEM_E_MARSHAL_INVALID_SIGNATURE", W_ERROR(WBEM_E_MARSHAL_INVALID_SIGNATURE) },
        { "WBEM_E_INVALID_QUALIFIER", W_ERROR(WBEM_E_INVALID_QUALIFIER) },
        { "WBEM_E_INVALID_DUPLICATE_PARAMETER", W_ERROR(WBEM_E_INVALID_DUPLICATE_PARAMETER) },
        { "WBEM_E_TOO_MUCH_DATA", W_ERROR(WBEM_E_TOO_MUCH_DATA) },
        { "WBEM_E_SERVER_TOO_BUSY", W_ERROR(WBEM_E_SERVER_TOO_BUSY) },
        { "WBEM_E_INVALID_FLAVOR", W_ERROR(WBEM_E_INVALID_FLAVOR) },
        { "WBEM_E_CIRCULAR_REFERENCE", W_ERROR(WBEM_E_CIRCULAR_REFERENCE) },
        { "WBEM_E_UNSUPPORTED_CLASS_UPDATE", W_ERROR(WBEM_E_UNSUPPORTED_CLASS_UPDATE) },
        { "WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE", W_ERROR(WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE) },
        { "WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE", W_ERROR(WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE) },
        { "WBEM_E_TOO_MANY_PROPERTIES", W_ERROR(WBEM_E_TOO_MANY_PROPERTIES) },
        { "WBEM_E_UPDATE_TYPE_MISMATCH", W_ERROR(WBEM_E_UPDATE_TYPE_MISMATCH) },
        { "WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED", W_ERROR(WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED) },
        { "WBEM_E_UPDATE_PROPAGATED_METHOD", W_ERROR(WBEM_E_UPDATE_PROPAGATED_METHOD) },
        { "WBEM_E_METHOD_NOT_IMPLEMENTED", W_ERROR(WBEM_E_METHOD_NOT_IMPLEMENTED) },
        { "WBEM_E_METHOD_DISABLED", W_ERROR(WBEM_E_METHOD_DISABLED) },
        { "WBEM_E_REFRESHER_BUSY", W_ERROR(WBEM_E_REFRESHER_BUSY) },
        { "WBEM_E_UNPARSABLE_QUERY", W_ERROR(WBEM_E_UNPARSABLE_QUERY) },
        { "WBEM_E_NOT_EVENT_CLASS", W_ERROR(WBEM_E_NOT_EVENT_CLASS) },
        { "WBEM_E_MISSING_GROUP_WITHIN", W_ERROR(WBEM_E_MISSING_GROUP_WITHIN) },
        { "WBEM_E_MISSING_AGGREGATION_LIST", W_ERROR(WBEM_E_MISSING_AGGREGATION_LIST) },
        { "WBEM_E_PROPERTY_NOT_AN_OBJECT", W_ERROR(WBEM_E_PROPERTY_NOT_AN_OBJECT) },
        { "WBEM_E_AGGREGATING_BY_OBJECT", W_ERROR(WBEM_E_AGGREGATING_BY_OBJECT) },
        { "WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY", W_ERROR(WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY) },
        { "WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING", W_ERROR(WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING) },
        { "WBEM_E_QUEUE_OVERFLOW", W_ERROR(WBEM_E_QUEUE_OVERFLOW) },
        { "WBEM_E_PRIVILEGE_NOT_HELD", W_ERROR(WBEM_E_PRIVILEGE_NOT_HELD) },
        { "WBEM_E_INVALID_OPERATOR", W_ERROR(WBEM_E_INVALID_OPERATOR) },
        { "WBEM_E_LOCAL_CREDENTIALS", W_ERROR(WBEM_E_LOCAL_CREDENTIALS) },
        { "WBEM_E_CANNOT_BE_ABSTRACT", W_ERROR(WBEM_E_CANNOT_BE_ABSTRACT) },
        { "WBEM_E_AMENDED_OBJECT", W_ERROR(WBEM_E_AMENDED_OBJECT) },
        { "WBEM_E_CLIENT_TOO_SLOW", W_ERROR(WBEM_E_CLIENT_TOO_SLOW) },
        { "WBEM_E_NULL_SECURITY_DESCRIPTOR", W_ERROR(WBEM_E_NULL_SECURITY_DESCRIPTOR) },
        { "WBEM_E_TIMED_OUT", W_ERROR(WBEM_E_TIMED_OUT) },
        { "WBEM_E_INVALID_ASSOCIATION", W_ERROR(WBEM_E_INVALID_ASSOCIATION) },
        { "WBEM_E_AMBIGUOUS_OPERATION", W_ERROR(WBEM_E_AMBIGUOUS_OPERATION) },
        { "WBEM_E_QUOTA_VIOLATION", W_ERROR(WBEM_E_QUOTA_VIOLATION) },
        { "WBEM_E_RESERVED_001", W_ERROR(WBEM_E_RESERVED_001) },
        { "WBEM_E_RESERVED_002", W_ERROR(WBEM_E_RESERVED_002) },
        { "WBEM_E_UNSUPPORTED_LOCALE", W_ERROR(WBEM_E_UNSUPPORTED_LOCALE) },
        { "WBEM_E_HANDLE_OUT_OF_DATE", W_ERROR(WBEM_E_HANDLE_OUT_OF_DATE) },
        { "WBEM_E_CONNECTION_FAILED", W_ERROR(WBEM_E_CONNECTION_FAILED) },
        { "WBEM_E_INVALID_HANDLE_REQUEST", W_ERROR(WBEM_E_INVALID_HANDLE_REQUEST) },
        { "WBEM_E_PROPERTY_NAME_TOO_WIDE", W_ERROR(WBEM_E_PROPERTY_NAME_TOO_WIDE) },
        { "WBEM_E_CLASS_NAME_TOO_WIDE", W_ERROR(WBEM_E_CLASS_NAME_TOO_WIDE) },
        { "WBEM_E_METHOD_NAME_TOO_WIDE", W_ERROR(WBEM_E_METHOD_NAME_TOO_WIDE) },
        { "WBEM_E_QUALIFIER_NAME_TOO_WIDE", W_ERROR(WBEM_E_QUALIFIER_NAME_TOO_WIDE) },
        { "WBEM_E_RERUN_COMMAND", W_ERROR(WBEM_E_RERUN_COMMAND) },
        { "WBEM_E_DATABASE_VER_MISMATCH", W_ERROR(WBEM_E_DATABASE_VER_MISMATCH) },
        { "WBEM_E_VETO_DELETE", W_ERROR(WBEM_E_VETO_DELETE) },
        { "WBEM_E_VETO_PUT", W_ERROR(WBEM_E_VETO_PUT) },
        { "WBEM_E_INVALID_LOCALE", W_ERROR(WBEM_E_INVALID_LOCALE) },
        { "WBEM_E_PROVIDER_SUSPENDED", W_ERROR(WBEM_E_PROVIDER_SUSPENDED) },
        { "WBEM_E_SYNCHRONIZATION_REQUIRED", W_ERROR(WBEM_E_SYNCHRONIZATION_REQUIRED) },
        { "WBEM_E_NO_SCHEMA", W_ERROR(WBEM_E_NO_SCHEMA) },
        { "WBEM_E_PROVIDER_ALREADY_REGISTERED", W_ERROR(WBEM_E_PROVIDER_ALREADY_REGISTERED) },
        { "WBEM_E_PROVIDER_NOT_REGISTERED", W_ERROR(WBEM_E_PROVIDER_NOT_REGISTERED) },
        { "WBEM_E_FATAL_TRANSPORT_ERROR", W_ERROR(WBEM_E_FATAL_TRANSPORT_ERROR) },
        { "WBEM_E_ENCRYPTED_CONNECTION_REQUIRED", W_ERROR(WBEM_E_ENCRYPTED_CONNECTION_REQUIRED) },
        { "WBEM_E_PROVIDER_TIMED_OUT", W_ERROR(WBEM_E_PROVIDER_TIMED_OUT) },
        { "WBEM_E_NO_KEY", W_ERROR(WBEM_E_NO_KEY) },
        { "WBEM_E_PROVIDER_DISABLED", W_ERROR(WBEM_E_PROVIDER_DISABLED) },
        { NULL, W_ERROR(0) }
};

const char *wmi_errstr(WERROR werror)
{
        int idx = 0;

        while (wmi_errs[idx].dos_errstr != NULL) {
                if (W_ERROR_V(wmi_errs[idx].werror) ==
                    W_ERROR_V(werror))
                        return wmi_errs[idx].dos_errstr;
                idx++;
        }

        return win_errstr(werror);
}
