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
#include "third_party/popt/popt.h"
#include "lib/cmdline/cmdline.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_oxidresolver_c.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_dcom_c.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/gen_ndr/com_dcom.h"

#include "lib/com/dcom/dcom.h"
#include "lib/com/com.h"

#include "lib/wmi/wmi.h"

struct program_args {
    char *hostname;
    char *query;
    char *ns;
    char *delim;
    struct cli_credentials *credentials;
};

static void parse_args(int argc, const char *argv[],
                TALLOC_CTX *mem_ctx,
                struct program_args *pmyargs)
{
    poptContext pc;
    int opt, i;

    int argc_new;
    char **argv_new;
    bool ok;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        POPT_COMMON_SAMBA
        POPT_COMMON_CONNECTION
        POPT_COMMON_CREDENTIALS
        POPT_COMMON_VERSION
        {
            .longName = "namespace",
            .shortName = 0,
            .argInfo = POPT_ARG_STRING,
            .arg = &pmyargs->ns,
            .val = 0,
            .descrip = "WMI namespace, default to root\\cimv2",
            .argDescrip = NULL
        },
        {
            .longName = "delimiter",
            .shortName = 0,
            .argInfo = POPT_ARG_STRING,
            .arg = &pmyargs->delim,
            .val = 0,
            .descrip = "delimiter to use when querying multiple values, default to '|'",
            .argDescrip = NULL
        },
        POPT_TABLEEND
    };
    ZERO_STRUCTP(pmyargs);

    ok = samba_cmdline_init(mem_ctx,
        SAMBA_CMDLINE_CONFIG_CLIENT,
        false /* require_smbconf */);
    if (!ok) {
        DBG_ERR("Failed to init cmdline parser!\n");
        TALLOC_FREE(mem_ctx);
        exit(1);
    }

    pc = samba_popt_get_context(getprogname(),
        argc,
        argv,
        long_options,
        POPT_CONTEXT_KEEP_FIRST);
    if (pc == NULL) {
        DBG_ERR("Failed to setup popt context!\n");
        TALLOC_FREE(mem_ctx);
        exit(1);
    }

    poptSetOtherOptionHelp(pc, "//host query\n\nExample: wmic -U [domain/]adminuser%password //host \"select * from Win32_ComputerSystem\"");

    while ((opt = poptGetNextOpt(pc)) != -1) {
        poptPrintHelp(pc, stdout, 0);
        poptFreeContext(pc);
        exit(1);
    }

    argv_new = discard_const_p(char *, poptGetArgs(pc));

    argc_new = argc;
    for (i = 0; i < argc; i++) {
        if (argv_new[i] == NULL) {
            argc_new = i;
            break;
        }
    }

    if (argc_new != 3
        || strncmp(argv_new[1], "//", 2) != 0) {
        poptPrintHelp(pc, stdout, 0);
        poptFreeContext(pc);
        exit(1);
    }

    pmyargs->credentials = samba_cmdline_get_creds();

    /* skip over leading "//" in host name */
    pmyargs->hostname = argv_new[1] + 2;
    pmyargs->query = argv_new[2];
    poptFreeContext(pc);
}

bool verbose = true;
#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
		DEBUG(0, ("%s:%d ERROR: %s -> %x\n", __FILE__, __LINE__, msg, W_ERROR_V(result))); \
			goto error; \
		} else { \
			if (verbose) {\
				DEBUG(0, ("%s:%d OK   : %s\n", __FILE__, __LINE__, msg)); \
			}\
		}

#define RETURN_CVAR_ARRAY_STR(fmt, arr) {\
	uint32_t i;\
	char *r;\
\
	if (!arr) {\
	        return talloc_strdup(mem_ctx, "NULL");\
	}\
	r = talloc_strdup(mem_ctx, "(");\
	for (i = 0; i < arr->count; ++i) {\
		r = talloc_asprintf_append(r, fmt "%s", arr->item[i], (i+1 == arr->count)?"":",");\
	}\
	return talloc_asprintf_append(r, ")");\
}

#define RETURN_CVAR_ARRAY_STR2(fmt, TYPE, arr) {\
	uint32_t i;\
	char *r;\
\
	if (!arr) {\
	        return talloc_strdup(mem_ctx, "NULL");\
	}\
	r = talloc_strdup(mem_ctx, "(");\
	for (i = 0; i < arr->count; ++i) {\
		r = talloc_asprintf_append(r, fmt "%s", (TYPE)arr->item[i], (i+1 == arr->count)?"":",");\
	}\
	return talloc_asprintf_append(r, ")");\
}

char *string_CIMVAR(TALLOC_CTX *mem_ctx, union CIMVAR *v, enum CIMTYPE_ENUMERATION cimtype);
char *string_CIMVAR(TALLOC_CTX *mem_ctx, union CIMVAR *v, enum CIMTYPE_ENUMERATION cimtype)
{
	switch (cimtype) {
	case CIM_SINT8: return talloc_asprintf(mem_ctx, "%d", v->v_sint8);
	case CIM_UINT8: return talloc_asprintf(mem_ctx, "%u", v->v_uint8);
	case CIM_SINT16: return talloc_asprintf(mem_ctx, "%d", v->v_sint16);
	case CIM_UINT16: return talloc_asprintf(mem_ctx, "%u", v->v_uint16);
	case CIM_SINT32: return talloc_asprintf(mem_ctx, "%d", v->v_sint32);
	case CIM_UINT32: return talloc_asprintf(mem_ctx, "%u", v->v_uint32);
	case CIM_SINT64: return talloc_asprintf(mem_ctx, "%ld", v->v_sint64);
	case CIM_UINT64: return talloc_asprintf(mem_ctx, "%lu", v->v_sint64);
	case CIM_REAL32: return talloc_asprintf(mem_ctx, "%f", (double)v->v_uint32);
	case CIM_REAL64: return talloc_asprintf(mem_ctx, "%f", (double)v->v_uint64);
	case CIM_BOOLEAN: return talloc_asprintf(mem_ctx, "%s", v->v_boolean?"True":"False");
	case CIM_STRING:
	case CIM_DATETIME:
	case CIM_REFERENCE: return talloc_asprintf(mem_ctx, "%s", v->v_string);
	case CIM_CHAR16: return talloc_asprintf(mem_ctx, "Unsupported");
	case CIM_OBJECT: return talloc_asprintf(mem_ctx, "Unsupported");
	case CIM_ARR_SINT8: RETURN_CVAR_ARRAY_STR("%d", v->a_sint8);
	case CIM_ARR_UINT8: RETURN_CVAR_ARRAY_STR("%u", v->a_uint8);
	case CIM_ARR_SINT16: RETURN_CVAR_ARRAY_STR("%d", v->a_sint16);
	case CIM_ARR_UINT16: RETURN_CVAR_ARRAY_STR("%u", v->a_uint16);
	case CIM_ARR_SINT32: RETURN_CVAR_ARRAY_STR("%d", v->a_sint32);
	case CIM_ARR_UINT32: RETURN_CVAR_ARRAY_STR("%u", v->a_uint32);
	case CIM_ARR_SINT64: RETURN_CVAR_ARRAY_STR("%ld", v->a_sint64);
	case CIM_ARR_UINT64: RETURN_CVAR_ARRAY_STR("%lu", v->a_uint64);
	case CIM_ARR_REAL32: RETURN_CVAR_ARRAY_STR2("%f", double, v->a_real32);
	case CIM_ARR_REAL64: RETURN_CVAR_ARRAY_STR2("%f", double, v->a_real64);
	case CIM_ARR_BOOLEAN: RETURN_CVAR_ARRAY_STR("%d", v->a_boolean);
	case CIM_ARR_STRING: RETURN_CVAR_ARRAY_STR("%s", v->a_string);
	case CIM_ARR_DATETIME: RETURN_CVAR_ARRAY_STR("%s", v->a_datetime);
	case CIM_ARR_REFERENCE: RETURN_CVAR_ARRAY_STR("%s", v->a_reference);
	default: return talloc_asprintf(mem_ctx, "Unsupported");
	}
    return NULL;
}

#undef RETURN_CVAR_ARRAY_STR

char ns[] = "//./root/cimv2";
int main(int argc, char **argv)
{
    TALLOC_CTX *frame = NULL;
	const char **const_argv = NULL;
    struct program_args args = {};
	uint32_t cnt = 1, ret;
	char *class_name = NULL;
	WERROR result;
	NTSTATUS status;
	struct IWbemServices *pWS = NULL;
	struct BSTR queryLanguage, query;
	struct IEnumWbemClassObject *pEnum = NULL;
	struct com_context *ctx = NULL;
    struct loadparm_context *lp_ctx = NULL;
    TALLOC_CTX *mem_ctx = NULL;
    struct IWbemClassObject *co = NULL;

    (void)co;
    (void)pEnum;
    (void)mem_ctx;
    (void)query;
    (void)queryLanguage;
    (void)class_name;
    (void)ret;

	frame = talloc_init("root");
	const_argv = discard_const_p(const char *, argv);

    smb_init_locale();
    parse_args(argc, const_argv, frame, &args);
    lp_ctx = samba_cmdline_get_lp_ctx();
    samba_cmdline_burn(argc, argv);
	wmi_init(&ctx, args.credentials, lp_ctx);

	if (!args.ns)
		args.ns = ns;
	result = WBEM_ConnectServer(ctx, args.hostname, args.ns, 0, 0, 0, 0, 0, &pWS);
	WERR_CHECK("Login to remote object.");

	queryLanguage.data = "WQL";
	query.data = args.query;
	result = IWbemServices_ExecQuery(pWS, ctx, queryLanguage, query
		, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_ENSURE_LOCATABLE | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
	WERR_CHECK("WMI query execute.");

	IEnumWbemClassObject_Reset(pEnum, ctx);
	WERR_CHECK("Reset result of WMI query.");
	mem_ctx = talloc_new(0);
	do {
		uint32_t i, j;
		(void)i;
		(void)j;
		result = IEnumWbemClassObject_IEnumWbemClassObject_Next(pEnum, mem_ctx, 0xFFFFFFFF, 1, &co, &ret);
		//result = IEnumWbemClassObject_SmartNext(pEnum, mem_ctx, 0xFFFFFFFF, cnt, co, &ret);
		/* WERR_INVALID_FUNCTION is OK, it means only that there is less returned objects than requested */
		if (!W_ERROR_EQUAL(result, WERR_INVALID_FUNCTION)) {
			WERR_CHECK("Retrieve result data.");
		} else {
			DEBUG(1, ("OK   : Retrieved less objects than requested (it is normal).\n"));
		}
        result = W_ERROR(0);
		if (!ret) break;

		for (i = 0; i < ret; ++i) {
            struct WbemClassObject *r = (struct WbemClassObject*)co->object_data;
			if (!class_name || strcmp(r->obj_class->__CLASS, class_name)) {
				if (class_name) talloc_free(class_name);
				class_name = talloc_strdup(ctx, r->obj_class->__CLASS);
				printf("CLASS: %s\n", class_name);
				for (j = 0; j < r->obj_class->__PROPERTY_COUNT; ++j)
					printf("%s%s", j?"|":"", r->obj_class->properties[j].name);
				printf("\n");
			}
			if (r->instance) {
				for (j = 0; j < r->obj_class->__PROPERTY_COUNT; ++j) {
					char *s;
					s = string_CIMVAR(ctx, &r->instance->data[j], r->obj_class->properties[j].desc->cimtype & CIM_TYPEMASK);
					printf("%s%s", j?"|":"", s);
				}
			}
			printf("\n");
		}
	} while (ret == cnt);
error:
	if (!W_ERROR_IS_OK(result)) {
		status = werror_to_ntstatus(result);
		if (verbose)
			fprintf(stderr, "NTSTATUS: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status));
		//talloc_free(ctx);
		return 1;
	}
	return 0;
}
