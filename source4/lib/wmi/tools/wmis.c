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
#include "auth/credentials/credentials.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_oxidresolver_c.h"
#include "librpc/gen_ndr/dcom.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_dcom_c.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/gen_ndr/com_dcom.h"

#include "lib/com/dcom/dcom.h"
#include "librpc/gen_ndr/com_wmi.h"
#include "librpc/ndr/ndr_table.h"

#include "lib/wmi/wmi.h"

struct program_args {
    char *hostname;
    char *query;
    struct cli_credentials *credentials;
};

static void parse_args(int argc, const char *argv[],
                TALLOC_CTX *mem_ctx, struct program_args *pmyargs)
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
	POPT_TABLEEND
    };

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

    poptSetOtherOptionHelp(pc, "//host\n\nExample: wmis -U [domain/]adminuser%password //host");

    while ((opt = poptGetNextOpt(pc)) != -1) {
        poptPrintUsage(pc, stdout, 0);
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

    if (argc_new < 2 || argv_new[1][0] != '/'
        || argv_new[1][1] != '/') {
        poptPrintUsage(pc, stdout, 0);
        poptFreeContext(pc);
        exit(1);
    }
    pmyargs->credentials = samba_cmdline_get_creds();
    pmyargs->hostname = argv_new[1] + 2;
    pmyargs->query = argv_new[2];
    poptFreeContext(pc);
}

#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
                            DEBUG(0, ("%s:%d ERROR: %s -> %x\n", __FILE__, __LINE__, msg, W_ERROR_V(result))); \
                            goto error; \
                        } else { \
                            DEBUG(0, ("%s:%d OK   : %s\n", __FILE__, __LINE__, msg)); \
                        }
/*
WERROR WBEM_ConnectServer(struct com_context *ctx, const char *server, const char *nspace, const char *user, const char *password, const char *locale, uint32_t flags, const char *authority, struct IWbemContext* wbem_ctx, struct IWbemServices** services)
{
	struct GUID clsid;
	struct GUID iid;
	WERROR result;
	HRESULT coresult;
	struct IUnknown **mqi;
	struct IWbemLevel1Login *pL;

	if (user) {
		char *cred;
		struct cli_credentials *cc;

		cred = talloc_asprintf(NULL, "%s%%%s", user, password);
		cc = cli_credentials_init(ctx);
		cli_credentials_set_conf(cc);
		cli_credentials_parse_string(cc, cred, CRED_SPECIFIED);
		dcom_set_server_credentials(ctx, server, cc);
		talloc_free(cred);
	}

	GUID_from_string(CLSID_WBEMLEVEL1LOGIN, &clsid);
	GUID_from_string(COM_IWBEMLEVEL1LOGIN_UUID, &iid);
	result = dcom_create_object(ctx, &clsid, server, 1, &iid, &mqi, &coresult);
	WERR_CHECK("dcom_create_object.");
	result = coresult;
	WERR_CHECK("Create remote WMI object.");
	pL = (struct IWbemLevel1Login *)mqi[0];
	talloc_free(mqi);

	result = IWbemLevel1Login_NTLMLogin(pL, ctx, nspace, locale, flags, wbem_ctx, services);
	WERR_CHECK("Login to remote object.");
error:
	return result;
}
*/
void print_CIMVALUE(FILE* out, enum CIMTYPE_ENUMERATION cimtype, const union CIMVAR* value, int level);
void print_CIMTYPE(FILE* out, enum CIMTYPE_ENUMERATION cimtype, int level);
void print_WbemQualifier(FILE* out, const struct WbemQualifier *c, int level);
void print_WbemProperty(FILE* out, const struct WbemProperty *c, int level);
void print_WbemClassMethod(FILE* out, struct WbemMethod* m, int level);
void print_WbemClassMethods(FILE* out, struct WbemMethods* m, int level);
void print_WbemClass(FILE* out, struct WbemClass *c, int level);
void print_WbemClassObject(FILE* out, struct WbemClassObject *r, int level);
void print_IWbemClassObject(FILE* out, struct IWbemClassObject *wco, int level);

void print_LEVEL(FILE* out, int level);
void print_LEVEL(FILE* out, int level) {
	for (; level > 0; --level)
		fprintf(out, "\t");
}
void print_CIMVALUE(FILE* out, enum CIMTYPE_ENUMERATION cimtype, const union CIMVAR* value, int level) {
	switch (cimtype) {
		case CIM_EMPTY: fprintf(out, "''"); break;
		case CIM_SINT16: fprintf(out, "%d", value->v_sint16); break;
		case CIM_SINT32: fprintf(out, "%d", value->v_sint32); break;
		case CIM_REAL32: fprintf(out, "%x", value->v_real32); break;
		case CIM_REAL64: fprintf(out, "%lx", value->v_real64); break;
		case CIM_STRING: fprintf(out, "%s", value->v_string ? value->v_string : "(NULL)"); break;
		case CIM_BOOLEAN: fprintf(out, "%s", value->v_boolean ? "TRUE" : "FALSE"); break;
		case CIM_OBJECT: fprintf(out, "!"); break;
		case CIM_SINT8: fprintf(out, "%d", (int)value->v_sint8); break;
		case CIM_UINT8: fprintf(out, "%x", (uint32_t)value->v_uint8); break;
		case CIM_UINT16: fprintf(out, "%x", value->v_uint16); break;
		case CIM_UINT32: fprintf(out, "%x", value->v_uint32); break;
		case CIM_SINT64: fprintf(out, "%ld", value->v_sint64); break;
		case CIM_UINT64: fprintf(out, "%lx", value->v_uint64); break;
		case CIM_DATETIME: fprintf(out, "%s", value->v_datetime ? value->v_datetime : "(NULL)"); break;
		case CIM_REFERENCE: fprintf(out, "%s", value->v_reference ? value->v_reference : "(NULL)"); break;
		case CIM_CHAR16: fprintf(out, "%x", value->v_uint16); break;
		case CIM_FLAG_ARRAY: fprintf(out, "CIM_FLAG_ARRAY"); break;
		case CIM_ILLEGAL: fprintf(out, "-"); break;
		case CIM_TYPEMASK: fprintf(out, "CIM_TYPEMASK"); break;
		case CIM_ARR_SINT8: fprintf(out, "CIM_ARR_SINT8"); break;
		case CIM_ARR_UINT8: fprintf(out, "CIM_ARR_UINT8"); break;
		case CIM_ARR_SINT16: fprintf(out, "CIM_ARR_SINT16"); break;
		case CIM_ARR_UINT16: fprintf(out, "CIM_ARR_UINT16"); break;
		case CIM_ARR_SINT32: fprintf(out, "CIM_ARR_SINT32"); break;
		case CIM_ARR_UINT32: fprintf(out, "CIM_ARR_UINT32"); break;
		case CIM_ARR_SINT64: fprintf(out, "CIM_ARR_SINT64"); break;
		case CIM_ARR_UINT64: fprintf(out, "CIM_ARR_UINT64"); break;
		case CIM_ARR_REAL32: fprintf(out, "CIM_ARR_REAL32"); break;
		case CIM_ARR_REAL64: fprintf(out, "CIM_ARR_REAL64"); break;
		case CIM_ARR_BOOLEAN: fprintf(out, "CIM_ARR_BOOLEAN"); break;
		case CIM_ARR_STRING: {
			if (value->a_string) {
				fprintf(out, "%d[", value->a_string->count);
				for (uint32_t i = 0; i < value->a_string->count; ++i) {
					if (value->a_string->item[i])
						fprintf(out, "\"%s\"", value->a_string->item[i]);
					else
						fprintf(out, "NULL ");
				}
				fprintf(out, "]");
			}
			else {
				fprintf(out, "(NULL)"); break;
			}
			break;
		}
		case CIM_ARR_DATETIME: fprintf(out, "CIM_ARR_DATETIME"); break;
		case CIM_ARR_REFERENCE: fprintf(out, "CIM_ARR_REFERENCE"); break;
		case CIM_ARR_CHAR16: fprintf(out, "CIM_ARR_CHAR16"); break;
		case CIM_ARR_OBJECT: fprintf(out, "CIM_ARR_OBJECT"); break;
		default:
			fprintf(out, "UNKNOWN(0x%x)", cimtype); break;
	}
}
void print_CIMTYPE(FILE* out, enum CIMTYPE_ENUMERATION cimtype, int level) {
	switch (cimtype) {
		case CIM_EMPTY: fprintf(out, "CIM_EMPTY"); break;
		case CIM_SINT16: fprintf(out, "CIM_SINT16"); break;
		case CIM_SINT32: fprintf(out, "CIM_SINT32"); break;
		case CIM_REAL32: fprintf(out, "CIM_REAL32"); break;
		case CIM_REAL64: fprintf(out, "CIM_REAL64"); break;
		case CIM_STRING: fprintf(out, "CIM_STRING"); break;
		case CIM_BOOLEAN: fprintf(out, "CIM_BOOLEAN"); break;
		case CIM_OBJECT: fprintf(out, "CIM_OBJECT"); break;
		case CIM_SINT8: fprintf(out, "CIM_SINT8"); break;
		case CIM_UINT8: fprintf(out, "CIM_UINT8"); break;
		case CIM_UINT16: fprintf(out, "CIM_UINT16"); break;
		case CIM_UINT32: fprintf(out, "CIM_UINT32"); break;
		case CIM_SINT64: fprintf(out, "CIM_SINT64"); break;
		case CIM_UINT64: fprintf(out, "CIM_UINT64"); break;
		case CIM_DATETIME: fprintf(out, "CIM_DATETIME"); break;
		case CIM_REFERENCE: fprintf(out, "CIM_REFERENCE"); break;
		case CIM_CHAR16: fprintf(out, "CIM_CHAR16"); break;
		case CIM_FLAG_ARRAY: fprintf(out, "CIM_FLAG_ARRAY"); break;
		case CIM_ILLEGAL: fprintf(out, "CIM_ILLEGAL"); break;
		case CIM_TYPEMASK: fprintf(out, "CIM_TYPEMASK"); break;
		case CIM_ARR_SINT8: fprintf(out, "CIM_ARR_SINT8"); break;
		case CIM_ARR_UINT8: fprintf(out, "CIM_ARR_UINT8"); break;
		case CIM_ARR_SINT16: fprintf(out, "CIM_ARR_SINT16"); break;
		case CIM_ARR_UINT16: fprintf(out, "CIM_ARR_UINT16"); break;
		case CIM_ARR_SINT32: fprintf(out, "CIM_ARR_SINT32"); break;
		case CIM_ARR_UINT32: fprintf(out, "CIM_ARR_UINT32"); break;
		case CIM_ARR_SINT64: fprintf(out, "CIM_ARR_SINT64"); break;
		case CIM_ARR_UINT64: fprintf(out, "CIM_ARR_UINT64"); break;
		case CIM_ARR_REAL32: fprintf(out, "CIM_ARR_REAL32"); break;
		case CIM_ARR_REAL64: fprintf(out, "CIM_ARR_REAL64"); break;
		case CIM_ARR_BOOLEAN: fprintf(out, "CIM_ARR_BOOLEAN"); break;
		case CIM_ARR_STRING: fprintf(out, "CIM_ARR_STRING"); break;
		case CIM_ARR_DATETIME: fprintf(out, "CIM_ARR_DATETIME"); break;
		case CIM_ARR_REFERENCE: fprintf(out, "CIM_ARR_REFERENCE"); break;
		case CIM_ARR_CHAR16: fprintf(out, "CIM_ARR_CHAR16"); break;
		case CIM_ARR_OBJECT: fprintf(out, "CIM_ARR_OBJECT"); break;
		default:
			fprintf(out, "UNKNOWN(0x%x)", cimtype); break;
	}
}
void print_WbemQualifier(FILE* out, const struct WbemQualifier *c, int level) {
	fprintf(out, "'%s'", c->name ? c->name : "(NULL)");
	fprintf(out, " flavors=%x", c->flavors);
	fprintf(out, " type=");
	print_CIMTYPE(out, c->cimtype, level+1);
	fprintf(out, " value=");
	print_CIMVALUE(out, c->cimtype, &c->value, level+1);
}

void print_WbemProperty(FILE* out, const struct WbemProperty *c, int level) {
	fprintf(out, "'%s'", c->name ? c->name : "(NULL)");
	if (c->desc) {
		fprintf(out, " depth=%d", c->desc->depth);
		fprintf(out, " offset=%d", c->desc->offset);
		fprintf(out, " nr=%d", c->desc->nr);
		fprintf(out, " type=");
		print_CIMTYPE(out, c->desc->cimtype, level+1);
		fprintf(out, " qualifiers=[%d]", c->desc->qualifiers.count);
		for (uint32_t i = 0; i < c->desc->qualifiers.count; ++i) {
			fprintf(out, "\n");
			print_LEVEL(out, level+1);
			fprintf(out, "[%d] ", i);
			print_WbemQualifier(out, c->desc->qualifiers.item[i], level+1);
		}
	}
}

void print_WbemClassMethod(FILE* out, struct WbemMethod* m, int level) {
	if (!m) return;
	fprintf(out, "'%s'", m->name ? m->name : "(NULL)");
	fprintf(out, " flags=%x", m->flags);
	fprintf(out, " origin=%d", m->origin);
	if (m->qualifiers) {
		fprintf(out, " qualifiers=[%d]", m->qualifiers->count);
	}
	for (uint32_t i = 0; i < m->qualifiers->count; ++i) {
		fprintf(out, "\n");
		print_LEVEL(out, level+1);
		fprintf(out, "qual[%d] ", i);
		print_WbemQualifier(out, m->qualifiers->item[i], level+1);
	}
	if (m->in) {
		fprintf(out, "\n");
		print_LEVEL(out, level+1);
		fprintf(out, "in:\n");
		print_WbemClassObject(out, m->in, level+1);
	}
	if (m->out) {
		fprintf(out, "\n");
		print_LEVEL(out, level+1);
		fprintf(out, "out:\n");
		print_WbemClassObject(out, m->out, level+1);
	}
}
void print_WbemClassMethods(FILE* out, struct WbemMethods* m, int level) {
	if (m && m->count) {
		print_LEVEL(out, level);
		fprintf(out, "methods: [%d]\n", m->count);
		for (uint32_t i = 0; i < m->count; ++i) {
			print_LEVEL(out, level+1);
			fprintf(out,"[%d] ", i);
			print_WbemClassMethod(out, &m->method[i], level+1);
			fprintf(out, "\n");
		}
	}
}
void print_WbemClass(FILE* out, struct WbemClass *c, int level) {
	if (!c) return;
	if (c->__DERIVATION.count) {
		print_LEVEL(out, level);
		fprintf(out, "derived: [%d]\n", c->__DERIVATION.count);
		for (uint32_t i = 0; i < c->__DERIVATION.count; ++i) {
			print_LEVEL(out, level+1);
			fprintf(out, "[%d] '%s'\n", i, c->__DERIVATION.item[i]);
		}
	}
	if (c->qualifiers.count) {
		print_LEVEL(out, level);
		fprintf(out, "qualifiers: [%d]\n", c->qualifiers.count);
		for (uint32_t i = 0; i < c->qualifiers.count; ++i) {
			print_LEVEL(out, level+1);
			fprintf(out,"[%d] ", i);
			print_WbemQualifier(out, c->qualifiers.item[i], level+1);
			fprintf(out, "\n");
		}
	}
	if (c->__PROPERTY_COUNT) {
		print_LEVEL(out, level);
		printf("properties: [%d]\n", c->__PROPERTY_COUNT);
		for (uint32_t i = 0; i < c->__PROPERTY_COUNT; ++i) {
			print_LEVEL(out, level+1);
			fprintf(out, "[%d] ", i);
			print_WbemProperty(out, &c->properties[i], level+1);
			fprintf(out, "\n");
		}
	}
}
void print_WbemClassObject(FILE* out, struct WbemClassObject *r, int level) {
	if (!r) return;
	if (r->sup_class && r->sup_class->__CLASS) {
		print_LEVEL(out, level);
		fprintf(out, "super class: '%s'\n", r->sup_class->__CLASS);
		print_WbemClass(out, r->sup_class, level+1);
		print_WbemClassMethods(out, r->sup_methods, level+1);
	}
	if (r->obj_class && r->obj_class->__CLASS) {
		print_LEVEL(out, level);
		fprintf(out, "current class: '%s'\n", r->obj_class->__CLASS);
		print_WbemClass(out, r->obj_class, level+1);
		print_WbemClassMethods(out, r->obj_methods, level+1);
	}
}
void print_IWbemClassObject(FILE* out, struct IWbemClassObject *wco, int level) {
	struct WbemClassObject *r = NULL;
	if (wco) {
		r = (struct WbemClassObject*)wco->object_data;
		print_WbemClassObject(out, r, level);
	}
}
WERROR WBEM_RemoteExecute(struct IWbemServices *pWS, const char *cmdline, uint32_t *ret_code);
WERROR WBEM_RemoteExecute(struct IWbemServices *pWS, const char *cmdline, uint32_t *ret_code)
{
	struct IWbemClassObject *wco = NULL;
	struct IWbemClassObject *inc = NULL, *outc = NULL, *in = NULL;
	struct IWbemClassObject *out = NULL;
	struct IWbemCallResult *res = NULL;
	WERROR result;
	union CIMVAR v;
	TALLOC_CTX *ctx;
	struct BSTR objectPath, methodName;

	ctx = talloc_new(0);

	objectPath.data = "Win32_Process";
	result = IWbemServices_GetObject(pWS, ctx, objectPath,
					 WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &wco, NULL);
	WERR_CHECK("GetObject. ");
	//print_IWbemClassObject(stdout, wco, 0);
    //wco->obj = pWS->obj;
    (void)methodName;
    (void)inc;
    (void)outc;
    (void)in;
    (void)out;
    (void)res;
    (void)v;

	result = IWbemClassObject_GetMethod(wco, ctx, "Create", 0, &inc, &outc);
	WERR_CHECK("IWbemClassObject_GetMethod.");

	result = IWbemClassObject_SpawnInstance(inc, ctx, 0, &in);
	WERR_CHECK("IWbemClassObject_SpawnInstance.");

	v.v_string = cmdline;
	result = IWbemClassObject_Put(in, ctx, "CommandLine", 0, &v, 0);
	WERR_CHECK("IWbemClassObject_Put(CommandLine).");
	v.v_string = "c:\\";
	result = IWbemClassObject_Put(in, ctx, "CurrentDirectory", 0, &v, 0);
	WERR_CHECK("IWbemClassObject_Put(CurrentDirectory).");
	//print_IWbemClassObject(stdout, in, 0);
	methodName.data = "Create";
	// result = IWbemServices_ExecMethod(pWS, ctx, objectPath, methodName, 0, NULL, in, &out,
	//  				  NULL);
	// result = IWbemServices_ExecMethod(pWS, ctx, objectPath, methodName, 0, NULL, 0x35ea, in, 0x2416, NULL,
	// 				  NULL);
	result = IWbemServices_ExecMethod(pWS, ctx, objectPath, methodName, 0
		, NULL, 0xff, in, NULL, NULL);
	// result = IWbemServices_ExecMethod(pWS, ctx, objectPath, methodName, 0
	// 	, NULL, 0x35ea, in, NULL, NULL);
	// result = IWbemServices_ExecMethod(pWS, ctx, objectPath, methodName, 0
	// , NULL, in, NULL, NULL);
	WERR_CHECK("IWbemServices_ExecMethod.");

	// if (ret_code) {
	// 	result = IWbemClassObject_Get(out->object_data, ctx, "ReturnValue", 0, &v, 0, 0);
	// 	WERR_CHECK("IWbemClassObject_Get(ReturnValue).");
	// 	*ret_code = v.v_uint32;
	// }
    goto error;
error:
	//talloc_free(ctx);
	return result;
}

char ns[] = "//./root/cimv2";

int main(int argc, char **argv)
{
    TALLOC_CTX *frame = NULL;
	const char **const_argv = NULL;
    struct program_args args = {};
	struct com_context *ctx = NULL;
	WERROR result;
	NTSTATUS status;
	struct IWbemServices *pWS = NULL;
	struct IEnumWbemClassObject *pEnum = NULL;
	uint32_t cnt = 0;
	struct BSTR queryLanguage;
	//struct BSTR query;
	struct loadparm_context *lp_ctx =  NULL;

    (void)queryLanguage;
    (void)cnt;
    (void)pEnum;
	frame = talloc_init("root");
	//frame = talloc_stackframe();
	const_argv = discard_const_p(const char *, argv);

    smb_init_locale();
    parse_args(argc, const_argv, frame, &args);
    lp_ctx = samba_cmdline_get_lp_ctx();
    //samba_cmdline_burn(argc, argv);
	wmi_init(&ctx, args.credentials, lp_ctx);

	result = WBEM_ConnectServer(ctx, args.hostname, ns, 0, 0, 0, 0, 0, &pWS);
	WERR_CHECK("WBEM_ConnectServer.");

	printf("1: Creating directory C:\\wmi_test_dir_tmp using method Win32_Process.Create\n");
	result = WBEM_RemoteExecute(pWS, "cmd.exe /C mkdir C:\\wmi_test_dir.tmp", &cnt);
	//result = WBEM_RemoteExecute(pWS, "notepad.exe", &cnt);
	//WERR_CHECK("WBEM_RemoteExecute.");
	printf("2: ReturnCode: %d\n", cnt);

	// printf("3: Monitoring directory C:\\wmi_test_dir_tmp. Please create/delete files in that directory to see notifications, after 4 events program quits.\n");
	// query.data = "SELECT * FROM __InstanceOperationEvent WITHIN 1 WHERE Targetinstance ISA 'CIM_DirectoryContainsFile' and TargetInstance.GroupComponent= 'Win32_Directory.Name=\"C:\\\\\\\\wmi_test_dir_tmp\"'";
	// queryLanguage.data = "WQL";
	// result = IWbemServices_ExecNotificationQuery(pWS, ctx, queryLanguage,
	// 	query, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
	// WERR_CHECK("WMI query execute.");
	// for (cnt = 0; cnt < 4; ++cnt) {
	// 	struct IWbemClassObject *co;
	// 	uint32_t ret;
	// 	result = IEnumWbemClassObject_SmartNext(pEnum, ctx, 0xFFFFFFFF, 1, &co, &ret);
    // 		WERR_CHECK("IEnumWbemClassObject_Next.");
	// 	//DCOM_TODO: printf("%s\n", co->obj_class->__CLASS);
	// }

error:
	status = werror_to_ntstatus(result);
	fprintf(stderr, "NTSTATUS: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status));
	//talloc_free(ctx);
	return 1;
}
