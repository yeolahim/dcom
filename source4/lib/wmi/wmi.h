/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008

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

#ifndef _WMI_H_
#define _WMI_H_

#include "librpc/gen_ndr/com_wmi.h"

typedef const char *CIMSTRING;

struct arr_int8 {
	uint32_t count;
	int8_t *item;
}/* [public] */;

struct arr_uint8 {
	uint32_t count;
	uint8_t *item;
}/* [public] */;

struct arr_int16 {
	uint32_t count;
	int16_t *item;
}/* [public] */;

struct arr_uint16 {
	uint32_t count;
	uint16_t *item;
}/* [public] */;

struct arr_int32 {
	uint32_t count;
	int32_t *item;
}/* [public] */;

struct arr_uint32 {
	uint32_t count;
	uint32_t *item;
}/* [public] */;

struct arr_dlong {
	uint32_t count;
	int64_t *item;
}/* [public] */;

struct arr_udlong {
	uint32_t count;
	uint64_t *item;
}/* [public] */;

struct arr_CIMSTRING {
	uint32_t count;
	CIMSTRING *item;/* [relative,string,charset(UTF16)] */
}/* [public] */;

struct arr_WbemClassObject {
	uint32_t count;
	struct WbemClassObject **item;/* [relative,subcontext(4)] */
}/* [public] */;

union CIMVAR {
	int8_t v_sint8;/* [case(CIM_SINT8)] */
	uint8_t v_uint8;/* [case(CIM_UINT8)] */
	int16_t v_sint16;/* [case(CIM_SINT16)] */
	uint16_t v_uint16;/* [case(CIM_UINT16)] */
	int32_t v_sint32;/* [case(CIM_SINT32)] */
	uint32_t v_uint32;/* [case(CIM_UINT32)] */
	int64_t v_sint64;/* [case(CIM_SINT64)] */
	uint64_t v_uint64;/* [case(CIM_UINT64)] */
	uint32_t v_real32;/* [case(CIM_REAL32)] */
	uint64_t v_real64;/* [case(CIM_REAL64)] */
	uint16_t v_boolean;/* [case(CIM_BOOLEAN)] */
	CIMSTRING v_string;/* [case(CIM_STRING),relative,string,charset(UTF16)] */
	CIMSTRING v_datetime;/* [case(CIM_DATETIME),relative,string,charset(UTF16)] */
	CIMSTRING v_reference;/* [case(CIM_REFERENCE),relative,string,charset(UTF16)] */
	struct WbemClassObject *v_object;/* [relative,subcontext(4),case(CIM_OBJECT)] */
	struct arr_int8 *a_sint8;/* [case(CIM_ARR_SINT8),relative] */
	struct arr_uint8 *a_uint8;/* [relative,case(CIM_ARR_UINT8)] */
	struct arr_int16 *a_sint16;/* [relative,case(CIM_ARR_SINT16)] */
	struct arr_uint16 *a_uint16;/* [case(CIM_ARR_UINT16),relative] */
	struct arr_int32 *a_sint32;/* [relative,case(CIM_ARR_SINT32)] */
	struct arr_uint32 *a_uint32;/* [relative,case(CIM_ARR_UINT32)] */
	struct arr_dlong *a_sint64;/* [relative,case(CIM_ARR_SINT64)] */
	struct arr_udlong *a_uint64;/* [case(CIM_ARR_UINT64),relative] */
	struct arr_uint32 *a_real32;/* [case(CIM_ARR_REAL32),relative] */
	struct arr_udlong *a_real64;/* [relative,case(CIM_ARR_REAL64)] */
	struct arr_uint16 *a_boolean;/* [relative,case(CIM_ARR_BOOLEAN)] */
	struct arr_CIMSTRING *a_string;/* [relative,case(CIM_ARR_STRING)] */
	struct arr_CIMSTRING *a_datetime;/* [relative,case(CIM_ARR_DATETIME)] */
	struct arr_CIMSTRING *a_reference;/* [relative,case(CIM_ARR_REFERENCE)] */
	struct arr_WbemClassObject *a_object;/* [relative,case(CIM_ARR_OBJECT)] */
}/* [public,nodiscriminant] */;

/* bitmap WBEM_FLAVOR_TYPE */
#define WBEM_FLAVOR_FLAG_PROPAGATE_TO_INSTANCE ( 0x1 )
#define WBEM_FLAVOR_FLAG_PROPAGATE_TO_DERIVED_CLASS ( 0x2 )
#define WBEM_FLAVOR_NOT_OVERRIDABLE ( 0x10 )
#define WBEM_FLAVOR_ORIGIN_PROPAGATED ( 0x20 )
#define WBEM_FLAVOR_ORIGIN_SYSTEM ( 0x40 )
#define WBEM_FLAVOR_AMENDED ( 0x80 )

/* bitmap WCO_FLAGS */
#define WCF_DECORATIONS ( 1 )
#define WCF_INSTANCE ( 2 )
#define WCF_CLASS ( 4 )
#define WCF_CLASS_PART_INTERNAL ( 8 )

struct WbemQualifier {
	CIMSTRING name;/* [relative,string,charset(UTF16)] */
	uint8_t flavors;
	enum CIMTYPE_ENUMERATION cimtype;
	union CIMVAR value;/* [switch_is(cimtype)] */
}/* [public,nopush,nopull] */;

struct WbemQualifiers {
	uint32_t count;
	struct WbemQualifier **item;/* [ref] */
}/* [nopull,nopush,public] */;

struct WbemPropertyDesc {
	uint32_t cimtype;
	uint16_t nr;
	uint32_t offset;
	uint32_t depth;
	struct WbemQualifiers qualifiers;
}/* [public] */;

struct WbemProperty {
	CIMSTRING name;/* [charset(UTF16),string,relative] */
	struct WbemPropertyDesc *desc;/* [relative] */
}/* [public] */;

/* bitmap DEFAULT_FLAGS */
#define DEFAULT_FLAG_EMPTY ( 1 )
#define DEFAULT_FLAG_INHERITED ( 2 )

struct WbemClass {
	uint8_t u_0;
	CIMSTRING __CLASS;/* [null_is_ffffffff,relative,string,charset(UTF16)] */
	uint32_t data_size;
	struct CIMSTRINGS __DERIVATION;
	struct WbemQualifiers qualifiers;
	uint32_t __PROPERTY_COUNT;
	struct WbemProperty *properties;
	uint8_t *default_flags;
	union CIMVAR *default_values;
}/* [noprint,nopull,nopush,flag(LIBNDR_FLAG_NOALIGN),public] */;

struct WbemMethod {
	CIMSTRING name;/* [null_is_ffffffff,relative,string,charset(UTF16)] */
	uint32_t u0;
	uint32_t u1;
	struct WbemQualifiers *qualifiers;/* [relative] */
	struct WbemClassObject *in;/* [relative,subcontext(4)] */
	struct WbemClassObject *out;/* [subcontext(4),relative] */
}/* [public] */;

struct WbemMethods {
	uint16_t count;
	uint16_t u0;
	struct WbemMethod *method;
}/* [flag(LIBNDR_FLAG_NOALIGN),public] */;

struct WbemInstance {
	uint8_t u1_0;
	CIMSTRING __CLASS;/* [relative,string,charset(UTF16)] */
	uint8_t *default_flags;/* [unique] */
	union CIMVAR *data;/* [unique] */
	uint32_t u2_4;
	uint8_t u3_1;
}/* [public,flag(LIBNDR_FLAG_NOALIGN),nopush,nopull,noprint] */;

struct WbemClassObject {
	uint8_t flags;
	CIMSTRING __SERVER;/* [charset(UTF16),string,ref] */
	CIMSTRING __NAMESPACE;/* [charset(UTF16),string,ref] */
	struct WbemClass *sup_class;/* [unique] */
	struct WbemMethods *sup_methods;/* [unique] */
	struct WbemClass *obj_class;/* [unique] */
	struct WbemMethods *obj_methods;/* [unique] */
	struct WbemInstance *instance;/* [unique] */
}/* [nopush,flag(LIBNDR_FLAG_NOALIGN),public,noprint,nopull] */;

/* The following definitions come from lib/wmi/wmicore.c  */


/** FIXME: Use credentials struct rather than user/password here */
WERROR WBEM_ConnectServer(struct com_context *ctx, const char *server, char *nspace,
			  struct cli_credentials *credentials,
			  uint16_t *locale, uint32_t flags, const char *authority,
			  struct IWbemContext* wbem_ctx, struct IWbemServices** services);
const char *wmi_errstr(WERROR werror);

/* The following definitions come from lib/wmi/wbemdata.c  */

WERROR IWbemClassObject_GetMethod(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, struct IWbemClassObject **in, struct IWbemClassObject **out);
void WbemClassObject_CreateInstance(struct IWbemClassObject *wco);
WERROR IWbemClassObject_Clone(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, struct IWbemClassObject **copy);
WERROR IWbemClassObject_SpawnInstance(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, uint32_t flags, struct IWbemClassObject **instance);
WERROR IWbemClassObject_Get(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION *cimtype, uint32_t *flavor);
WERROR IWbemClassObject_Put(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION cimtype);
WERROR IEnumWbemClassObject_SmartNext(struct IEnumWbemClassObject *d, TALLOC_CTX *mem_ctx, int32_t lTimeout, uint32_t uCount, struct IWbemClassObject **apObjects, uint32_t *puReturned);
struct composite_context *dcom_proxy_IEnumWbemClassObject_Release_send(struct IUnknown *d, TALLOC_CTX *mem_ctx);

void wmi_init(struct com_context **ctx, struct cli_credentials *credentials,
			  struct loadparm_context *lp_ctx);
const char *wmi_errstr(WERROR werror);
#endif
