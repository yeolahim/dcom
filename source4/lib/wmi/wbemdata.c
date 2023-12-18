/*
   WMI Implementation
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
#include <talloc.h>
#include "librpc/gen_ndr/dcom.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "librpc/ndr/libndr.h"
//#include "librpc/ndr/libndr_proto.h"
#include "lib/com/com.h"
#include "lib/com/dcom/dcom.h"
#include "lib/util/dlinklist.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "libcli/composite/composite.h"
#include "lib/wmi/wmi.h"
#include "librpc/gen_ndr/ndr_wmi.h"
#include "librpc/ndr/libndr.h"

struct ndr_pull_save {
	uint32_t data_size;
	uint32_t offset;
	struct ndr_pull_save *next;
};

/* save the offset/size of the current ndr state */
void ndr_pull_save(struct ndr_pull *ndr, struct ndr_pull_save *save);
/* restore the size/offset of a ndr structure */
void ndr_pull_restore(struct ndr_pull *ndr, struct ndr_pull_save *save);

void copy_bits(const uint8_t *src, uint32_t bsrc, uint8_t *dst, uint32_t bdst, uint32_t count);
enum ndr_err_code ndr_push_relative_ptr2(struct ndr_push *ndr, const void *p);

enum ndr_err_code ndr_push_arr_int8(struct ndr_push *ndr, int ndr_flags, const struct arr_int8 *r);
enum ndr_err_code ndr_pull_arr_int8(struct ndr_pull *ndr, int ndr_flags, struct arr_int8 *r);
void ndr_print_arr_int8(struct ndr_print *ndr, const char *name, const struct arr_int8 *r);

enum ndr_err_code ndr_push_arr_uint8(struct ndr_push *ndr, int ndr_flags, const struct arr_uint8 *r);
enum ndr_err_code ndr_pull_arr_uint8(struct ndr_pull *ndr, int ndr_flags, struct arr_uint8 *r);
void ndr_print_arr_uint8(struct ndr_print *ndr, const char *name, const struct arr_uint8 *r);

enum ndr_err_code ndr_push_arr_int16(struct ndr_push *ndr, int ndr_flags, const struct arr_int16 *r);
enum ndr_err_code ndr_pull_arr_int16(struct ndr_pull *ndr, int ndr_flags, struct arr_int16 *r);
void ndr_print_arr_int16(struct ndr_print *ndr, const char *name, const struct arr_int16 *r);

enum ndr_err_code ndr_push_arr_uint16(struct ndr_push *ndr, int ndr_flags, const struct arr_uint16 *r);
enum ndr_err_code ndr_pull_arr_uint16(struct ndr_pull *ndr, int ndr_flags, struct arr_uint16 *r);
void ndr_print_arr_uint16(struct ndr_print *ndr, const char *name, const struct arr_uint16 *r);

enum ndr_err_code ndr_push_arr_int32(struct ndr_push *ndr, int ndr_flags, const struct arr_int32 *r);
enum ndr_err_code ndr_pull_arr_int32(struct ndr_pull *ndr, int ndr_flags, struct arr_int32 *r);
void ndr_print_arr_int32(struct ndr_print *ndr, const char *name, const struct arr_int32 *r);

enum ndr_err_code ndr_push_arr_uint32(struct ndr_push *ndr, int ndr_flags, const struct arr_uint32 *r);
enum ndr_err_code ndr_pull_arr_uint32(struct ndr_pull *ndr, int ndr_flags, struct arr_uint32 *r);
void ndr_print_arr_uint32(struct ndr_print *ndr, const char *name, const struct arr_uint32 *r);

enum ndr_err_code ndr_push_arr_dlong(struct ndr_push *ndr, int ndr_flags, const struct arr_dlong *r);
enum ndr_err_code ndr_pull_arr_dlong(struct ndr_pull *ndr, int ndr_flags, struct arr_dlong *r);
void ndr_print_arr_dlong(struct ndr_print *ndr, const char *name, const struct arr_dlong *r);

enum ndr_err_code ndr_push_arr_udlong(struct ndr_push *ndr, int ndr_flags, const struct arr_udlong *r);
enum ndr_err_code ndr_pull_arr_udlong(struct ndr_pull *ndr, int ndr_flags, struct arr_udlong *r);
void ndr_print_arr_udlong(struct ndr_print *ndr, const char *name, const struct arr_udlong *r);

enum ndr_err_code ndr_push_WbemPropertyDesc(struct ndr_push *ndr, int ndr_flags, const struct WbemPropertyDesc *r);
enum ndr_err_code ndr_pull_WbemPropertyDesc(struct ndr_pull *ndr, int ndr_flags, struct WbemPropertyDesc *r);
void ndr_print_WbemPropertyDesc(struct ndr_print *ndr, const char *name, const struct WbemPropertyDesc *r);

enum ndr_err_code ndr_push_WbemProperty(struct ndr_push *ndr, int ndr_flags, const struct WbemProperty *r);
enum ndr_err_code ndr_pull_WbemProperty(struct ndr_pull *ndr, int ndr_flags, struct WbemProperty *r);
void ndr_print_WbemProperty(struct ndr_print *ndr, const char *name, const struct WbemProperty *r);

enum ndr_err_code ndr_push_arr_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const struct arr_CIMSTRING *r);
enum ndr_err_code ndr_pull_arr_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, struct arr_CIMSTRING *r);
void ndr_print_arr_CIMSTRING(struct ndr_print *ndr, const char *name, const struct arr_CIMSTRING *r);

enum ndr_err_code ndr_push_arr_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct arr_WbemClassObject *r);
enum ndr_err_code ndr_pull_arr_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct arr_WbemClassObject *r);
void ndr_print_arr_WbemClassObject(struct ndr_print *ndr, const char *name, const struct arr_WbemClassObject *r);

enum ndr_err_code ndr_pull_CIMVAR(struct ndr_pull *ndr, int ndr_flags, union CIMVAR *r);
enum ndr_err_code ndr_push_CIMVAR(struct ndr_push *ndr, int ndr_flags, const union CIMVAR *r);
void ndr_print_CIMVAR(struct ndr_print *ndr, const char *name, const union CIMVAR *r);

enum ndr_err_code ndr_pull_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, CIMSTRING *r);
enum ndr_err_code ndr_push_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const CIMSTRING *r);
void ndr_print_CIMSTRING(struct ndr_print *ndr, const char *name, const CIMSTRING *r);

enum ndr_err_code ndr_pull_CIMSTRINGS(struct ndr_pull *ndr, int ndr_flags, struct CIMSTRINGS *r);
enum ndr_err_code ndr_push_CIMSTRINGS(struct ndr_push *ndr, int ndr_flags, const struct CIMSTRINGS *r);
void ndr_print_CIMSTRINGS(struct ndr_print *ndr, const char *name, const struct CIMSTRINGS *r);

enum ndr_err_code ndr_push_WbemQualifier(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifier *r);
enum ndr_err_code ndr_pull_WbemQualifier(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifier *r);
void ndr_print_WbemQualifier(struct ndr_print *ndr, const char *name, const struct WbemQualifier *r);

enum ndr_err_code ndr_pull_WbemQualifiers(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifiers *r);
enum ndr_err_code ndr_push_WbemQualifiers(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifiers *r);
void ndr_print_WbemQualifiers(struct ndr_print *ndr, const char *name, const struct WbemQualifiers *r);

enum ndr_err_code ndr_pull_DataWithStack(struct ndr_pull *ndr, ndr_pull_flags_fn_t fn, void *r);
enum ndr_err_code ndr_push_DataWithStack(struct ndr_push *ndr, ndr_push_flags_fn_t fn, const void *r);

enum ndr_err_code ndr_pull_WbemClass(struct ndr_pull *ndr, struct WbemClass *r);
enum ndr_err_code ndr_push_WbemClass(struct ndr_push *ndr, int ndr_flags, const struct WbemClass *r);
void ndr_print_WbemClass(struct ndr_print *ndr, const char *name, const struct WbemClass *r);

enum ndr_err_code ndr_push_WbemMethod(struct ndr_push *ndr, int ndr_flags, const struct WbemMethod *r);
enum ndr_err_code ndr_pull_WbemMethod(struct ndr_pull *ndr, int ndr_flags, struct WbemMethod *r);
void ndr_print_WbemMethod(struct ndr_print *ndr, const char *name, const struct WbemMethod *r);

enum ndr_err_code ndr_push_WbemMethods(struct ndr_push *ndr, int ndr_flags, const struct WbemMethods *r);
enum ndr_err_code ndr_pull_WbemMethods(struct ndr_pull *ndr, struct WbemMethods *r);
void ndr_print_WbemMethods(struct ndr_print *ndr, const char *name, const struct WbemMethods *r);

enum ndr_err_code ndr_push_WbemInstance_priv(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r);
enum ndr_err_code ndr_pull_WbemInstance_priv(struct ndr_pull *ndr, int ndr_flags, const struct WbemClassObject *r);
void ndr_print_WbemInstance_priv(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r);

enum ndr_err_code ndr_pull_WbemClassObject_Object(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r);

enum ndr_err_code ndr_pull_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r);
enum ndr_err_code ndr_push_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r);
void ndr_print_WbemClassObject(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r);

void duplicate_CIMVAR(TALLOC_CTX *mem_ctx, const union CIMVAR *src, union CIMVAR *dst, enum CIMTYPE_ENUMERATION cimtype);

enum {
	DATATYPE_CLASSOBJECT = 2,
	DATATYPE_OBJECT = 3,
	COFLAG_IS_CLASS = 4,
};

void dump_hex(const char* name, uint32_t size, const uint8_t* data);
void dump_hex(const char* name, uint32_t size, const uint8_t* data) {
    printf("%s: %d", name, size);
    for (uint32_t i =0; i < size; ++i) {
        if (0 == i % 16)
            printf("\n [%04x0] ", i / 16);
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void swap_off(uint32_t* l, uint32_t* r);
void swap_off(uint32_t* l, uint32_t* r) {
	uint32_t v = *l;
	*l = *r;
	*r = v;
}

void print_NDR_ERROR(enum ndr_err_code status, const char* file, int line);
void print_NDR_ERROR(enum ndr_err_code status, const char* file, int line) {
	printf("error '%d' at %s:%d\n", status, file, line);
}
#ifdef NDR_CHECK
#undef NDR_CHECK
#endif
#define NDR_CHECK(call) do { \
	enum ndr_err_code _status; \
	_status = call; \
	if (unlikely(!NDR_ERR_CODE_IS_SUCCESS(_status))) {	\
		print_NDR_ERROR(_status, __FILE__, __LINE__); \
		return _status; \
	} \
} while (0)

static enum ndr_err_code marshal(TALLOC_CTX *mem_ctx, struct IUnknown *pv, struct OBJREF *o)
{
	struct ndr_push *ndr;
	struct WbemClassObject *wco;
	struct MInterfacePointer *mp;

	mp = (struct MInterfacePointer *)((char *)o - offsetof(struct MInterfacePointer, obj)); /* FIXME:high remove this Mumbo Jumbo */
	wco = (struct WbemClassObject *)pv->object_data;

	ndr = talloc_zero(mem_ctx, struct ndr_push);
	ndr->flags = 0;
	ndr->alloc_size = 1024;
	ndr->data = talloc_array(mp, uint8_t, ndr->alloc_size);

	if (wco) {
		uint32_t ofs;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0x12345678));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		NDR_CHECK(ndr_push_WbemClassObject(ndr, NDR_SCALARS | NDR_BUFFERS, wco));
		ofs = ndr->offset;
		ndr->offset = 4;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs - 8));
		ndr->offset = ofs;
	} else {
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
	}
	o->u_objref.u_custom.pData = talloc_realloc(mp, ndr->data, uint8_t, ndr->offset);
	o->u_objref.u_custom.size = ndr->offset;

	mp->size = sizeof(struct OBJREF) - sizeof(union OBJREF_Types) + sizeof(struct u_custom) + o->u_objref.u_custom.size - 8;
	if (DEBUGLVL(9)) {
		NDR_PRINT_DEBUG(WbemClassObject, wco);
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code unmarshal(TALLOC_CTX *mem_ctx, struct OBJREF *o, struct IUnknown **pv)
{
	struct ndr_pull *ndr;
	struct WbemClassObject *wco;
	enum ndr_err_code ndr_err;
    //struct OBJREF oref;
	uint32_t u;
	(void)ndr_err;
	mem_ctx = talloc_new(0);
	ndr = talloc_zero(mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = mem_ctx;
	ndr->data = o->u_objref.u_custom.pData;
	ndr->data_size = o->u_objref.u_custom.size;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	if (u != 0x12345678) { // Signature
		talloc_free(*pv);
		*pv = NULL;
		return NDR_ERR_SUCCESS;
	}
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	if (u + 8 > ndr->data_size) {
		DEBUG(1, ("unmarshall_IWbemClassObject: Incorrect data_size"));
		return NDR_ERR_BUFSIZE;
	}
	wco = talloc_zero(*pv, struct WbemClassObject);
	ndr->current_mem_ctx = wco;
	ndr_err = ndr_pull_WbemClassObject(ndr, NDR_SCALARS | NDR_BUFFERS, wco);

	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err) && (DEBUGLVL(9))) {
		NDR_PRINT_DEBUG(WbemClassObject, wco);
	}

	if (NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		(*pv)->object_data = wco;
	} else {
		talloc_free(wco);
	}
	return ndr_err;
}

static struct GUID IWbemClassObject_IID = {
    0xdc12a681, 0x737f, 0x11cf, {0x88, 0x4d}, {0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}
};

WERROR dcom_IWbemClassObject_from_WbemClassObject(struct com_context *ctx, struct IWbemClassObject **_p, struct WbemClassObject *wco);
WERROR dcom_IWbemClassObject_from_WbemClassObject(struct com_context *ctx, struct IWbemClassObject **_p, struct WbemClassObject *wco)
{
	struct IWbemClassObject *p;

	p = talloc_zero(ctx, struct IWbemClassObject);
	p->ctx = ctx;
	p->obj.signature = 0x574f454d;
	p->obj.flags = OBJREF_CUSTOM;
    p->vtable = (struct IWbemClassObject_vtable *)dcom_proxy_vtable_by_iid(&IWbemClassObject_IID);

	GUID_from_string("dc12a681-737f-11cf-884d-00aa004b2e24", &p->obj.iid);
	GUID_from_string("4590f812-1d3a-11d0-891f-00aa004b2e24", &p->obj.u_objref.u_custom.clsid);
	p->object_data = (void *)wco;
	talloc_steal(p, p->object_data);
	*_p = p;
	return WERR_OK;
}

WERROR IWbemClassObject_GetMethod(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, struct IWbemClassObject **in, struct IWbemClassObject **out)
{
	uint32_t i;
	struct WbemClassObject *wco;
	wco = (struct WbemClassObject *)d->object_data;
	for (i = 0; i < wco->obj_methods->count; ++i)
	    if (!strcmp(wco->obj_methods->method[i].name, name)) {
	        if (in) dcom_IWbemClassObject_from_WbemClassObject(d->ctx, in, wco->obj_methods->method[i].in);
	            if (out) dcom_IWbemClassObject_from_WbemClassObject(d->ctx, out, wco->obj_methods->method[i].out);
	                return WERR_OK;
	    }
	return WERR_NOT_FOUND;
}

void IWbemClassObject_CreateInstance(struct WbemClassObject *wco);
void IWbemClassObject_CreateInstance(struct WbemClassObject *wco)
{
	uint32_t i;

	wco->instance = talloc_zero(wco, struct WbemInstance);
	wco->instance->default_flags = talloc_array(wco->instance, uint8_t, wco->obj_class->__PROPERTY_COUNT);
	wco->instance->data = talloc_array(wco->instance, union CIMVAR, wco->obj_class->__PROPERTY_COUNT);
	memset(wco->instance->data, 0, sizeof(union CIMVAR) * wco->obj_class->__PROPERTY_COUNT);
	for (i = 0; i < wco->obj_class->__PROPERTY_COUNT; ++i) {
		wco->instance->default_flags[i] = 1; /* FIXME:high resolve this magic */
	}
	wco->instance->__CLASS = wco->obj_class->__CLASS;
	wco->instance->u2_4 = 4;
	wco->instance->u3_1 = 1;
}

WERROR IWbemClassObject_Clone(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, struct IWbemClassObject **copy)
{
	return WERR_NOT_SUPPORTED;
}

WERROR IWbemClassObject_SpawnInstance(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, uint32_t flags, struct IWbemClassObject **instance)
{
	struct WbemClassObject *wco, *nwco;
	(void)wco;
	wco = (struct WbemClassObject *)d->object_data;
	nwco = talloc_zero(mem_ctx, struct WbemClassObject);
	nwco->flags = WCF_INSTANCE;
	nwco->obj_class = wco->obj_class;
	IWbemClassObject_CreateInstance(nwco);
	dcom_IWbemClassObject_from_WbemClassObject(d->ctx, instance, nwco);
	return WERR_OK;
}

WERROR IWbemClassObject_Get(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION *cimtype, uint32_t *flavor)
{
	struct WbemClassObject *wco;
	uint32_t i;

	wco = (struct WbemClassObject *)d->object_data;
	for (i = 0; i < wco->obj_class->__PROPERTY_COUNT; ++i) {
		if (!strcmp(wco->obj_class->properties[i].name, name)) {
			duplicate_CIMVAR(mem_ctx, &wco->instance->data[i], val, wco->obj_class->properties[i].desc->cimtype);
			if (cimtype != NULL)
				*cimtype = wco->obj_class->properties[i].desc->cimtype;
			if (flavor != NULL)
				*flavor = 0; /* FIXME:avg implement flavor */
			return WERR_OK;
		}
	}
	return WERR_NOT_FOUND;
}

WERROR IWbemClassObject_Put(struct IWbemClassObject *d, TALLOC_CTX *mem_ctx, const char *name, uint32_t flags, union CIMVAR *val, enum CIMTYPE_ENUMERATION cimtype)
{
	struct WbemClassObject *wco;
	uint32_t i;

	wco = (struct WbemClassObject *)d->object_data;
	for (i = 0; i < wco->obj_class->__PROPERTY_COUNT; ++i) {
		if (!strcmp(wco->obj_class->properties[i].name, name)) {
			if (cimtype && cimtype != wco->obj_class->properties[i].desc->cimtype) return WERR_INVALID_PARAMETER;
			wco->instance->default_flags[i] = 0;
			duplicate_CIMVAR(wco->instance, val, &wco->instance->data[i], wco->obj_class->properties[i].desc->cimtype);
			return WERR_OK;
		}
	}
	return WERR_NOT_FOUND;
}

void duplicate_CIMVAR(TALLOC_CTX *mem_ctx, const union CIMVAR *src, union CIMVAR *dst, enum CIMTYPE_ENUMERATION cimtype)
{
	uint32_t i;

	switch (cimtype & CIM_TYPEMASK) {
	case CIM_SINT8:
	case CIM_UINT8:
	case CIM_SINT16:
	case CIM_UINT16:
	case CIM_SINT32:
	case CIM_UINT32:
	case CIM_SINT64:
	case CIM_UINT64:
	case CIM_REAL32:
	case CIM_REAL64:
	case CIM_BOOLEAN:
		*dst = *src;
		break;
	case CIM_STRING:
	case CIM_DATETIME:
	case CIM_REFERENCE:
		dst->v_string = talloc_strdup(mem_ctx, src->v_string);
		break;
	case CIM_OBJECT:
		// dst->v_object = talloc_zero(mem_ctx, struct WbemClassObject);
		// duplicate_WbemClassObject(dst->v_object, src->v_object, dst->v_object);
		break;
	case CIM_ARR_SINT8:
	case CIM_ARR_UINT8:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->count = src->a_uint8->count;
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, src->a_uint8->count);
		break;
	case CIM_ARR_SINT16:
	case CIM_ARR_UINT16:
	case CIM_ARR_BOOLEAN:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->count = src->a_uint8->count;
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 2*src->a_uint8->count);
		break;
	case CIM_ARR_SINT32:
	case CIM_ARR_UINT32:
	case CIM_ARR_REAL32:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->count = src->a_uint8->count;
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 4*src->a_uint8->count);
		break;
	case CIM_ARR_SINT64:
	case CIM_ARR_UINT64:
	case CIM_ARR_REAL64:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->count = src->a_uint8->count;
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, 8*src->a_uint8->count);
		break;
	case CIM_ARR_STRING:
	case CIM_ARR_DATETIME:
	case CIM_ARR_REFERENCE:
		dst->a_uint8 = talloc_memdup(mem_ctx, src->a_uint8, sizeof(struct arr_uint8));
		dst->a_uint8->count = src->a_uint8->count;
		dst->a_uint8->item = talloc_memdup(dst->a_uint8, src->a_uint8->item, sizeof(CIMSTRING)*src->a_uint8->count);
		for (i = 0; i < src->a_uint8->count; ++i)
			dst->a_string->item[i] = talloc_strdup(dst->a_uint8->item, src->a_string->item[i]);
		break;
	default:
		DEBUG(0, ("duplicate_CIMVAR: cimtype 0x%04X not supported\n", cimtype & CIM_TYPEMASK));
		break;
	}
}

#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
			      DEBUG(1, ("ERROR: %s - %s\n", msg, wmi_errstr(result))); \
	return result; \
			  } else { \
			      DEBUG(1, ("OK   : %s\n", msg)); \
			  }

struct pair_guid_ptr {
	struct GUID guid;
	void *ptr;
	struct pair_guid_ptr *next, *prev;
};

void *get_ptr_by_guid(struct pair_guid_ptr *list, struct GUID *uuid);
void *get_ptr_by_guid(struct pair_guid_ptr *list, struct GUID *uuid)
{
	for (; list; list = list->next) {
	    	if (GUID_equal(&list->guid, uuid))
				return list->ptr;
	}
	return NULL;
}

void add_pair_guid_ptr(TALLOC_CTX *mem_ctx, struct pair_guid_ptr **list, struct GUID *uuid, void *ptr);
void add_pair_guid_ptr(TALLOC_CTX *mem_ctx, struct pair_guid_ptr **list, struct GUID *uuid, void *ptr)
{
	struct pair_guid_ptr *e;

	e = talloc(mem_ctx, struct pair_guid_ptr);
	e->guid = *uuid;
	e->ptr = ptr;
	talloc_steal(e, ptr);
	DLIST_ADD(*list, e);
}

struct IEnumWbemClassObject_data {
	struct GUID guid;
	struct IWbemFetchSmartEnum *pFSE;
	struct IWbemWCOSmartEnum *pSE;
	struct pair_guid_ptr *cache;
};
#define NDR_CHECK_EXPR(expr) do { if (!(expr)) {\
					DEBUG(0, ("%s(%d): WBEMDATA_ERR(0x%08X): Error parsing(%s)\n", __FILE__, __LINE__, ndr->offset, #expr)); \
					return NDR_ERR_VALIDATE; \
					} \
				    } while(0)

#define NDR_CHECK_CONST(val, exp) NDR_CHECK_EXPR((val) == (exp))

enum ndr_err_code WBEMDATA_Parse(TALLOC_CTX *mem_ctx, uint8_t *data, uint32_t size, struct IEnumWbemClassObject *d, uint32_t uCount, struct IWbemClassObject **apObjects);
enum ndr_err_code WBEMDATA_Parse(TALLOC_CTX *mem_ctx, uint8_t *data, uint32_t size, struct IEnumWbemClassObject *d, uint32_t uCount, struct IWbemClassObject **apObjects)
{
	struct ndr_pull *ndr;
	uint32_t u, i, ofs_next;
	uint8_t u8, datatype;
	struct GUID guid;
	struct IEnumWbemClassObject_data *ecod;
	(void)ecod;
	if (!uCount) 
		return NDR_ERR_BAD_SWITCH;

	ecod = d->object_data;

	ndr = talloc_zero(mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = d->ctx;
	ndr->data = data;
	ndr->data_size = size;
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x0);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, *(const uint32_t *)"WBEM");
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, *(const uint32_t *)"DATA");
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x1A); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u + 6);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x0);
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u8));
	NDR_CHECK_CONST(u8, 0x01); /* Major Version */
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u8));
	NDR_CHECK_EXPR(u8 <= 1); /* Minor Version 0 - Win2000, 1 - XP/2003 */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0x8); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, 0xC); /* Length of header */
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_PULL_NEED_BYTES(ndr, u + 4);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
	NDR_CHECK_CONST(u, uCount);
	for (i = 0; i < uCount; ++i) {
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_CHECK_CONST(u, 0x9); /* Length of header */
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_PULL_NEED_BYTES(ndr, u + 1);
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &datatype));
		ofs_next = ndr->offset + u;
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_CHECK_CONST(u, 0x18); /* Length of header */
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
		NDR_PULL_NEED_BYTES(ndr, u + 16);
		NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &guid));
		switch (datatype) {
		case DATATYPE_CLASSOBJECT:
			apObjects[i] = talloc_zero(d->ctx, struct IWbemClassObject);
			ndr->current_mem_ctx = apObjects[i];
			//DCOM_TODO: NDR_CHECK(ndr_pull_WbemClassObject(ndr, NDR_SCALARS|NDR_BUFFERS, apObjects[i]));
			ndr->current_mem_ctx = d->ctx;
			//DCOM_TODO: add_pair_guid_ptr(ecod, &ecod->cache, &guid, apObjects[i]->obj_class);
			break;
		case DATATYPE_OBJECT:
			apObjects[i] = talloc_zero(d->ctx, struct IWbemClassObject);
			//DCOM_TODO: apObjects[i]->obj_class = get_ptr_by_guid(ecod->cache, &guid);
			//DCOM_TODO: (void)talloc_reference(apObjects[i], apObjects[i]->obj_class);
			ndr->current_mem_ctx = apObjects[i];
			//DCOM_TODO: NDR_CHECK(ndr_pull_WbemClassObject_Object(ndr, NDR_SCALARS|NDR_BUFFERS, apObjects[i]));
			ndr->current_mem_ctx = d->ctx;
			break;
		default:
			DEBUG(0, ("WBEMDATA_Parse: Data type %d not supported\n", datatype));
			return NDR_ERR_BAD_SWITCH;
		}
		ndr->offset = ofs_next;
    		if (DEBUGLVL(9)) {
			//DCOM_TODO: NDR_PRINT_DEBUG(IWbemClassObject, apObjects[i]);
		}
	}
	return NDR_ERR_SUCCESS;
}

WERROR IEnumWbemClassObject_SmartNext(struct IEnumWbemClassObject *d, TALLOC_CTX *mem_ctx, int32_t lTimeout, uint32_t uCount, struct IWbemClassObject **apObjects, uint32_t *puReturned)
{
	WERROR result;
	NTSTATUS status;
	struct IEnumWbemClassObject_data *ecod;
	TALLOC_CTX *loc_ctx;
	uint32_t size;
	uint8_t *data;

	loc_ctx = talloc_new(0);
	ecod = d->object_data;
	if (!ecod) {
		struct GUID iid;
		WERROR coresult;

		d->object_data = ecod = talloc_zero(d, struct IEnumWbemClassObject_data);
		GUID_from_string(COM_IWBEMFETCHSMARTENUM_UUID, &iid);
		result = dcom_query_interface((struct IUnknown *)d, 5, 1, &iid, (struct IUnknown **)&ecod->pFSE, &coresult);
		WERR_CHECK("dcom_query_interface.");
		result = coresult;
		WERR_CHECK("Retrieve enumerator of result(IWbemFetchSmartEnum).");

		result = IWbemFetchSmartEnum_Fetch(ecod->pFSE, mem_ctx, &ecod->pSE);
		WERR_CHECK("Retrieve enumerator of result(IWbemWCOSmartEnum).");

		ecod->guid = GUID_random();
		//DCOM_TODO: d->vtable->Release_send = dcom_proxy_IEnumWbemClassObject_Release_send;
	}

	result = IWbemWCOSmartEnum_IWbemWCOSmartEnum_Next(ecod->pSE, loc_ctx, &ecod->guid, lTimeout, uCount, puReturned, &size, &data);
	if (!W_ERROR_EQUAL(result, WERR_INVALID_FUNCTION)) {
		WERR_CHECK("IWbemWCOSmartEnum_Next.");
	}

	if (data) {
		//DCOM_TODO: NDR_CHECK(WBEMDATA_Parse(mem_ctx, data, size, d, *puReturned, apObjects));
	}
	if (!W_ERROR_IS_OK(result)) {
		status = werror_to_ntstatus(result);
		DEBUG(9, ("dcom_proxy_IEnumWbemClassObject_Next: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status)));
	}
	talloc_free(loc_ctx);
	return result;
}

struct composite_context *dcom_proxy_IEnumWbemClassObject_Release_send(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
	struct composite_context *c, *cr;
	struct REMINTERFACEREF iref[3];
	struct dcom_object_exporter *ox;
	struct IEnumWbemClassObject_data *ecod;
	int n;
	(void)ox;
	(void)iref;
	c = composite_create(d->ctx, d->ctx->event_ctx);
	if (c == NULL) return NULL;
	c->private_data = d;

	ox = object_exporter_by_ip(d->ctx, d);
	iref[0].ipid = IUnknown_ipid(d);
	iref[0].cPublicRefs = 5;
	iref[0].cPrivateRefs = 0;
	n = 1;

	ecod = d->object_data;
	if (ecod) {
		if (ecod->pFSE) {
			talloc_steal(d, ecod->pFSE);
			iref[n].ipid = IUnknown_ipid(ecod->pFSE);
			iref[n].cPublicRefs = 5;
			iref[n].cPrivateRefs = 0;
			++n;
		}
		if (ecod->pSE) {
			talloc_steal(d, ecod->pSE);
			iref[n].ipid = IUnknown_ipid(ecod->pSE);
			iref[n].cPublicRefs = 5;
			iref[n].cPrivateRefs = 0;
			++n;
		}
	}
	cr = NULL;
	//DCOM_TODO: cr = IRemUnknown_RemRelease_send(ox->rem_unknown, mem_ctx, n, iref);

	composite_continue(c, cr, dcom_release_continue, c);
	return c;
}

NTSTATUS dcom_proxy_IWbemClassObject_init(TALLOC_CTX *ctx);
NTSTATUS dcom_proxy_IWbemClassObject_init(TALLOC_CTX *ctx)
{
	struct GUID clsid;
	GUID_from_string("4590f812-1d3a-11d0-891f-00aa004b2e24", &clsid);
	dcom_register_marshal(ctx, &clsid, marshal, unmarshal);

#if 0
	struct IEnumWbemClassObject_vtable *proxy_vtable;
	proxy_vtable = (struct IEnumWbemClassObject_vtable *)dcom_proxy_vtable_by_iid((struct GUID *)&dcerpc_table_IEnumWbemClassObject.syntax_id.uuid);
	if (proxy_vtable)
		proxy_vtable->Release_send = dcom_proxy_IEnumWbemClassObject_Release_send;
	else
		DEBUG(0, ("WARNING: IEnumWbemClassObject should be initialized before IWbemClassObject."));
#endif

	return NT_STATUS_OK;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

enum ndr_err_code ndr_push_relative_ptr2(struct ndr_push *ndr, const void *p)
{
	uint32_t save_offset;
	uint32_t ptr_offset = 0xFFFFFFFF;
	if (p == NULL) {
		return NDR_ERR_SUCCESS;
	}
	save_offset = ndr->offset;
	NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, p, &ptr_offset));
	if (ptr_offset > ndr->offset) {
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,
				      "ndr_push_relative_ptr2 ptr_offset(%u) > ndr->offset(%u)",
				      ptr_offset, ndr->offset);
	}
	ndr->offset = ptr_offset;
	if (save_offset < ndr->relative_base_offset) {
		return ndr_push_error(ndr, NDR_ERR_BUFSIZE,
				      "ndr_push_relative_ptr2 save_offset(%u) < ndr->relative_base_offset(%u)",
				      save_offset, ndr->relative_base_offset);
	}
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, save_offset - ndr->relative_base_offset));
	ndr->offset = save_offset;
	return NDR_ERR_SUCCESS;
}

void copy_bits(const uint8_t *src, uint32_t bsrc, uint8_t *dst, uint32_t bdst, uint32_t count)
{
	uint8_t mask;

	src += bsrc >> 3;
	bsrc &= 7;
	dst += bdst >> 3;
	bdst &= 7;
	mask = ((1 << count) - 1);
	*dst &= ~(mask << bdst);
	*dst |= ((*src >> bsrc) & mask) << bdst;
}

#define IS_CIMTYPE_PTR(t) (((t) & CIM_FLAG_ARRAY) || ((t) == CIM_STRING) || ((t) == CIM_DATETIME) || ((t) == CIM_REFERENCE))

/* save the offset/size of the current ndr state */
void ndr_pull_save(struct ndr_pull *ndr, struct ndr_pull_save *save)
{
	save->offset = ndr->offset;
	save->data_size = ndr->data_size;
}

/* restore the size/offset of a ndr structure */
void ndr_pull_restore(struct ndr_pull *ndr, struct ndr_pull_save *save)
{
	ndr->offset = save->offset;
	ndr->data_size = save->data_size;
}

enum ndr_err_code ndr_push_arr_int8(struct ndr_push *ndr, int ndr_flags, const struct arr_int8 *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_int8(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_int8(struct ndr_pull *ndr, int ndr_flags, struct arr_int8 *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_int8(struct ndr_print *ndr, const char *name, const struct arr_int8 *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_int8");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_int8(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_uint8(struct ndr_push *ndr, int ndr_flags, const struct arr_uint8 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		NDR_CHECK(ndr_push_array_uint8(ndr, NDR_SCALARS, r->item, r->count));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_uint8(struct ndr_pull *ndr, int ndr_flags, struct arr_uint8 *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->item, r->count));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_uint8(struct ndr_print *ndr, const char *name, const struct arr_uint8 *r)
{
	ndr_print_struct(ndr, name, "arr_uint8");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr_print_array_uint8(ndr, "item", r->item, r->count);
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_int16(struct ndr_push *ndr, int ndr_flags, const struct arr_int16 *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_int16(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_int16(struct ndr_pull *ndr, int ndr_flags, struct arr_int16 *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_int16(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_int16(struct ndr_print *ndr, const char *name, const struct arr_int16 *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_int16");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_int16(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_uint16(struct ndr_push *ndr, int ndr_flags, const struct arr_uint16 *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_uint16(struct ndr_pull *ndr, int ndr_flags, struct arr_uint16 *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_uint16(struct ndr_print *ndr, const char *name, const struct arr_uint16 *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_uint16");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_uint16(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_int32(struct ndr_push *ndr, int ndr_flags, const struct arr_int32 *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_int32(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_int32(struct ndr_pull *ndr, int ndr_flags, struct arr_int32 *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_int32(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_int32(struct ndr_print *ndr, const char *name, const struct arr_int32 *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_int32");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_int32(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_uint32(struct ndr_push *ndr, int ndr_flags, const struct arr_uint32 *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_uint32(struct ndr_pull *ndr, int ndr_flags, struct arr_uint32 *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_uint32(struct ndr_print *ndr, const char *name, const struct arr_uint32 *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_uint32");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_uint32(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_dlong(struct ndr_push *ndr, int ndr_flags, const struct arr_dlong *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_dlong(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_dlong(struct ndr_pull *ndr, int ndr_flags, struct arr_dlong *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_dlong(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_dlong(struct ndr_print *ndr, const char *name, const struct arr_dlong *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_dlong");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_dlong(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_udlong(struct ndr_push *ndr, int ndr_flags, const struct arr_udlong *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_udlong(struct ndr_pull *ndr, int ndr_flags, struct arr_udlong *r)
{
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_udlong(struct ndr_print *ndr, const char *name, const struct arr_udlong *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_udlong");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_udlong(ndr, "item", r->item[cntr_item_0]);
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const struct arr_CIMSTRING *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_relative_ptr1(ndr, r->item[cntr_item_0]));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			if (r->item[cntr_item_0]) {
				NDR_CHECK(ndr_push_relative_ptr2(ndr, r->item[cntr_item_0]));
				NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->item[cntr_item_0]));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_CIMSTRING2(struct ndr_pull *heap, struct arr_CIMSTRING *r);
enum ndr_err_code ndr_pull_arr_CIMSTRING2(struct ndr_pull *heap, struct arr_CIMSTRING *r)
{
	uint32_t _ptr_item;
	TALLOC_CTX *prev_ctx;

	NDR_CHECK(ndr_pull_align(heap, 4));
	NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &r->count));
	NDR_PULL_ALLOC_N(heap, r->item, r->count);

	prev_ctx = heap->current_mem_ctx;
	heap->current_mem_ctx = r->item;

	for (int i = 0; i < r->count; ++i) {
		NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &_ptr_item));
		if (_ptr_item) {
			swap_off(&heap->offset, &_ptr_item);
			NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &(r->item)[i]));
			swap_off(&heap->offset, &_ptr_item);
		} else {
			(r->item)[i] = NULL;
		}
	}
	heap->current_mem_ctx = prev_ctx;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, struct arr_CIMSTRING *r)
{
	uint32_t _ptr_item;
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	//TALLOC_CTX *_mem_save_item_1;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_item));
			if (_ptr_item) {
				NDR_PULL_ALLOC(ndr, (r->item)[cntr_item_0]);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, (r->item)[cntr_item_0], _ptr_item));
			} else {
				(r->item)[cntr_item_0] = NULL;
			}
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			if ((r->item)[cntr_item_0]) {
				struct ndr_pull_save _relative_save;
				ndr_pull_save(ndr, &_relative_save);
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, (r->item)[cntr_item_0]));
				NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &(r->item)[cntr_item_0]));
				ndr_pull_restore(ndr, &_relative_save);
			}
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_CIMSTRING(struct ndr_print *ndr, const char *name, const struct arr_CIMSTRING *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_CIMSTRING");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_ptr(ndr, "item", r->item[cntr_item_0]);
			ndr->depth++;
			if (r->item[cntr_item_0]) {
				ndr_print_CIMSTRING(ndr, "item", &r->item[cntr_item_0]);
			}
			ndr->depth--;
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_arr_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct arr_WbemClassObject *r)
{
	uint32_t cntr_item_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->count));
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			if (r->item[cntr_item_0]) {
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->item[cntr_item_0]));
			} else {
				NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, r->item[cntr_item_0], ndr->offset));
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
			}
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_push_relative_ptr2(ndr, r->item[cntr_item_0]));
			if (r->item[cntr_item_0]) {
				{
					struct ndr_push *_ndr_item;
					NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_item, 4, -1));
					NDR_CHECK(ndr_push_WbemClassObject(_ndr_item, NDR_SCALARS|NDR_BUFFERS, r->item[cntr_item_0]));
					NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_item, 4, -1));
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_arr_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct arr_WbemClassObject *r)
{
	uint32_t _ptr_item;
	uint32_t cntr_item_0;
	TALLOC_CTX *_mem_save_item_0;
	TALLOC_CTX *_mem_save_item_1;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->count));
		NDR_PULL_ALLOC_N(ndr, r->item, r->count);
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_item));
			if (_ptr_item) {
				NDR_PULL_ALLOC(ndr, (r->item)[cntr_item_0]);
				NDR_CHECK(ndr_pull_relative_ptr1(ndr, (r->item)[cntr_item_0], _ptr_item));
			} else {
				(r->item)[cntr_item_0] = NULL;
			}
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	if (ndr_flags & NDR_BUFFERS) {
		_mem_save_item_0 = NDR_PULL_GET_MEM_CTX(ndr);
		NDR_PULL_SET_MEM_CTX(ndr, r->item, 0);
		for (cntr_item_0 = 0; cntr_item_0 < r->count; cntr_item_0++) {
			if ((r->item)[cntr_item_0]) {
				struct ndr_pull_save _relative_save;
				ndr_pull_save(ndr, &_relative_save);
				NDR_CHECK(ndr_pull_relative_ptr2(ndr, (r->item)[cntr_item_0]));
				_mem_save_item_1 = NDR_PULL_GET_MEM_CTX(ndr);
				NDR_PULL_SET_MEM_CTX(ndr, (r->item)[cntr_item_0], 0);
				{
					struct ndr_pull *_ndr_item;
					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_item, 4, -1));
					if (_ndr_item->data_size) {
						NDR_CHECK(ndr_pull_WbemClassObject(_ndr_item, NDR_SCALARS|NDR_BUFFERS, (r->item)[cntr_item_0]));
					} else {
						talloc_free((r->item)[cntr_item_0]);
						(r->item)[cntr_item_0] = NULL;
					}
					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_item, 4, -1));
				}
				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_1, 0);
				ndr_pull_restore(ndr, &_relative_save);
			}
		}
		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_item_0, 0);
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_arr_WbemClassObject(struct ndr_print *ndr, const char *name, const struct arr_WbemClassObject *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "arr_WbemClassObject");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_ptr(ndr, "item", r->item[cntr_item_0]);
			ndr->depth++;
			if (r->item[cntr_item_0]) {
				ndr_print_WbemClassObject(ndr, "item", r->item[cntr_item_0]);
			}
			ndr->depth--;
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_CIMVAR(struct ndr_push *ndr, int ndr_flags, const union CIMVAR *r)
{
	uint32_t level;
	NDR_CHECK(ndr_token_peek(&ndr->switch_list, r, &level));
	if (ndr_flags & NDR_SCALARS) {
		switch (level) {
			case CIM_SINT8:
				NDR_CHECK(ndr_push_int8(ndr, NDR_SCALARS, r->v_sint8));
			break;

			case CIM_UINT8:
				NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->v_uint8));
			break;

			case CIM_SINT16:
				NDR_CHECK(ndr_push_int16(ndr, NDR_SCALARS, r->v_sint16));
			break;

			case CIM_UINT16:
				NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->v_uint16));
			break;

			case CIM_SINT32:
				NDR_CHECK(ndr_push_int32(ndr, NDR_SCALARS, r->v_sint32));
			break;

			case CIM_UINT32:
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->v_uint32));
			break;

			case CIM_SINT64:
				NDR_CHECK(ndr_push_dlong(ndr, NDR_SCALARS, r->v_sint64));
			break;

			case CIM_UINT64:
				NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->v_uint64));
			break;

			case CIM_REAL32:
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->v_real32));
			break;

			case CIM_REAL64:
				NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->v_real64));
			break;

			case CIM_BOOLEAN:
				NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->v_boolean));
			break;

			case CIM_STRING:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->v_string));
			break;

			case CIM_DATETIME:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->v_datetime));
			break;

			case CIM_REFERENCE:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->v_reference));
			break;

			case CIM_OBJECT:
				if (r->v_object) {
					NDR_CHECK(ndr_push_relative_ptr1(ndr, r->v_object));
				} else {
					NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, r->v_object, ndr->offset));
					NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
				}
			break;

			case CIM_ARR_SINT8:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_sint8));
			break;

			case CIM_ARR_UINT8:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_uint8));
			break;

			case CIM_ARR_SINT16:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_sint16));
			break;

			case CIM_ARR_UINT16:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_uint16));
			break;

			case CIM_ARR_SINT32:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_sint32));
			break;

			case CIM_ARR_UINT32:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_uint32));
			break;

			case CIM_ARR_SINT64:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_sint64));
			break;

			case CIM_ARR_UINT64:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_uint64));
			break;

			case CIM_ARR_REAL32:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_real32));
			break;

			case CIM_ARR_REAL64:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_real64));
			break;

			case CIM_ARR_BOOLEAN:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_boolean));
			break;

			case CIM_ARR_STRING:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_string));
			break;

			case CIM_ARR_DATETIME:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_datetime));
			break;

			case CIM_ARR_REFERENCE:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_reference));
			break;

			case CIM_ARR_OBJECT:
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->a_object));
			break;

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", level);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case CIM_SINT8:
			break;

			case CIM_UINT8:
			break;

			case CIM_SINT16:
			break;

			case CIM_UINT16:
			break;

			case CIM_SINT32:
			break;

			case CIM_UINT32:
			break;

			case CIM_SINT64:
			break;

			case CIM_UINT64:
			break;

			case CIM_REAL32:
			break;

			case CIM_REAL64:
			break;

			case CIM_BOOLEAN:
			break;

			case CIM_STRING:
				if (r->v_string) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->v_string));
					NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->v_string));
				}
			break;

			case CIM_DATETIME:
				if (r->v_datetime) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->v_datetime));
					NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->v_datetime));
				}
			break;

			case CIM_REFERENCE:
				if (r->v_reference) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->v_reference));
					NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->v_reference));
				}
			break;

			case CIM_OBJECT:
				NDR_CHECK(ndr_push_relative_ptr2(ndr, r->v_object));
				if (r->v_object) {
					{
						struct ndr_push *_ndr_v_object;
						NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_v_object, 4, -1));
						NDR_CHECK(ndr_push_WbemClassObject(_ndr_v_object, NDR_SCALARS|NDR_BUFFERS, r->v_object));
						NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_v_object, 4, -1));
					}
				}
			break;

			case CIM_ARR_SINT8:
				if (r->a_sint8) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_sint8));
					NDR_CHECK(ndr_push_arr_int8(ndr, NDR_SCALARS, r->a_sint8));
				}
			break;

			case CIM_ARR_UINT8:
				if (r->a_uint8) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_uint8));
					NDR_CHECK(ndr_push_arr_uint8(ndr, NDR_SCALARS, r->a_uint8));
				}
			break;

			case CIM_ARR_SINT16:
				if (r->a_sint16) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_sint16));
					NDR_CHECK(ndr_push_arr_int16(ndr, NDR_SCALARS, r->a_sint16));
				}
			break;

			case CIM_ARR_UINT16:
				if (r->a_uint16) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_uint16));
					NDR_CHECK(ndr_push_arr_uint16(ndr, NDR_SCALARS, r->a_uint16));
				}
			break;

			case CIM_ARR_SINT32:
				if (r->a_sint32) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_sint32));
					NDR_CHECK(ndr_push_arr_int32(ndr, NDR_SCALARS, r->a_sint32));
				}
			break;

			case CIM_ARR_UINT32:
				if (r->a_uint32) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_uint32));
					NDR_CHECK(ndr_push_arr_uint32(ndr, NDR_SCALARS, r->a_uint32));
				}
			break;

			case CIM_ARR_SINT64:
				if (r->a_sint64) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_sint64));
					NDR_CHECK(ndr_push_arr_dlong(ndr, NDR_SCALARS, r->a_sint64));
				}
			break;

			case CIM_ARR_UINT64:
				if (r->a_uint64) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_uint64));
					NDR_CHECK(ndr_push_arr_udlong(ndr, NDR_SCALARS, r->a_uint64));
				}
			break;

			case CIM_ARR_REAL32:
				if (r->a_real32) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_real32));
					NDR_CHECK(ndr_push_arr_uint32(ndr, NDR_SCALARS, r->a_real32));
				}
			break;

			case CIM_ARR_REAL64:
				if (r->a_real64) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_real64));
					NDR_CHECK(ndr_push_arr_udlong(ndr, NDR_SCALARS, r->a_real64));
				}
			break;

			case CIM_ARR_BOOLEAN:
				if (r->a_boolean) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_boolean));
					NDR_CHECK(ndr_push_arr_uint16(ndr, NDR_SCALARS, r->a_boolean));
				}
			break;

			case CIM_ARR_STRING:
				if (r->a_string) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_string));
					NDR_CHECK(ndr_push_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_string));
				}
			break;

			case CIM_ARR_DATETIME:
				if (r->a_datetime) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_datetime));
					NDR_CHECK(ndr_push_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_datetime));
				}
			break;

			case CIM_ARR_REFERENCE:
				if (r->a_reference) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_reference));
					NDR_CHECK(ndr_push_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_reference));
				}
			break;

			case CIM_ARR_OBJECT:
				if (r->a_object) {
					NDR_CHECK(ndr_push_relative_ptr2(ndr, r->a_object));
					NDR_CHECK(ndr_push_arr_WbemClassObject(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_object));
				}
			break;

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", level);
		}
	}
	return NDR_ERR_SUCCESS;
}
enum ndr_err_code ndr_pull_CIMVAR2(struct ndr_pull *ndr, struct ndr_pull *heap, enum CIMTYPE_ENUMERATION cimtype, union CIMVAR *r);
enum ndr_err_code ndr_pull_CIMVAR2(struct ndr_pull *ndr, struct ndr_pull *heap, enum CIMTYPE_ENUMERATION cimtype, union CIMVAR *r)
{
	// uint32_t level;
	// //TALLOC_CTX *_mem_save_v_string_0;
	// //TALLOC_CTX *_mem_save_v_datetime_0;
	// //TALLOC_CTX *_mem_save_v_reference_0;
	// TALLOC_CTX *_mem_save_v_object_0;
	// TALLOC_CTX *_mem_save_a_sint8_0;
	// TALLOC_CTX *_mem_save_a_uint8_0;
	// TALLOC_CTX *_mem_save_a_sint16_0;
	// TALLOC_CTX *_mem_save_a_uint16_0;
	// TALLOC_CTX *_mem_save_a_sint32_0;
	// TALLOC_CTX *_mem_save_a_uint32_0;
	// TALLOC_CTX *_mem_save_a_sint64_0;
	// TALLOC_CTX *_mem_save_a_uint64_0;
	// TALLOC_CTX *_mem_save_a_real32_0;
	// TALLOC_CTX *_mem_save_a_real64_0;
	// TALLOC_CTX *_mem_save_a_boolean_0;
	// TALLOC_CTX *_mem_save_a_string_0;
	// TALLOC_CTX *_mem_save_a_datetime_0;
	// TALLOC_CTX *_mem_save_a_reference_0;
	// TALLOC_CTX *_mem_save_a_object_0;
  // NDR_CHECK(ndr_token_peek(&ndr->switch_list, r, &level));
	// if (ndr_flags & NDR_SCALARS) {
	switch (cimtype) {
		case CIM_SINT8: {
			NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->v_sint8));
		break; }

		case CIM_UINT8: {
			NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->v_uint8));
		break; }

		case CIM_SINT16: {
			NDR_CHECK(ndr_pull_int16(ndr, NDR_SCALARS, &r->v_sint16));
		break; }

		case CIM_UINT16: {
			NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->v_uint16));
		break; }

		case CIM_SINT32: {
			NDR_CHECK(ndr_pull_int32(ndr, NDR_SCALARS, &r->v_sint32));
		break; }

		case CIM_UINT32: {
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->v_uint32));
		break; }

		case CIM_SINT64: {
			NDR_CHECK(ndr_pull_dlong(ndr, NDR_SCALARS, &r->v_sint64));
		break; }

		case CIM_UINT64: {
			NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->v_uint64));
		break; }

		case CIM_REAL32: {
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->v_real32));
		break; }

		case CIM_REAL64: {
			NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->v_real64));
		break; }

		case CIM_BOOLEAN: {
			NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->v_boolean));
		break; }

		case CIM_STRING: {
			uint32_t _ptr_v_string;
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_v_string));
			if (_ptr_v_string) {
				swap_off(&heap->offset, &_ptr_v_string);
				NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->v_string));
				swap_off(&heap->offset, &_ptr_v_string);
			} else {
				r->v_string = NULL;
			}
		break; }

		case CIM_DATETIME: {
			uint32_t _ptr_v_datetime;
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_v_datetime));
			if (_ptr_v_datetime) {
				swap_off(&heap->offset, &_ptr_v_datetime);
				NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->v_datetime));
				swap_off(&heap->offset, &_ptr_v_datetime);
			} else {
				r->v_datetime = NULL;
			}
		break; }

		case CIM_REFERENCE: {
			uint32_t _ptr_v_reference;
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_v_reference));
			if (_ptr_v_reference) {
				swap_off(&heap->offset, &_ptr_v_reference);
				NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->v_reference));
				swap_off(&heap->offset, &_ptr_v_reference);
			} else {
				r->v_reference = NULL;
			}
		break; }

		// case CIM_OBJECT: {
		// 	uint32_t _ptr_v_object;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_v_object));
		// 	if (_ptr_v_object) {
		// 		NDR_PULL_ALLOC(ndr, r->v_object);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->v_object, _ptr_v_object));
		// 	} else {
		// 		r->v_object = NULL;
		// 	}
		// break; }

		// case CIM_ARR_SINT8: {
		// 	uint32_t _ptr_a_sint8;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint8));
		// 	if (_ptr_a_sint8) {
		// 		NDR_PULL_ALLOC(ndr, r->a_sint8);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint8, _ptr_a_sint8));
		// 	} else {
		// 		r->a_sint8 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_UINT8: {
		// 	uint32_t _ptr_a_uint8;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint8));
		// 	if (_ptr_a_uint8) {
		// 		NDR_PULL_ALLOC(ndr, r->a_uint8);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint8, _ptr_a_uint8));
		// 	} else {
		// 		r->a_uint8 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_SINT16: {
		// 	uint32_t _ptr_a_sint16;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint16));
		// 	if (_ptr_a_sint16) {
		// 		NDR_PULL_ALLOC(ndr, r->a_sint16);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint16, _ptr_a_sint16));
		// 	} else {
		// 		r->a_sint16 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_UINT16: {
		// 	uint32_t _ptr_a_uint16;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint16));
		// 	if (_ptr_a_uint16) {
		// 		NDR_PULL_ALLOC(ndr, r->a_uint16);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint16, _ptr_a_uint16));
		// 	} else {
		// 		r->a_uint16 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_SINT32: {
		// 	uint32_t _ptr_a_sint32;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint32));
		// 	if (_ptr_a_sint32) {
		// 		NDR_PULL_ALLOC(ndr, r->a_sint32);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint32, _ptr_a_sint32));
		// 	} else {
		// 		r->a_sint32 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_UINT32: {
		// 	uint32_t _ptr_a_uint32;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint32));
		// 	if (_ptr_a_uint32) {
		// 		NDR_PULL_ALLOC(ndr, r->a_uint32);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint32, _ptr_a_uint32));
		// 	} else {
		// 		r->a_uint32 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_SINT64: {
		// 	uint32_t _ptr_a_sint64;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint64));
		// 	if (_ptr_a_sint64) {
		// 		NDR_PULL_ALLOC(ndr, r->a_sint64);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint64, _ptr_a_sint64));
		// 	} else {
		// 		r->a_sint64 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_UINT64: {
		// 	uint32_t _ptr_a_uint64;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint64));
		// 	if (_ptr_a_uint64) {
		// 		NDR_PULL_ALLOC(ndr, r->a_uint64);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint64, _ptr_a_uint64));
		// 	} else {
		// 		r->a_uint64 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_REAL32: {
		// 	uint32_t _ptr_a_real32;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_real32));
		// 	if (_ptr_a_real32) {
		// 		NDR_PULL_ALLOC(ndr, r->a_real32);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_real32, _ptr_a_real32));
		// 	} else {
		// 		r->a_real32 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_REAL64: {
		// 	uint32_t _ptr_a_real64;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_real64));
		// 	if (_ptr_a_real64) {
		// 		NDR_PULL_ALLOC(ndr, r->a_real64);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_real64, _ptr_a_real64));
		// 	} else {
		// 		r->a_real64 = NULL;
		// 	}
		// break; }

		// case CIM_ARR_BOOLEAN: {
		// 	uint32_t _ptr_a_boolean;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_boolean));
		// 	if (_ptr_a_boolean) {
		// 		NDR_PULL_ALLOC(ndr, r->a_boolean);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_boolean, _ptr_a_boolean));
		// 	} else {
		// 		r->a_boolean = NULL;
		// 	}
		// break; }

		case CIM_ARR_STRING: {
			uint32_t _ptr_a_string;
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_a_string));
			if (_ptr_a_string) {
				NDR_PULL_ALLOC(ndr, r->a_string);
				swap_off(&heap->offset, &_ptr_a_string);
				NDR_CHECK(ndr_pull_arr_CIMSTRING2(heap, r->a_string));
				swap_off(&heap->offset, &_ptr_a_string);
			} else {
				r->a_string = NULL;
			}
		break; }

		// case CIM_ARR_DATETIME: {
		// 	uint32_t _ptr_a_datetime;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_datetime));
		// 	if (_ptr_a_datetime) {
		// 		NDR_PULL_ALLOC(ndr, r->a_datetime);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_datetime, _ptr_a_datetime));
		// 	} else {
		// 		r->a_datetime = NULL;
		// 	}
		// break; }

		// case CIM_ARR_REFERENCE: {
		// 	uint32_t _ptr_a_reference;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_reference));
		// 	if (_ptr_a_reference) {
		// 		NDR_PULL_ALLOC(ndr, r->a_reference);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_reference, _ptr_a_reference));
		// 	} else {
		// 		r->a_reference = NULL;
		// 	}
		// break; }

		// case CIM_ARR_OBJECT: {
		// 	uint32_t _ptr_a_object;
		// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_object));
		// 	if (_ptr_a_object) {
		// 		NDR_PULL_ALLOC(ndr, r->a_object);
		// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_object, _ptr_a_object));
		// 	} else {
		// 		r->a_object = NULL;
		// 	}
		// break; }

		default:
			printf("Bad switch value %u\n", cimtype);
			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", cimtype);
	}
	// }
	// if (ndr_flags & NDR_BUFFERS) {
	// 	switch (level) {
	// 		case CIM_SINT8: {
	// 		break; }

	// 		case CIM_UINT8: {
	// 		break; }

	// 		case CIM_SINT16: {
	// 		break; }

	// 		case CIM_UINT16: {
	// 		break; }

	// 		case CIM_SINT32: {
	// 		break; }

	// 		case CIM_UINT32: {
	// 		break; }

	// 		case CIM_SINT64: {
	// 		break; }

	// 		case CIM_UINT64: {
	// 		break; }

	// 		case CIM_REAL32: {
	// 		break; }

	// 		case CIM_REAL64: {
	// 		break; }

	// 		case CIM_BOOLEAN: {
	// 		break; }

	// 		case CIM_STRING: {
	// 			if (r->v_string) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_string));
	// 				NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_string));
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_DATETIME: {
	// 			if (r->v_datetime) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_datetime));
	// 				NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_datetime));
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_REFERENCE: {
	// 			if (r->v_reference) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_reference));
	// 				NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_reference));
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_OBJECT: {
	// 			if (r->v_object) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_object));
	// 				_mem_save_v_object_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->v_object, 0);
	// 				{
	// 					struct ndr_pull *_ndr_v_object;
	// 					NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_v_object, 4, -1));
	// 					if (_ndr_v_object->data_size) {
	// 						NDR_CHECK(ndr_pull_WbemClassObject(_ndr_v_object, NDR_SCALARS|NDR_BUFFERS, r->v_object));
	// 					} else {
	// 						talloc_free(r->v_object);
	// 						r->v_object = NULL;
	// 					}
	// 					NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_v_object, 4, -1));
	// 				}
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_v_object_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_SINT8: {
	// 			if (r->a_sint8) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint8));
	// 				_mem_save_a_sint8_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_sint8, 0);
	// 				NDR_CHECK(ndr_pull_arr_int8(ndr, NDR_SCALARS, r->a_sint8));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint8_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_UINT8: {
	// 			if (r->a_uint8) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint8));
	// 				_mem_save_a_uint8_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_uint8, 0);
	// 				NDR_CHECK(ndr_pull_arr_uint8(ndr, NDR_SCALARS, r->a_uint8));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint8_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_SINT16: {
	// 			if (r->a_sint16) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint16));
	// 				_mem_save_a_sint16_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_sint16, 0);
	// 				NDR_CHECK(ndr_pull_arr_int16(ndr, NDR_SCALARS, r->a_sint16));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint16_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_UINT16: {
	// 			if (r->a_uint16) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint16));
	// 				_mem_save_a_uint16_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_uint16, 0);
	// 				NDR_CHECK(ndr_pull_arr_uint16(ndr, NDR_SCALARS, r->a_uint16));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint16_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_SINT32: {
	// 			if (r->a_sint32) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint32));
	// 				_mem_save_a_sint32_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_sint32, 0);
	// 				NDR_CHECK(ndr_pull_arr_int32(ndr, NDR_SCALARS, r->a_sint32));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint32_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_UINT32: {
	// 			if (r->a_uint32) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint32));
	// 				_mem_save_a_uint32_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_uint32, 0);
	// 				NDR_CHECK(ndr_pull_arr_uint32(ndr, NDR_SCALARS, r->a_uint32));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint32_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_SINT64: {
	// 			if (r->a_sint64) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint64));
	// 				_mem_save_a_sint64_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_sint64, 0);
	// 				NDR_CHECK(ndr_pull_arr_dlong(ndr, NDR_SCALARS, r->a_sint64));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint64_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_UINT64: {
	// 			if (r->a_uint64) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint64));
	// 				_mem_save_a_uint64_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_uint64, 0);
	// 				NDR_CHECK(ndr_pull_arr_udlong(ndr, NDR_SCALARS, r->a_uint64));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint64_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_REAL32: {
	// 			if (r->a_real32) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_real32));
	// 				_mem_save_a_real32_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_real32, 0);
	// 				NDR_CHECK(ndr_pull_arr_uint32(ndr, NDR_SCALARS, r->a_real32));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_real32_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_REAL64: {
	// 			if (r->a_real64) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_real64));
	// 				_mem_save_a_real64_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_real64, 0);
	// 				NDR_CHECK(ndr_pull_arr_udlong(ndr, NDR_SCALARS, r->a_real64));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_real64_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_BOOLEAN: {
	// 			if (r->a_boolean) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_boolean));
	// 				_mem_save_a_boolean_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_boolean, 0);
	// 				NDR_CHECK(ndr_pull_arr_uint16(ndr, NDR_SCALARS, r->a_boolean));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_boolean_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_STRING: {
	// 			if (r->a_string) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_string));
	// 				_mem_save_a_string_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_string, 0);
	// 				NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_string));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_string_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_DATETIME: {
	// 			if (r->a_datetime) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_datetime));
	// 				_mem_save_a_datetime_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_datetime, 0);
	// 				NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_datetime));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_datetime_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_REFERENCE: {
	// 			if (r->a_reference) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_reference));
	// 				_mem_save_a_reference_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_reference, 0);
	// 				NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_reference));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_reference_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		case CIM_ARR_OBJECT: {
	// 			if (r->a_object) {
	// 				struct ndr_pull_save _relative_save;
	// 				ndr_pull_save(ndr, &_relative_save);
	// 				NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_object));
	// 				_mem_save_a_object_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 				NDR_PULL_SET_MEM_CTX(ndr, r->a_object, 0);
	// 				NDR_CHECK(ndr_pull_arr_WbemClassObject(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_object));
	// 				NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_object_0, 0);
	// 				ndr_pull_restore(ndr, &_relative_save);
	// 			}
	// 		break; }

	// 		default:
	// 			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", level);
	// 	}
	// }
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_CIMVAR(struct ndr_pull *ndr, int ndr_flags, union CIMVAR *r)
{
	uint32_t level;
	//TALLOC_CTX *_mem_save_v_string_0;
	//TALLOC_CTX *_mem_save_v_datetime_0;
	//TALLOC_CTX *_mem_save_v_reference_0;
	TALLOC_CTX *_mem_save_v_object_0;
	TALLOC_CTX *_mem_save_a_sint8_0;
	TALLOC_CTX *_mem_save_a_uint8_0;
	TALLOC_CTX *_mem_save_a_sint16_0;
	TALLOC_CTX *_mem_save_a_uint16_0;
	TALLOC_CTX *_mem_save_a_sint32_0;
	TALLOC_CTX *_mem_save_a_uint32_0;
	TALLOC_CTX *_mem_save_a_sint64_0;
	TALLOC_CTX *_mem_save_a_uint64_0;
	TALLOC_CTX *_mem_save_a_real32_0;
	TALLOC_CTX *_mem_save_a_real64_0;
	TALLOC_CTX *_mem_save_a_boolean_0;
	TALLOC_CTX *_mem_save_a_string_0;
	TALLOC_CTX *_mem_save_a_datetime_0;
	TALLOC_CTX *_mem_save_a_reference_0;
	TALLOC_CTX *_mem_save_a_object_0;
    NDR_CHECK(ndr_token_peek(&ndr->switch_list, r, &level));
	if (ndr_flags & NDR_SCALARS) {
		switch (level) {
			case CIM_SINT8: {
				NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->v_sint8));
			break; }

			case CIM_UINT8: {
				NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->v_uint8));
			break; }

			case CIM_SINT16: {
				NDR_CHECK(ndr_pull_int16(ndr, NDR_SCALARS, &r->v_sint16));
			break; }

			case CIM_UINT16: {
				NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->v_uint16));
			break; }

			case CIM_SINT32: {
				NDR_CHECK(ndr_pull_int32(ndr, NDR_SCALARS, &r->v_sint32));
			break; }

			case CIM_UINT32: {
				NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->v_uint32));
			break; }

			case CIM_SINT64: {
				NDR_CHECK(ndr_pull_dlong(ndr, NDR_SCALARS, &r->v_sint64));
			break; }

			case CIM_UINT64: {
				NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->v_uint64));
			break; }

			case CIM_REAL32: {
				NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->v_real32));
			break; }

			case CIM_REAL64: {
				NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->v_real64));
			break; }

			case CIM_BOOLEAN: {
				NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->v_boolean));
			break; }

			case CIM_STRING: {
				uint32_t _ptr_v_string;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_v_string));
				if (_ptr_v_string) {
					NDR_PULL_ALLOC(ndr, r->v_string);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->v_string, _ptr_v_string));
				} else {
					r->v_string = NULL;
				}
			break; }

			case CIM_DATETIME: {
				uint32_t _ptr_v_datetime;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_v_datetime));
				if (_ptr_v_datetime) {
					NDR_PULL_ALLOC(ndr, r->v_datetime);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->v_datetime, _ptr_v_datetime));
				} else {
					r->v_datetime = NULL;
				}
			break; }

			case CIM_REFERENCE: {
				uint32_t _ptr_v_reference;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_v_reference));
				if (_ptr_v_reference) {
					NDR_PULL_ALLOC(ndr, r->v_reference);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->v_reference, _ptr_v_reference));
				} else {
					r->v_reference = NULL;
				}
			break; }

			case CIM_OBJECT: {
				uint32_t _ptr_v_object;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_v_object));
				if (_ptr_v_object) {
					NDR_PULL_ALLOC(ndr, r->v_object);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->v_object, _ptr_v_object));
				} else {
					r->v_object = NULL;
				}
			break; }

			case CIM_ARR_SINT8: {
				uint32_t _ptr_a_sint8;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint8));
				if (_ptr_a_sint8) {
					NDR_PULL_ALLOC(ndr, r->a_sint8);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint8, _ptr_a_sint8));
				} else {
					r->a_sint8 = NULL;
				}
			break; }

			case CIM_ARR_UINT8: {
				uint32_t _ptr_a_uint8;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint8));
				if (_ptr_a_uint8) {
					NDR_PULL_ALLOC(ndr, r->a_uint8);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint8, _ptr_a_uint8));
				} else {
					r->a_uint8 = NULL;
				}
			break; }

			case CIM_ARR_SINT16: {
				uint32_t _ptr_a_sint16;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint16));
				if (_ptr_a_sint16) {
					NDR_PULL_ALLOC(ndr, r->a_sint16);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint16, _ptr_a_sint16));
				} else {
					r->a_sint16 = NULL;
				}
			break; }

			case CIM_ARR_UINT16: {
				uint32_t _ptr_a_uint16;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint16));
				if (_ptr_a_uint16) {
					NDR_PULL_ALLOC(ndr, r->a_uint16);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint16, _ptr_a_uint16));
				} else {
					r->a_uint16 = NULL;
				}
			break; }

			case CIM_ARR_SINT32: {
				uint32_t _ptr_a_sint32;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint32));
				if (_ptr_a_sint32) {
					NDR_PULL_ALLOC(ndr, r->a_sint32);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint32, _ptr_a_sint32));
				} else {
					r->a_sint32 = NULL;
				}
			break; }

			case CIM_ARR_UINT32: {
				uint32_t _ptr_a_uint32;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint32));
				if (_ptr_a_uint32) {
					NDR_PULL_ALLOC(ndr, r->a_uint32);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint32, _ptr_a_uint32));
				} else {
					r->a_uint32 = NULL;
				}
			break; }

			case CIM_ARR_SINT64: {
				uint32_t _ptr_a_sint64;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_sint64));
				if (_ptr_a_sint64) {
					NDR_PULL_ALLOC(ndr, r->a_sint64);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_sint64, _ptr_a_sint64));
				} else {
					r->a_sint64 = NULL;
				}
			break; }

			case CIM_ARR_UINT64: {
				uint32_t _ptr_a_uint64;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_uint64));
				if (_ptr_a_uint64) {
					NDR_PULL_ALLOC(ndr, r->a_uint64);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_uint64, _ptr_a_uint64));
				} else {
					r->a_uint64 = NULL;
				}
			break; }

			case CIM_ARR_REAL32: {
				uint32_t _ptr_a_real32;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_real32));
				if (_ptr_a_real32) {
					NDR_PULL_ALLOC(ndr, r->a_real32);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_real32, _ptr_a_real32));
				} else {
					r->a_real32 = NULL;
				}
			break; }

			case CIM_ARR_REAL64: {
				uint32_t _ptr_a_real64;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_real64));
				if (_ptr_a_real64) {
					NDR_PULL_ALLOC(ndr, r->a_real64);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_real64, _ptr_a_real64));
				} else {
					r->a_real64 = NULL;
				}
			break; }

			case CIM_ARR_BOOLEAN: {
				uint32_t _ptr_a_boolean;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_boolean));
				if (_ptr_a_boolean) {
					NDR_PULL_ALLOC(ndr, r->a_boolean);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_boolean, _ptr_a_boolean));
				} else {
					r->a_boolean = NULL;
				}
			break; }

			case CIM_ARR_STRING: {
				uint32_t _ptr_a_string;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_string));
				if (_ptr_a_string) {
					NDR_PULL_ALLOC(ndr, r->a_string);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_string, _ptr_a_string));
				} else {
					r->a_string = NULL;
				}
			break; }

			case CIM_ARR_DATETIME: {
				uint32_t _ptr_a_datetime;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_datetime));
				if (_ptr_a_datetime) {
					NDR_PULL_ALLOC(ndr, r->a_datetime);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_datetime, _ptr_a_datetime));
				} else {
					r->a_datetime = NULL;
				}
			break; }

			case CIM_ARR_REFERENCE: {
				uint32_t _ptr_a_reference;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_reference));
				if (_ptr_a_reference) {
					NDR_PULL_ALLOC(ndr, r->a_reference);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_reference, _ptr_a_reference));
				} else {
					r->a_reference = NULL;
				}
			break; }

			case CIM_ARR_OBJECT: {
				uint32_t _ptr_a_object;
				NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_a_object));
				if (_ptr_a_object) {
					NDR_PULL_ALLOC(ndr, r->a_object);
					NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->a_object, _ptr_a_object));
				} else {
					r->a_object = NULL;
				}
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", level);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		switch (level) {
			case CIM_SINT8: {
			break; }

			case CIM_UINT8: {
			break; }

			case CIM_SINT16: {
			break; }

			case CIM_UINT16: {
			break; }

			case CIM_SINT32: {
			break; }

			case CIM_UINT32: {
			break; }

			case CIM_SINT64: {
			break; }

			case CIM_UINT64: {
			break; }

			case CIM_REAL32: {
			break; }

			case CIM_REAL64: {
			break; }

			case CIM_BOOLEAN: {
			break; }

			case CIM_STRING: {
				if (r->v_string) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_string));
					NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_string));
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_DATETIME: {
				if (r->v_datetime) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_datetime));
					NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_datetime));
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_REFERENCE: {
				if (r->v_reference) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_reference));
					NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->v_reference));
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_OBJECT: {
				if (r->v_object) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->v_object));
					_mem_save_v_object_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->v_object, 0);
					{
						struct ndr_pull *_ndr_v_object;
						NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_v_object, 4, -1));
						if (_ndr_v_object->data_size) {
							NDR_CHECK(ndr_pull_WbemClassObject(_ndr_v_object, NDR_SCALARS|NDR_BUFFERS, r->v_object));
						} else {
							talloc_free(r->v_object);
							r->v_object = NULL;
						}
						NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_v_object, 4, -1));
					}
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_v_object_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_SINT8: {
				if (r->a_sint8) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint8));
					_mem_save_a_sint8_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_sint8, 0);
					NDR_CHECK(ndr_pull_arr_int8(ndr, NDR_SCALARS, r->a_sint8));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint8_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_UINT8: {
				if (r->a_uint8) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint8));
					_mem_save_a_uint8_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_uint8, 0);
					NDR_CHECK(ndr_pull_arr_uint8(ndr, NDR_SCALARS, r->a_uint8));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint8_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_SINT16: {
				if (r->a_sint16) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint16));
					_mem_save_a_sint16_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_sint16, 0);
					NDR_CHECK(ndr_pull_arr_int16(ndr, NDR_SCALARS, r->a_sint16));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint16_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_UINT16: {
				if (r->a_uint16) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint16));
					_mem_save_a_uint16_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_uint16, 0);
					NDR_CHECK(ndr_pull_arr_uint16(ndr, NDR_SCALARS, r->a_uint16));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint16_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_SINT32: {
				if (r->a_sint32) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint32));
					_mem_save_a_sint32_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_sint32, 0);
					NDR_CHECK(ndr_pull_arr_int32(ndr, NDR_SCALARS, r->a_sint32));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint32_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_UINT32: {
				if (r->a_uint32) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint32));
					_mem_save_a_uint32_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_uint32, 0);
					NDR_CHECK(ndr_pull_arr_uint32(ndr, NDR_SCALARS, r->a_uint32));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint32_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_SINT64: {
				if (r->a_sint64) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_sint64));
					_mem_save_a_sint64_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_sint64, 0);
					NDR_CHECK(ndr_pull_arr_dlong(ndr, NDR_SCALARS, r->a_sint64));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_sint64_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_UINT64: {
				if (r->a_uint64) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_uint64));
					_mem_save_a_uint64_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_uint64, 0);
					NDR_CHECK(ndr_pull_arr_udlong(ndr, NDR_SCALARS, r->a_uint64));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_uint64_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_REAL32: {
				if (r->a_real32) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_real32));
					_mem_save_a_real32_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_real32, 0);
					NDR_CHECK(ndr_pull_arr_uint32(ndr, NDR_SCALARS, r->a_real32));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_real32_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_REAL64: {
				if (r->a_real64) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_real64));
					_mem_save_a_real64_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_real64, 0);
					NDR_CHECK(ndr_pull_arr_udlong(ndr, NDR_SCALARS, r->a_real64));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_real64_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_BOOLEAN: {
				if (r->a_boolean) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_boolean));
					_mem_save_a_boolean_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_boolean, 0);
					NDR_CHECK(ndr_pull_arr_uint16(ndr, NDR_SCALARS, r->a_boolean));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_boolean_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_STRING: {
				if (r->a_string) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_string));
					_mem_save_a_string_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_string, 0);
					NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_string));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_string_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_DATETIME: {
				if (r->a_datetime) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_datetime));
					_mem_save_a_datetime_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_datetime, 0);
					NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_datetime));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_datetime_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_REFERENCE: {
				if (r->a_reference) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_reference));
					_mem_save_a_reference_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_reference, 0);
					NDR_CHECK(ndr_pull_arr_CIMSTRING(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_reference));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_reference_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			case CIM_ARR_OBJECT: {
				if (r->a_object) {
					struct ndr_pull_save _relative_save;
					ndr_pull_save(ndr, &_relative_save);
					NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->a_object));
					_mem_save_a_object_0 = NDR_PULL_GET_MEM_CTX(ndr);
					NDR_PULL_SET_MEM_CTX(ndr, r->a_object, 0);
					NDR_CHECK(ndr_pull_arr_WbemClassObject(ndr, NDR_SCALARS|NDR_BUFFERS, r->a_object));
					NDR_PULL_SET_MEM_CTX(ndr, _mem_save_a_object_0, 0);
					ndr_pull_restore(ndr, &_relative_save);
				}
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u", level);
		}
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_CIMVAR(struct ndr_print *ndr, const char *name, const union CIMVAR *r)
{
	uint32_t level;
    if (unlikely(!NDR_ERR_CODE_IS_SUCCESS(ndr_token_peek(&ndr->switch_list, r, &level)))) {
        return;
    }
	ndr_print_union(ndr, name, level, "CIMVAR");
	switch (level) {
		case CIM_SINT8:
			ndr_print_int8(ndr, "v_sint8", r->v_sint8);
		break;

		case CIM_UINT8:
			ndr_print_uint8(ndr, "v_uint8", r->v_uint8);
		break;

		case CIM_SINT16:
			ndr_print_int16(ndr, "v_sint16", r->v_sint16);
		break;

		case CIM_UINT16:
			ndr_print_uint16(ndr, "v_uint16", r->v_uint16);
		break;

		case CIM_SINT32:
			ndr_print_int32(ndr, "v_sint32", r->v_sint32);
		break;

		case CIM_UINT32:
			ndr_print_uint32(ndr, "v_uint32", r->v_uint32);
		break;

		case CIM_SINT64:
			ndr_print_dlong(ndr, "v_sint64", r->v_sint64);
		break;

		case CIM_UINT64:
			ndr_print_udlong(ndr, "v_uint64", r->v_uint64);
		break;

		case CIM_REAL32:
			ndr_print_uint32(ndr, "v_real32", r->v_real32);
		break;

		case CIM_REAL64:
			ndr_print_udlong(ndr, "v_real64", r->v_real64);
		break;

		case CIM_BOOLEAN:
			ndr_print_uint16(ndr, "v_boolean", r->v_boolean);
		break;

		case CIM_STRING:
			ndr_print_ptr(ndr, "v_string", r->v_string);
			ndr->depth++;
			if (r->v_string) {
				ndr_print_CIMSTRING(ndr, "v_string", &r->v_string);
			}
			ndr->depth--;
		break;

		case CIM_DATETIME:
			ndr_print_ptr(ndr, "v_datetime", r->v_datetime);
			ndr->depth++;
			if (r->v_datetime) {
				ndr_print_CIMSTRING(ndr, "v_datetime", &r->v_datetime);
			}
			ndr->depth--;
		break;

		case CIM_REFERENCE:
			ndr_print_ptr(ndr, "v_reference", r->v_reference);
			ndr->depth++;
			if (r->v_reference) {
				ndr_print_CIMSTRING(ndr, "v_reference", &r->v_reference);
			}
			ndr->depth--;
		break;

		case CIM_OBJECT:
			ndr_print_ptr(ndr, "v_object", r->v_object);
			ndr->depth++;
			if (r->v_object) {
				ndr_print_WbemClassObject(ndr, "v_object", r->v_object);
			}
			ndr->depth--;
		break;

		case CIM_ARR_SINT8:
			ndr_print_ptr(ndr, "a_sint8", r->a_sint8);
			ndr->depth++;
			if (r->a_sint8) {
				ndr_print_arr_int8(ndr, "a_sint8", r->a_sint8);
			}
			ndr->depth--;
		break;

		case CIM_ARR_UINT8:
			ndr_print_ptr(ndr, "a_uint8", r->a_uint8);
			ndr->depth++;
			if (r->a_uint8) {
				ndr_print_arr_uint8(ndr, "a_uint8", r->a_uint8);
			}
			ndr->depth--;
		break;

		case CIM_ARR_SINT16:
			ndr_print_ptr(ndr, "a_sint16", r->a_sint16);
			ndr->depth++;
			if (r->a_sint16) {
				ndr_print_arr_int16(ndr, "a_sint16", r->a_sint16);
			}
			ndr->depth--;
		break;

		case CIM_ARR_UINT16:
			ndr_print_ptr(ndr, "a_uint16", r->a_uint16);
			ndr->depth++;
			if (r->a_uint16) {
				ndr_print_arr_uint16(ndr, "a_uint16", r->a_uint16);
			}
			ndr->depth--;
		break;

		case CIM_ARR_SINT32:
			ndr_print_ptr(ndr, "a_sint32", r->a_sint32);
			ndr->depth++;
			if (r->a_sint32) {
				ndr_print_arr_int32(ndr, "a_sint32", r->a_sint32);
			}
			ndr->depth--;
		break;

		case CIM_ARR_UINT32:
			ndr_print_ptr(ndr, "a_uint32", r->a_uint32);
			ndr->depth++;
			if (r->a_uint32) {
				ndr_print_arr_uint32(ndr, "a_uint32", r->a_uint32);
			}
			ndr->depth--;
		break;

		case CIM_ARR_SINT64:
			ndr_print_ptr(ndr, "a_sint64", r->a_sint64);
			ndr->depth++;
			if (r->a_sint64) {
				ndr_print_arr_dlong(ndr, "a_sint64", r->a_sint64);
			}
			ndr->depth--;
		break;

		case CIM_ARR_UINT64:
			ndr_print_ptr(ndr, "a_uint64", r->a_uint64);
			ndr->depth++;
			if (r->a_uint64) {
				ndr_print_arr_udlong(ndr, "a_uint64", r->a_uint64);
			}
			ndr->depth--;
		break;

		case CIM_ARR_REAL32:
			ndr_print_ptr(ndr, "a_real32", r->a_real32);
			ndr->depth++;
			if (r->a_real32) {
				ndr_print_arr_uint32(ndr, "a_real32", r->a_real32);
			}
			ndr->depth--;
		break;

		case CIM_ARR_REAL64:
			ndr_print_ptr(ndr, "a_real64", r->a_real64);
			ndr->depth++;
			if (r->a_real64) {
				ndr_print_arr_udlong(ndr, "a_real64", r->a_real64);
			}
			ndr->depth--;
		break;

		case CIM_ARR_BOOLEAN:
			ndr_print_ptr(ndr, "a_boolean", r->a_boolean);
			ndr->depth++;
			if (r->a_boolean) {
				ndr_print_arr_uint16(ndr, "a_boolean", r->a_boolean);
			}
			ndr->depth--;
		break;

		case CIM_ARR_STRING:
			ndr_print_ptr(ndr, "a_string", r->a_string);
			ndr->depth++;
			if (r->a_string) {
				ndr_print_arr_CIMSTRING(ndr, "a_string", r->a_string);
			}
			ndr->depth--;
		break;

		case CIM_ARR_DATETIME:
			ndr_print_ptr(ndr, "a_datetime", r->a_datetime);
			ndr->depth++;
			if (r->a_datetime) {
				ndr_print_arr_CIMSTRING(ndr, "a_datetime", r->a_datetime);
			}
			ndr->depth--;
		break;

		case CIM_ARR_REFERENCE:
			ndr_print_ptr(ndr, "a_reference", r->a_reference);
			ndr->depth++;
			if (r->a_reference) {
				ndr_print_arr_CIMSTRING(ndr, "a_reference", r->a_reference);
			}
			ndr->depth--;
		break;

		case CIM_ARR_OBJECT:
			ndr_print_ptr(ndr, "a_object", r->a_object);
			ndr->depth++;
			if (r->a_object) {
				ndr_print_arr_WbemClassObject(ndr, "a_object", r->a_object);
			}
			ndr->depth--;
		break;

		default:
			ndr_print_bad_level(ndr, name, level);
	}
}
enum ndr_err_code ndr_push_CIMSTRING(struct ndr_push *ndr, int ndr_flags, const CIMSTRING *r)
{
	uint8_t u;
	enum ndr_err_code status;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

        NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, 0));
	u = ndr->flags;
	ndr->flags |= LIBNDR_FLAG_STR_ASCII | LIBNDR_FLAG_STR_NULLTERM;
	status = ndr_push_string(ndr, NDR_SCALARS, *r);
	DEBUG(9, ("%08X: Push string: %s\n", ndr->offset, *r));
	ndr->flags = u;
	return status;
}

enum ndr_err_code ndr_pull_CIMSTRING(struct ndr_pull *ndr, int ndr_flags, CIMSTRING *r)
{
	uint8_t u;
	enum ndr_err_code status;

	if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &u));
		switch (u) {
		case 0:
			u = ndr->flags;
			ndr->flags |= LIBNDR_FLAG_STR_ASCII | LIBNDR_FLAG_STR_NULLTERM;
			status = ndr_pull_string(ndr, NDR_SCALARS, r);
			DEBUG(9, ("%08X: Pull string: %s\n", ndr->offset, *r));
			ndr->flags = u;
			return status;
		case 1:
			u = ndr->flags;
			ndr->flags |= LIBNDR_FLAG_STR_NULLTERM;
			status = ndr_pull_string(ndr, NDR_SCALARS, r);
			DEBUG(9, ("%08X: Pull string: %s\n", ndr->offset, *r));
			ndr->flags = u;
			return status;
		default: return NDR_ERR_BAD_SWITCH;
	}
}

void ndr_print_CIMSTRING(struct ndr_print *ndr, const char *name, const CIMSTRING *r)
{
	ndr->print(ndr, "%-25s: \"%s\"", name, *r);
}

enum ndr_err_code ndr_push_CIMSTRINGS(struct ndr_push *ndr, int ndr_flags, const struct CIMSTRINGS *r)
{
	uint32_t ofs_size, ofs, i;

        if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

	ofs_size = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));

	for (i = 0; i < r->count; ++i) {
		ofs = ndr->offset;
		NDR_CHECK(ndr_push_CIMSTRING(ndr, ndr_flags, &r->item[i]));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr->offset - ofs));
	}
	ofs = ndr->offset;
	ndr->offset = ofs_size;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs -  ofs_size));
	ndr->offset = ofs;

        return NDR_ERR_SUCCESS;
}

void ndr_print_CIMSTRINGS(struct ndr_print *ndr, const char *name, const struct CIMSTRINGS *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "CIMSTRINGS");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_ptr(ndr, "item", r->item[cntr_item_0]);
			ndr->depth++;
			ndr_print_CIMSTRING(ndr, "item", &r->item[cntr_item_0]);
			ndr->depth--;
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_pull_CIMSTRINGS(struct ndr_pull *ndr, int ndr_flags, struct CIMSTRINGS *r)
{
    uint32_t endofs;
    uint32_t len;
    TALLOC_CTX *mem_ctx;
    uint32_t u;

    if (!(ndr_flags & NDR_SCALARS)) return NDR_ERR_SUCCESS;

    mem_ctx = ndr->current_mem_ctx;

    NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
    endofs += ndr->offset - sizeof(endofs);

    r->count = 0;
    len = 5;
    r->item = talloc_array(mem_ctx, CIMSTRING, len);
    ndr->current_mem_ctx = r->item;
    while (ndr->offset < endofs) {
        if (r->count >= len) {
            len += 3;
            r->item = talloc_realloc(mem_ctx, r->item, CIMSTRING, len);
            /* update the memory context with the realloc'ed ptr */
            ndr->current_mem_ctx = r->item;
        }
        NDR_CHECK(ndr_pull_CIMSTRING(ndr, ndr_flags, &r->item[r->count]));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &u));
        ++r->count;
    }

    r->item = talloc_realloc(mem_ctx, r->item, CIMSTRING, r->count);

    ndr->current_mem_ctx = mem_ctx;

    return NDR_ERR_SUCCESS;
}

static const char *qualifier_keys[] = {
    [0] = "\"",
    [1] = "key",
    [2] = "",
    [3] = "read",
    [4] = "write",
    [5] = "volatile",
    [6] = "provider",
    [7] = "dynamic",
    [8] = "cimwin32",
    [9] = "DWORD",
    [10] = "CIMTYPE"
};

#define arr_sizeof(a) (sizeof(a)/sizeof(a[0]))
static const char *qn_unknown = "Unknown_qualifier_name";

enum ndr_err_code ndr_push_WbemQualifier(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifier *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->name));
		NDR_CHECK(ndr_push_WBEM_FLAVOR_TYPE(ndr, NDR_SCALARS, r->flavors));
		NDR_CHECK(ndr_push_CIMTYPE_ENUMERATION(ndr, NDR_SCALARS, r->cimtype));
		NDR_CHECK(ndr_push_set_switch_value(ndr, &r->value, r->cimtype & CIM_TYPEMASK));
		NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->value));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->name) {
			uint32_t ofs;
			int32_t i;
			for (i = 0; i < arr_sizeof(qualifier_keys); ++i)
				if (qualifier_keys[i] && !strcmp(r->name, qualifier_keys[i])) break;
			if (i == arr_sizeof(qualifier_keys)) {
				if (!strncmp(qn_unknown, r->name, sizeof(qn_unknown) - 1))
						i = atoi(r->name + sizeof(qn_unknown) - 1);
				else
						i = -1;
			}
			if (i >= 0) {
				ofs = ndr->offset;
				NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->name, &ndr->offset));
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0x80000000 | i));
				ndr->offset = ofs;
			} else {
				NDR_CHECK(ndr_push_relative_ptr2(ndr, r->name));
				NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->name));
			}
		}
		NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->value));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemQualifier(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifier *r)
{
        uint32_t _ptr_name;
        TALLOC_CTX *_mem_save_name_0;
        if (ndr_flags & NDR_SCALARS) {
                NDR_CHECK(ndr_pull_align(ndr, 4));
                NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_name));
                if (_ptr_name != 0xFFFFFFFF) {
                        NDR_PULL_ALLOC(ndr, r->name);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->name, _ptr_name));
                } else {
                        r->name = NULL;
                }
                NDR_CHECK(ndr_pull_WBEM_FLAVOR_TYPE(ndr, NDR_SCALARS, &r->flavors));
                NDR_CHECK(ndr_pull_CIMTYPE_ENUMERATION(ndr, NDR_SCALARS, &r->cimtype));
                NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->value, r->cimtype & CIM_TYPEMASK));
                NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS, &r->value));
        }
        if (ndr_flags & NDR_BUFFERS) {
		uint32_t relofs;
		NDR_CHECK(ndr_token_peek(&ndr->relative_list, r->name, &relofs));
		if (relofs & 0x80000000) {
			relofs &= 0xFF;
			if ((relofs < sizeof(qualifier_keys)/sizeof(qualifier_keys[0])) && qualifier_keys[relofs]) {
				r->name = talloc_strdup(ndr->current_mem_ctx, qualifier_keys[relofs]);
			} else {
				r->name = talloc_asprintf(ndr->current_mem_ctx, "%s%d", qn_unknown, relofs);
			}
		} else if (r->name) {
                        struct ndr_pull_save _relative_save;
                        ndr_pull_save(ndr, &_relative_save);
                        NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->name));
                        _mem_save_name_0 = NDR_PULL_GET_MEM_CTX(ndr);
                        NDR_PULL_SET_MEM_CTX(ndr, r->name, 0);
                        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->name));
                        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_name_0, 0);
                        ndr_pull_restore(ndr, &_relative_save);
                }
                NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_BUFFERS, &r->value));
        }
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemQualifier2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemQualifier *r);
enum ndr_err_code ndr_pull_WbemQualifier2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemQualifier *r)
{
	uint32_t _ptr_name;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_name));
	if (_ptr_name != 0xFFFFFFFF) {
		if (_ptr_name & 0x80000000) {
			_ptr_name &= 0xFF;
			if ((_ptr_name < sizeof(qualifier_keys)/sizeof(qualifier_keys[0])) && qualifier_keys[_ptr_name]) {
					r->name = talloc_strdup(ndr->current_mem_ctx, qualifier_keys[_ptr_name]);
			} else {
					r->name = talloc_asprintf(ndr->current_mem_ctx, "%s%d", qn_unknown, _ptr_name);
			}
		} else {
			swap_off(&heap->offset, &_ptr_name);
			NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->name));
			swap_off(&heap->offset, &_ptr_name);
		}
	} else {
			r->name = NULL;
	}
	NDR_CHECK(ndr_pull_WBEM_FLAVOR_TYPE(ndr, NDR_SCALARS, &r->flavors));
	NDR_CHECK(ndr_pull_CIMTYPE_ENUMERATION(ndr, NDR_SCALARS, &r->cimtype));
	NDR_CHECK(ndr_pull_CIMVAR2(ndr, heap, r->cimtype & CIM_TYPEMASK, &r->value));
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemQualifier(struct ndr_print *ndr, const char *name, const struct WbemQualifier *r)
{
	ndr_print_struct(ndr, name, "WbemQualifier");
	ndr->depth++;
	ndr_print_ptr(ndr, "name", r->name);
	ndr->depth++;
	if (r->name) {
		ndr_print_CIMSTRING(ndr, "name", &r->name);
	}
	ndr->depth--;
	ndr_print_WBEM_FLAVOR_TYPE(ndr, "flavors", r->flavors);
	ndr_print_CIMTYPE_ENUMERATION(ndr, "cimtype", r->cimtype);
	ndr_print_set_switch_value(ndr, &r->value, r->cimtype);
	ndr_print_CIMVAR(ndr, "value", &r->value);
	ndr->depth--;
}

enum ndr_err_code ndr_push_WbemQualifiers(struct ndr_push *ndr, int ndr_flags, const struct WbemQualifiers *r)
{
	uint32_t i, ofs, ofs_size;

        if (ndr_flags & NDR_SCALARS) {
		ofs_size = ndr->offset;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		for (i = 0; i < r->count; ++i)
			NDR_CHECK(ndr_push_WbemQualifier(ndr, NDR_SCALARS, r->item[i]));
		ofs = ndr->offset;
		ndr->offset = ofs_size;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs - ofs_size));
		ndr->offset = ofs;
	}
	if (ndr_flags & NDR_BUFFERS) {
		for (i = 0; i < r->count; ++i)
			NDR_CHECK(ndr_push_WbemQualifier(ndr, NDR_BUFFERS, r->item[i]));
	}
        return NDR_ERR_SUCCESS;
}

void ndr_print_WbemQualifiers(struct ndr_print *ndr, const char *name, const struct WbemQualifiers *r)
{
	uint32_t cntr_item_0;
	ndr_print_struct(ndr, name, "WbemQualifiers");
	ndr->depth++;
	ndr_print_uint32(ndr, "count", r->count);
	ndr->print(ndr, "%s: ARRAY(%d)", "item", r->count);
	ndr->depth++;
	for (cntr_item_0=0;cntr_item_0<r->count;cntr_item_0++) {
		char *idx_0=NULL;
		asprintf(&idx_0, "[%d]", cntr_item_0);
		if (idx_0) {
			ndr_print_ptr(ndr, "item", r->item[cntr_item_0]);
			ndr->depth++;
			ndr_print_WbemQualifier(ndr, "item", r->item[cntr_item_0]);
			ndr->depth--;
			free(idx_0);
		}
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_pull_WbemQualifiers(struct ndr_pull *ndr, int ndr_flags, struct WbemQualifiers *r)
{
	uint32_t endofs;
	uint32_t len;
	TALLOC_CTX *mem_ctx;

	mem_ctx = ndr->current_mem_ctx;

    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
        endofs += ndr->offset - 4;

        r->count = 0;
        len = 10;
        r->item = talloc_array(mem_ctx, struct WbemQualifier*, len);
        ndr->current_mem_ctx = r->item;
        while (ndr->offset < endofs) {
            if (r->count >= len) {
                len += 3;
                r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, len);
                /* update the memory context with the realloc'ed ptr */
                ndr->current_mem_ctx = r->item;
            }
            NDR_PULL_ALLOC(ndr, r->item[r->count]);
            NDR_CHECK(ndr_pull_WbemQualifier(ndr, NDR_SCALARS, r->item[r->count]));
            ++r->count;
        }
        r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, r->count);
    }
    if (ndr_flags & NDR_BUFFERS) {
        uint32_t i;
        ndr->current_mem_ctx = r->item;
        for (i = 0; i < r->count; ++i) {
            NDR_CHECK(ndr_pull_WbemQualifier(ndr, NDR_BUFFERS, r->item[i]));
        }
    }

ndr->current_mem_ctx = mem_ctx;

    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemQualifiers2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemQualifiers *r);
enum ndr_err_code ndr_pull_WbemQualifiers2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemQualifiers *r)
{
	uint32_t endofs;
	uint32_t len;
	TALLOC_CTX *mem_ctx;

	mem_ctx = ndr->current_mem_ctx;

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
	endofs += ndr->offset - sizeof(endofs);

	r->count = 0;
	len = 10;
	r->item = talloc_array(mem_ctx, struct WbemQualifier*, len);
	ndr->current_mem_ctx = r->item;
	while (ndr->offset < endofs) {
		if (r->count >= len) {
			len += 3;
			r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, len);
			/* update the memory context with the realloc'ed ptr */
			ndr->current_mem_ctx = r->item;
		}
		NDR_PULL_ALLOC(ndr, r->item[r->count]);
		NDR_CHECK(ndr_pull_WbemQualifier2(ndr, heap, r->item[r->count]));
		++r->count;
	}
	r->item = talloc_realloc(mem_ctx, r->item, struct WbemQualifier*, r->count);
	ndr->current_mem_ctx = mem_ctx;
	return NDR_ERR_SUCCESS;
}
enum ndr_err_code ndr_push_DataWithStack(struct ndr_push *ndr, ndr_push_flags_fn_t fn, const void *r)
{
	uint32_t ofs, ofs_size, ofs_ssize;

	ofs_size = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));

	NDR_CHECK(fn(ndr, NDR_SCALARS, r));

	ofs_ssize = ndr->offset;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
	ndr->relative_base_offset = ndr->offset;

	NDR_CHECK(fn(ndr, NDR_BUFFERS, r));

	ofs = ndr->offset;
	ndr->offset = ofs_size;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ofs-ofs_size));
	ndr->offset = ofs_ssize;
	NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, (ofs-ofs_ssize-4) | 0x80000000));
	ndr->offset = ofs;

    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_DataWithStack(struct ndr_pull *ndr, ndr_pull_flags_fn_t fn, void *r)
{
	uint32_t end, size, ssize, ndrend;

	end = ndr->offset;
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &size));
	NDR_PULL_NEED_BYTES(ndr, size - 4);
	end += size;
	ndrend = ndr->data_size;
	ndr->data_size = end;
    printf("data ws size = %x, offset = %x, end = %x\n", size, ndr->offset - 4, ndr->data_size);
    if (fn) {
	    NDR_CHECK(fn(ndr, NDR_SCALARS, r));

        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ssize));
        printf("data ws ssize = %x, offset = %x\n", ssize, ndr->offset - 4);
        if (!(ssize & 0x80000000))
            return ndr_pull_error(ndr, NDR_ERR_VALIDATE, "ndr_pull_DataWithStack(%08X): Stack size without 31th bit set: 0x%08X", ndr->offset - 4, ssize);
        ssize &= 0x7FFFFFFF;
        NDR_PULL_NEED_BYTES(ndr, ssize);
        ndr->data_size = ndr->offset + ssize;

        ndr->relative_base_offset = ndr->offset;

        NDR_CHECK(fn(ndr, NDR_BUFFERS, r));
    }
	ndr->data_size = ndrend;
	ndr->offset = end;

    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_WbemPropertyDesc(struct ndr_push *ndr, int ndr_flags, const struct WbemPropertyDesc *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->cimtype));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->nr));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->offset));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->depth));
		NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemPropertyDesc2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemPropertyDesc *r);
enum ndr_err_code ndr_pull_WbemPropertyDesc2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemPropertyDesc *r)
{
	NDR_CHECK(ndr_pull_align(ndr, 4));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->cimtype));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->nr));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->offset));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->depth));
	NDR_CHECK(ndr_pull_WbemQualifiers2(ndr, heap, &r->qualifiers));
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemPropertyDesc(struct ndr_pull *ndr, int ndr_flags, struct WbemPropertyDesc *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->cimtype));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->nr));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->offset));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->depth));
		NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemPropertyDesc(struct ndr_print *ndr, const char *name, const struct WbemPropertyDesc *r)
{
	ndr_print_struct(ndr, name, "WbemPropertyDesc");
	ndr->depth++;
	ndr_print_uint32(ndr, "cimtype", r->cimtype);
	ndr_print_uint16(ndr, "nr", r->nr);
	ndr_print_uint32(ndr, "offset", r->offset);
	ndr_print_uint32(ndr, "depth", r->depth);
	ndr_print_WbemQualifiers(ndr, "qualifiers", &r->qualifiers);
	ndr->depth--;
}

enum ndr_err_code ndr_push_WbemProperty(struct ndr_push *ndr, int ndr_flags, const struct WbemProperty *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->name));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->desc));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->name) {
			NDR_CHECK(ndr_push_relative_ptr2(ndr, r->name));
			NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->name));
		}
		if (r->desc) {
			NDR_CHECK(ndr_push_relative_ptr2(ndr, r->desc));
			NDR_CHECK(ndr_push_WbemPropertyDesc(ndr, NDR_SCALARS|NDR_BUFFERS, r->desc));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemProperty2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemProperty *r);
enum ndr_err_code ndr_pull_WbemProperty2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemProperty *r)
{
	uint32_t _ptr_name;
	uint32_t _ptr_desc;
	TALLOC_CTX *_mem_save_desc_0;

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_name));
	if (_ptr_name) {
		swap_off(&heap->offset, &_ptr_name);
		NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->name));
		swap_off(&heap->offset, &_ptr_name);
	} else {
		r->name = NULL;
	}

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_desc));
	if (_ptr_desc) {
		NDR_PULL_ALLOC(ndr, r->desc);
		_mem_save_desc_0 = heap->current_mem_ctx;
		swap_off(&heap->offset, &_ptr_desc);
		NDR_CHECK(ndr_pull_WbemPropertyDesc2(heap, heap, r->desc));
		swap_off(&heap->offset, &_ptr_desc);
		heap->current_mem_ctx = _mem_save_desc_0;
	} else {
		r->desc = NULL;
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemProperty(struct ndr_pull *ndr, int ndr_flags, struct WbemProperty *r)
{
	uint32_t _ptr_name;
	//TALLOC_CTX *_mem_save_name_0;
	uint32_t _ptr_desc;
	TALLOC_CTX *_mem_save_desc_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_name));
		if (_ptr_name) {
			NDR_PULL_ALLOC(ndr, r->name);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->name, _ptr_name));
		} else {
			r->name = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_desc));
		if (_ptr_desc) {
			NDR_PULL_ALLOC(ndr, r->desc);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->desc, _ptr_desc));
		} else {
			r->desc = NULL;
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->name) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->name));
			NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->name));
			ndr_pull_restore(ndr, &_relative_save);
		}
		if (r->desc) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->desc));
			_mem_save_desc_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->desc, 0);
			NDR_CHECK(ndr_pull_WbemPropertyDesc(ndr, NDR_SCALARS|NDR_BUFFERS, r->desc));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_desc_0, 0);
			ndr_pull_restore(ndr, &_relative_save);
		}
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemProperty(struct ndr_print *ndr, const char *name, const struct WbemProperty *r)
{
	ndr_print_struct(ndr, name, "WbemProperty");
	ndr->depth++;
	ndr_print_ptr(ndr, "name", r->name);
	ndr->depth++;
	if (r->name) {
		ndr_print_CIMSTRING(ndr, "name", &r->name);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "desc", r->desc);
	ndr->depth++;
	if (r->desc) {
		ndr_print_WbemPropertyDesc(ndr, "desc", r->desc);
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_WbemClass(struct ndr_push *ndr, int ndr_flags, const struct WbemClass *r)
{
	uint32_t cntr_properties_0;
	uint32_t i, ofs, vofs;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_push_align(ndr, 4));
			NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->u_0));
			if (r->__CLASS) {
				NDR_CHECK(ndr_push_relative_ptr1(ndr, r->__CLASS));
			} else {
				NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
			}
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->data_size));
			NDR_CHECK(ndr_push_CIMSTRINGS(ndr, NDR_SCALARS, &r->__DERIVATION));
			NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->__PROPERTY_COUNT));
			for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
				NDR_CHECK(ndr_push_WbemProperty(ndr, NDR_SCALARS, &r->properties[cntr_properties_0]));
			}

			ofs = ndr->offset;
			NDR_PUSH_NEED_BYTES(ndr, r->data_size);

			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				copy_bits(&r->default_flags[i], 0, ndr->data + ndr->offset, 2*r->properties[i].desc->nr, 2);
			}
			i = 0xFF;
			copy_bits((uint8_t *)&i, 0, ndr->data + ndr->offset, 2*r->__PROPERTY_COUNT, (8 - 2*r->__PROPERTY_COUNT) % 7);
			vofs = ofs + ((r->__PROPERTY_COUNT + 3) >> 2);
			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				NDR_CHECK(ndr_push_set_switch_value(ndr, &r->default_values[i], r->properties[i].desc->cimtype & CIM_TYPEMASK));
				ndr->offset = vofs + r->properties[i].desc->offset;
				if ((r->default_flags[i] & DEFAULT_FLAG_EMPTY) && IS_CIMTYPE_PTR(r->properties[i].desc->cimtype & CIM_TYPEMASK)) {
                    NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
				} else {
					NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->default_values[i]));
				}
			}
			ndr->offset = ofs + r->data_size;
                }
                if (ndr_flags & NDR_BUFFERS) {
                        if (r->__CLASS) {
                                NDR_CHECK(ndr_push_relative_ptr2(ndr, r->__CLASS));
                                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__CLASS));
                        }
                        NDR_CHECK(ndr_push_CIMSTRINGS(ndr, NDR_BUFFERS, &r->__DERIVATION));
                        NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
                        for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                                NDR_CHECK(ndr_push_WbemProperty(ndr, NDR_BUFFERS, &r->properties[cntr_properties_0]));
                        }
			for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
				if (r->default_flags[i] & DEFAULT_FLAG_EMPTY) continue;
				NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->default_values[i]));
			}
                }
                ndr->flags = _flags_save_STRUCT;
        }
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemClass(struct ndr_pull *ndr, struct WbemClass *r)
{
	uint32_t endofs = 0; // to methods
	uint32_t classNameRef = 0;
	uint32_t qualifiersSize = 0;
	TALLOC_CTX *prev_ctx;
	struct ndr_pull* heap = NULL;
	NDR_PULL_SET_MEM_CTX(ndr, r, 0);

	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
	endofs += ndr->offset - sizeof(endofs);
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->u_0)); // ReservedOctet
	///
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &classNameRef));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->data_size)); // NdTableValueTableLength in octets
	NDR_CHECK(ndr_pull_CIMSTRINGS(ndr, NDR_SCALARS, &r->__DERIVATION));

	heap = talloc_zero(ndr->current_mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = ndr->current_mem_ctx;
	heap->data_size = ndr->data_size - ndr->offset;
	heap->data = ndr->data + ndr->offset;
	heap->offset = 0;
	ndr_set_flags(&heap->flags, ndr->flags);
	NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &qualifiersSize));
	heap->offset += qualifiersSize - sizeof(uint32_t);
	NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &r->__PROPERTY_COUNT));
	heap->offset += (r->__PROPERTY_COUNT * 2 * sizeof(uint32_t)) + r->data_size;
	NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &heap->data_size));
	heap->data_size &= 0x7fffffff;
	heap->data += heap->offset;
	if (classNameRef != 0xFFFFFFFF) {
		swap_off(&heap->offset, &classNameRef);
		NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->__CLASS));
		swap_off(&heap->offset, &classNameRef);
	} else {
		r->__CLASS = NULL;
	}
	///
	NDR_CHECK(ndr_pull_WbemQualifiers2(ndr, heap, &r->qualifiers));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->__PROPERTY_COUNT));
	NDR_PULL_ALLOC_N(ndr, r->properties, r->__PROPERTY_COUNT);
	prev_ctx = NDR_PULL_GET_MEM_CTX(ndr);
	NDR_PULL_SET_MEM_CTX(ndr, r->properties, 0);
	for (uint32_t i = 0; i < r->__PROPERTY_COUNT; ++i) {
		NDR_CHECK(ndr_pull_WbemProperty2(ndr, heap, &(r->properties)[i]));
	}
	NDR_PULL_SET_MEM_CTX(ndr, prev_ctx, 0);

	NDR_PULL_ALLOC_N(ndr, r->default_flags, r->__PROPERTY_COUNT);
	memset(r->default_flags, 1, sizeof(*r->default_flags) * r->__PROPERTY_COUNT);
	{
		uint8_t* ptr = ndr->data + ndr->offset;
		for (uint32_t i = 0; i < r->__PROPERTY_COUNT; ++i) {
			r->default_flags[i] = 0;
			copy_bits(ptr, 2*r->properties[i].desc->nr, &r->default_flags[i], 0, 2);
		}
	}
	NDR_PULL_ALLOC_N(ndr, r->default_values, r->__PROPERTY_COUNT);
	memset(r->default_values, 0, sizeof(*r->default_values) * r->__PROPERTY_COUNT);
	{
		uint32_t ofs = ndr->offset + ((r->__PROPERTY_COUNT + 3) >> 2);
		for (uint32_t i = 0; i < r->__PROPERTY_COUNT; ++i) {
			if (r->default_flags[i] & DEFAULT_FLAG_EMPTY) continue;
			NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->default_values[i], r->properties[i].desc->cimtype & CIM_TYPEMASK));
			ndr->offset = ofs + r->properties[i].desc->offset;
			NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS|NDR_BUFFERS, &r->default_values[i]));
		}
	}

	ndr->offset = endofs;
	return NDR_ERR_SUCCESS;
}
enum ndr_err_code ndr_pull_WbemClass_(struct ndr_pull *ndr, int ndr_flags, struct WbemClass *r);
enum ndr_err_code ndr_pull_WbemClass_(struct ndr_pull *ndr, int ndr_flags, struct WbemClass *r)
{
	uint32_t _ptr___CLASS;
	uint32_t cntr_properties_0;
	TALLOC_CTX *_mem_save_properties_0;
	uint32_t i;

    {
        uint32_t _flags_save_STRUCT = ndr->flags;

        ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        if (ndr_flags & NDR_SCALARS) {
            NDR_CHECK(ndr_pull_align(ndr, 4));
            NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->u_0));
            printf("_ptr___CLASS offset = %x\n", ndr->offset);
            NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr___CLASS));
            if (_ptr___CLASS != 0xFFFFFFFF) {
                printf("__CLASS offset = %x\n", _ptr___CLASS);
                NDR_PULL_ALLOC(ndr, r->__CLASS);
                NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->__CLASS, _ptr___CLASS));
            } else {
                r->__CLASS = NULL;
            }
            NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->data_size));
            printf("__DERIVATION offset = %x\n", ndr->offset);
            NDR_CHECK(ndr_pull_CIMSTRINGS(ndr, NDR_SCALARS, &r->__DERIVATION));
            NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_SCALARS, &r->qualifiers));
            printf("__PROPERTY_COUNT offset = %x\n", ndr->offset);
            NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->__PROPERTY_COUNT));
            NDR_PULL_ALLOC_N(ndr, r->properties, r->__PROPERTY_COUNT);
            _mem_save_properties_0 = NDR_PULL_GET_MEM_CTX(ndr);
            NDR_PULL_SET_MEM_CTX(ndr, r->properties, 0);
            for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                NDR_CHECK(ndr_pull_WbemProperty(ndr, NDR_SCALARS, &(r->properties)[cntr_properties_0]));
            }
            NDR_PULL_SET_MEM_CTX(ndr, _mem_save_properties_0, 0);

            NDR_PULL_NEED_BYTES(ndr, r->data_size);

            NDR_PULL_ALLOC_N(ndr, r->default_flags, r->__PROPERTY_COUNT);
            NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->default_flags, ndr->offset));

            NDR_PULL_ALLOC_N(ndr, r->default_values, r->__PROPERTY_COUNT);
            memset(r->default_values, 0, sizeof(*r->default_values) * r->__PROPERTY_COUNT);
            NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->default_values, ndr->offset + ((r->__PROPERTY_COUNT + 3) >> 2)));

            ndr->offset += r->data_size;
        }
        if (ndr_flags & NDR_BUFFERS) {
            if (r->__CLASS) {
                TALLOC_CTX *_mem_save___CLASS_0;
                struct ndr_pull_save _relative_save;
                ndr_pull_save(ndr, &_relative_save);
                NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->__CLASS));
                _mem_save___CLASS_0 = NDR_PULL_GET_MEM_CTX(ndr);
                NDR_PULL_SET_MEM_CTX(ndr, r->__CLASS, 0);
                NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__CLASS));
                NDR_PULL_SET_MEM_CTX(ndr, _mem_save___CLASS_0, 0);
                ndr_pull_restore(ndr, &_relative_save);
            }
            NDR_CHECK(ndr_pull_CIMSTRINGS(ndr, NDR_BUFFERS, &r->__DERIVATION));
            NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_BUFFERS, &r->qualifiers));
            _mem_save_properties_0 = NDR_PULL_GET_MEM_CTX(ndr);
            NDR_PULL_SET_MEM_CTX(ndr, r->properties, 0);
            for (cntr_properties_0 = 0; cntr_properties_0 < r->__PROPERTY_COUNT; cntr_properties_0++) {
                NDR_CHECK(ndr_pull_WbemProperty(ndr, NDR_BUFFERS, &(r->properties)[cntr_properties_0]));
            }
            NDR_PULL_SET_MEM_CTX(ndr, _mem_save_properties_0, 0);
            {
                uint32_t ofs;
                NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->default_flags, &ofs));
                for (i = 0; i < r->__PROPERTY_COUNT; ++i) {
                    r->default_flags[i] = 0;
                    copy_bits(ndr->data + ofs, 2*r->properties[i].desc->nr, &r->default_flags[i], 0, 2);
                }
            }
            {
                struct ndr_pull_save _relative_save;
                uint32_t ofs;
                ndr_pull_save(ndr, &_relative_save);
                NDR_CHECK(ndr_token_retrieve(&ndr->relative_list, r->default_values, &ofs));
                for (i=0; i < r->__PROPERTY_COUNT; ++i) {
                    if (r->default_flags[i] & DEFAULT_FLAG_EMPTY) continue;
                    NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->default_values[i], r->properties[i].desc->cimtype & CIM_TYPEMASK));
                    ndr->offset = ofs + r->properties[i].desc->offset;
                    NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS|NDR_BUFFERS, &r->default_values[i]));
                }
                ndr_pull_restore(ndr, &_relative_save);
            }
        }
        ndr->flags = _flags_save_STRUCT;
    }
    return NDR_ERR_SUCCESS;
}

void ndr_print_WbemClass(struct ndr_print *ndr, const char *name, const struct WbemClass *r)
{
        uint32_t cntr_properties_0;
        uint32_t cntr_default_values_0;
        ndr_print_struct(ndr, name, "WbemClass");
        {
                uint32_t _flags_save_STRUCT = ndr->flags;
                ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
                ndr->depth++;
                ndr_print_uint8(ndr, "u_0", r->u_0);
                ndr_print_ptr(ndr, "__CLASS", r->__CLASS);
                ndr->depth++;
                if (r->__CLASS) {
                        ndr_print_CIMSTRING(ndr, "__CLASS", &r->__CLASS);
                }
                ndr->depth--;
                ndr_print_uint32(ndr, "data_size", r->data_size);
                ndr_print_CIMSTRINGS(ndr, "__DERIVATION", &r->__DERIVATION);
                ndr_print_WbemQualifiers(ndr, "qualifiers", &r->qualifiers);
                ndr_print_uint32(ndr, "__PROPERTY_COUNT", r->__PROPERTY_COUNT);
                ndr->print(ndr, "%s: ARRAY(%d)", "properties", r->__PROPERTY_COUNT);
                ndr->depth++;
                for (cntr_properties_0=0;cntr_properties_0<r->__PROPERTY_COUNT;cntr_properties_0++) {
                        char *idx_0=NULL;
                        asprintf(&idx_0, "[%d]", cntr_properties_0);
                        if (idx_0) {
                                ndr_print_WbemProperty(ndr, "properties", &r->properties[cntr_properties_0]);
                                free(idx_0);
                        }
                }
                ndr->depth--;
                ndr_print_array_uint8(ndr, "default_flags", r->default_flags, r->__PROPERTY_COUNT);
                ndr->print(ndr, "%s: ARRAY(%d)", "default_values", r->__PROPERTY_COUNT);
                ndr->depth++;
                for (cntr_default_values_0=0;cntr_default_values_0<r->__PROPERTY_COUNT;cntr_default_values_0++) {
                        char *idx_0=NULL;
                        asprintf(&idx_0, "[%d]", cntr_default_values_0);
                        if (idx_0) {
				ndr_print_set_switch_value(ndr, &r->default_values[cntr_default_values_0], r->properties[cntr_default_values_0].desc->cimtype & CIM_TYPEMASK);
                                ndr_print_CIMVAR(ndr, "default_values", &r->default_values[cntr_default_values_0]);
                                free(idx_0);
                        }
                }
                ndr->depth--;
                ndr->depth--;
                ndr->flags = _flags_save_STRUCT;
        }
}

enum ndr_err_code ndr_push_WbemMethod(struct ndr_push *ndr, int ndr_flags, const struct WbemMethod *r)
{
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		if (r->name) {
			NDR_CHECK(ndr_push_relative_ptr1(ndr, r->name));
		} else {
			NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, r->name, ndr->offset));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
		}
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->flags));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->origin));
		NDR_CHECK(ndr_push_relative_ptr1(ndr, r->qualifiers));
		if (r->in) {
			NDR_CHECK(ndr_push_relative_ptr1(ndr, r->in));
		} else {
			NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, r->in, ndr->offset));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
		}
		if (r->out) {
			NDR_CHECK(ndr_push_relative_ptr1(ndr, r->out));
		} else {
			NDR_CHECK(ndr_token_store(ndr, &ndr->relative_list, r->out, ndr->offset));
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->name) {
			NDR_CHECK(ndr_push_relative_ptr2(ndr, r->name));
			NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->name));
		}
		if (r->qualifiers) {
			NDR_CHECK(ndr_push_relative_ptr2(ndr, r->qualifiers));
			NDR_CHECK(ndr_push_WbemQualifiers(ndr, NDR_SCALARS|NDR_BUFFERS, r->qualifiers));
		}
		NDR_CHECK(ndr_push_relative_ptr2(ndr, r->in));
		if (r->in) {
			{
				struct ndr_push *_ndr_in;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_in, 4, -1));
				NDR_CHECK(ndr_push_WbemClassObject(_ndr_in, NDR_SCALARS|NDR_BUFFERS, r->in));
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_in, 4, -1));
			}
		}
		NDR_CHECK(ndr_push_relative_ptr2(ndr, r->out));
		if (r->out) {
			{
				struct ndr_push *_ndr_out;
				NDR_CHECK(ndr_push_subcontext_start(ndr, &_ndr_out, 4, -1));
				NDR_CHECK(ndr_push_WbemClassObject(_ndr_out, NDR_SCALARS|NDR_BUFFERS, r->out));
				NDR_CHECK(ndr_push_subcontext_end(ndr, _ndr_out, 4, -1));
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemMethod_InOut(struct ndr_pull *heap, uint32_t ptr, struct WbemClassObject **r);
enum ndr_err_code ndr_pull_WbemMethod_InOut(struct ndr_pull *heap, uint32_t ptr, struct WbemClassObject **r)
{
	TALLOC_CTX *prev_ctx = NULL;
	if (ptr != 0xFFFFFFFF) {
		NDR_PULL_ALLOC(heap, *r);
		NDR_ZERO_STRUCTP(*r);

		prev_ctx = heap->current_mem_ctx;
		heap->current_mem_ctx = *r;
		swap_off(&heap->offset, &ptr);
		{
			struct ndr_pull *_ndr_in;
			NDR_CHECK(ndr_pull_subcontext_start(heap, &_ndr_in, 4, -1));
			if (_ndr_in->data_size) {
				NDR_CHECK(ndr_pull_WbemClassObject(_ndr_in, NDR_SCALARS|NDR_BUFFERS, *r));
			} else {
				talloc_free(*r);
				*r = NULL;
			}
			NDR_CHECK(ndr_pull_subcontext_end(heap, _ndr_in, 4, -1));
		}
		swap_off(&heap->offset, &ptr);
		heap->current_mem_ctx = prev_ctx;
	} else {
		*r = NULL;
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemMethod2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemMethod *r);
enum ndr_err_code ndr_pull_WbemMethod2(struct ndr_pull *ndr, struct ndr_pull *heap, struct WbemMethod *r)
{
	uint32_t _ptr_name;
	uint32_t _ptr_qualifiers;
	uint32_t _ptr_in;
	uint32_t _ptr_out;
	//TALLOC_CTX *_mem_save_name_0;
	TALLOC_CTX *prev_ctx = NULL;
	// TALLOC_CTX *_mem_save_in_0;
	// TALLOC_CTX *_mem_save_out_0;

	NDR_CHECK(ndr_pull_align(ndr, 4));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_name));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->flags));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->origin));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_qualifiers));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_in));
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_ptr_out));

	if (_ptr_name != 0xFFFFFFFF) {
		swap_off(&heap->offset, &_ptr_name);
		NDR_CHECK(ndr_pull_CIMSTRING(heap, NDR_SCALARS, &r->name));
		swap_off(&heap->offset, &_ptr_name);
	} else {
		r->name = NULL;
	}
	if (_ptr_qualifiers != 0xFFFFFFFF) {
		NDR_PULL_ALLOC(heap, r->qualifiers);
		r->qualifiers->count = 0;
		r->qualifiers->item = NULL;
		prev_ctx = heap->current_mem_ctx;
		heap->current_mem_ctx = r->qualifiers;
		swap_off(&heap->offset, &_ptr_qualifiers);
		NDR_CHECK(ndr_pull_WbemQualifiers2(heap, heap, r->qualifiers));
		swap_off(&heap->offset, &_ptr_qualifiers);
		heap->current_mem_ctx = prev_ctx;
	} else {
		r->qualifiers = NULL;
	}
	NDR_CHECK(ndr_pull_WbemMethod_InOut(heap, _ptr_in, &r->in));
	NDR_CHECK(ndr_pull_WbemMethod_InOut(heap, _ptr_out, &r->out));
	// if (ndr_flags & NDR_SCALARS) {
	// 	NDR_CHECK(ndr_pull_align(ndr, 4));
	// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_name));
	// 	if (_ptr_name != 0xFFFFFFFF) {
	// 		NDR_PULL_ALLOC(ndr, r->name);
	// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->name, _ptr_name));
	// 	} else {
	// 		r->name = NULL;
	// 	}
	// 	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->u0));
	// 	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->u1));
	// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_qualifiers));
	// 	if (_ptr_qualifiers) {
	// 		NDR_PULL_ALLOC(ndr, r->qualifiers);
	// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->qualifiers, _ptr_qualifiers));
	// 	} else {
	// 		r->qualifiers = NULL;
	// 	}
	// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_in));
	// 	if (_ptr_in) {
	// 		NDR_PULL_ALLOC(ndr, r->in);
	// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->in, _ptr_in));
	// 	} else {
	// 		r->in = NULL;
	// 	}
	// 	NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_out));
	// 	if (_ptr_out) {
	// 		NDR_PULL_ALLOC(ndr, r->out);
	// 		NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->out, _ptr_out));
	// 	} else {
	// 		r->out = NULL;
	// 	}
	// }
	// if (ndr_flags & NDR_BUFFERS) {
	// 	if (r->name) {
	// 		struct ndr_pull_save _relative_save;
	// 		ndr_pull_save(ndr, &_relative_save);
	// 		NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->name));
	// 		NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->name));
	// 		ndr_pull_restore(ndr, &_relative_save);
	// 	}
	// 	if (r->qualifiers) {
	// 		struct ndr_pull_save _relative_save;
	// 		ndr_pull_save(ndr, &_relative_save);
	// 		NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->qualifiers));
	// 		_mem_save_qualifiers_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 		NDR_PULL_SET_MEM_CTX(ndr, r->qualifiers, 0);
	// 		NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_SCALARS|NDR_BUFFERS, r->qualifiers));
	// 		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_qualifiers_0, 0);
	// 		ndr_pull_restore(ndr, &_relative_save);
	// 	}
	// 	if (r->in) {
	// 		struct ndr_pull_save _relative_save;
	// 		ndr_pull_save(ndr, &_relative_save);
	// 		NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->in));
	// 		_mem_save_in_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 		NDR_PULL_SET_MEM_CTX(ndr, r->in, 0);
	// 		{
	// 			struct ndr_pull *_ndr_in;
	// 			NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_in, 4, -1));
	// 			if (_ndr_in->data_size) {
	// 				NDR_CHECK(ndr_pull_WbemClassObject(_ndr_in, NDR_SCALARS|NDR_BUFFERS, r->in));
	// 			} else {
	// 				talloc_free(r->in);
	// 				r->in = NULL;
	// 			}
	// 			NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_in, 4, -1));
	// 		}
	// 		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_in_0, 0);
	// 		ndr_pull_restore(ndr, &_relative_save);
	// 	}
	// 	if (r->out) {
	// 		struct ndr_pull_save _relative_save;
	// 		ndr_pull_save(ndr, &_relative_save);
	// 		NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->out));
	// 		_mem_save_out_0 = NDR_PULL_GET_MEM_CTX(ndr);
	// 		NDR_PULL_SET_MEM_CTX(ndr, r->out, 0);
	// 		{
	// 			struct ndr_pull *_ndr_out;
	// 			NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_out, 4, -1));
	// 			if (_ndr_out->data_size) {
	// 				NDR_CHECK(ndr_pull_WbemClassObject(_ndr_out, NDR_SCALARS|NDR_BUFFERS, r->out));
	// 			} else {
	// 				talloc_free(r->out);
	// 				r->out = NULL;
	// 			}
	// 			NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_out, 4, -1));
	// 		}
	// 		NDR_PULL_SET_MEM_CTX(ndr, _mem_save_out_0, 0);
	// 		ndr_pull_restore(ndr, &_relative_save);
	// 	}
	// }
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemMethod(struct ndr_pull *ndr, int ndr_flags, struct WbemMethod *r)
{
	uint32_t _ptr_name;
	//TALLOC_CTX *_mem_save_name_0;
	uint32_t _ptr_qualifiers;
	TALLOC_CTX *_mem_save_qualifiers_0;
	uint32_t _ptr_in;
	TALLOC_CTX *_mem_save_in_0;
	uint32_t _ptr_out;
	TALLOC_CTX *_mem_save_out_0;
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_name));
		if (_ptr_name != 0xFFFFFFFF) {
			NDR_PULL_ALLOC(ndr, r->name);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->name, _ptr_name));
		} else {
			r->name = NULL;
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->flags));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->origin));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_qualifiers));
		if (_ptr_qualifiers) {
			NDR_PULL_ALLOC(ndr, r->qualifiers);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->qualifiers, _ptr_qualifiers));
		} else {
			r->qualifiers = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_in));
		if (_ptr_in) {
			NDR_PULL_ALLOC(ndr, r->in);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->in, _ptr_in));
		} else {
			r->in = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_out));
		if (_ptr_out) {
			NDR_PULL_ALLOC(ndr, r->out);
			NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->out, _ptr_out));
		} else {
			r->out = NULL;
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->name) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->name));
			NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->name));
			ndr_pull_restore(ndr, &_relative_save);
		}
		if (r->qualifiers) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->qualifiers));
			_mem_save_qualifiers_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->qualifiers, 0);
			NDR_CHECK(ndr_pull_WbemQualifiers(ndr, NDR_SCALARS|NDR_BUFFERS, r->qualifiers));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_qualifiers_0, 0);
			ndr_pull_restore(ndr, &_relative_save);
		}
		if (r->in) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->in));
			_mem_save_in_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->in, 0);
			{
				struct ndr_pull *_ndr_in;
				NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_in, 4, -1));
				if (_ndr_in->data_size) {
					NDR_CHECK(ndr_pull_WbemClassObject(_ndr_in, NDR_SCALARS|NDR_BUFFERS, r->in));
				} else {
					talloc_free(r->in);
					r->in = NULL;
				}
				NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_in, 4, -1));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_in_0, 0);
			ndr_pull_restore(ndr, &_relative_save);
		}
		if (r->out) {
			struct ndr_pull_save _relative_save;
			ndr_pull_save(ndr, &_relative_save);
			NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->out));
			_mem_save_out_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->out, 0);
			{
				struct ndr_pull *_ndr_out;
				NDR_CHECK(ndr_pull_subcontext_start(ndr, &_ndr_out, 4, -1));
				if (_ndr_out->data_size) {
					NDR_CHECK(ndr_pull_WbemClassObject(_ndr_out, NDR_SCALARS|NDR_BUFFERS, r->out));
				} else {
					talloc_free(r->out);
					r->out = NULL;
				}
				NDR_CHECK(ndr_pull_subcontext_end(ndr, _ndr_out, 4, -1));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_out_0, 0);
			ndr_pull_restore(ndr, &_relative_save);
		}
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemMethod(struct ndr_print *ndr, const char *name, const struct WbemMethod *r)
{
	ndr_print_struct(ndr, name, "WbemMethod");
	ndr->depth++;
	ndr_print_ptr(ndr, "name", r->name);
	ndr->depth++;
	if (r->name) {
		ndr_print_CIMSTRING(ndr, "name", &r->name);
	}
	ndr->depth--;
	ndr_print_uint32(ndr, "u0", r->flags);
	ndr_print_uint32(ndr, "u1", r->origin);
	ndr_print_ptr(ndr, "qualifiers", r->qualifiers);
	ndr->depth++;
	if (r->qualifiers) {
		ndr_print_WbemQualifiers(ndr, "qualifiers", r->qualifiers);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "in", r->in);
	ndr->depth++;
	if (r->in) {
		ndr_print_WbemClassObject(ndr, "in", r->in);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "out", r->out);
	ndr->depth++;
	if (r->out) {
		ndr_print_WbemClassObject(ndr, "out", r->out);
	}
	ndr->depth--;
	ndr->depth--;
}

enum ndr_err_code ndr_push_WbemMethods(struct ndr_push *ndr, int ndr_flags, const struct WbemMethods *r)
{
	uint32_t cntr_method_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_push_align(ndr, 4));
			NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->count));
			NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->u0));
			for (cntr_method_0 = 0; cntr_method_0 < r->count; cntr_method_0++) {
				NDR_CHECK(ndr_push_WbemMethod(ndr, NDR_SCALARS, &r->method[cntr_method_0]));
			}
		}
		if (ndr_flags & NDR_BUFFERS) {
			for (cntr_method_0 = 0; cntr_method_0 < r->count; cntr_method_0++) {
				NDR_CHECK(ndr_push_WbemMethod(ndr, NDR_BUFFERS, &r->method[cntr_method_0]));
			}
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemMethods(struct ndr_pull *ndr, struct WbemMethods *r)
{
	uint32_t endofs = 0; // to end
	struct ndr_pull* heap = NULL;
	TALLOC_CTX *prev_ctx = NULL;
	uint32_t prev_flags = ndr->flags;

	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
	NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &endofs));
	endofs += ndr->offset - sizeof(endofs);

	NDR_CHECK(ndr_pull_align(ndr, 4));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->count));
	NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->u0));
	NDR_PULL_ALLOC_N(ndr, r->method, r->count);
	prev_ctx = NDR_PULL_GET_MEM_CTX(ndr);
	NDR_PULL_SET_MEM_CTX(ndr, r->method, 0);

	heap = talloc_zero(ndr->current_mem_ctx, struct ndr_pull);
	ndr->current_mem_ctx = ndr->current_mem_ctx;
	heap->data_size = ndr->data_size - ndr->offset;
	heap->data = ndr->data + ndr->offset + (24 * r->count);
	heap->offset = 0;
	ndr_set_flags(&heap->flags, ndr->flags);
	NDR_CHECK(ndr_pull_uint32(heap, NDR_SCALARS, &heap->data_size));
	heap->data_size &= 0x7fffffff;
	heap->data += heap->offset;

	for (uint32_t i = 0; i < r->count; ++i) {
		NDR_CHECK(ndr_pull_WbemMethod2(ndr, heap, &(r->method)[i]));
	}
	NDR_PULL_SET_MEM_CTX(ndr, prev_ctx, 0);

	ndr->flags = prev_flags;
	ndr->offset = endofs;
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemMethods_(struct ndr_pull *ndr, int ndr_flags, struct WbemMethods *r);
enum ndr_err_code ndr_pull_WbemMethods_(struct ndr_pull *ndr, int ndr_flags, struct WbemMethods *r)
{
	uint32_t cntr_method_0;
	TALLOC_CTX *_mem_save_method_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_pull_align(ndr, 4));
			NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->count));
			NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->u0));
			NDR_PULL_ALLOC_N(ndr, r->method, r->count);
			_mem_save_method_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->method, 0);
			for (cntr_method_0 = 0; cntr_method_0 < r->count; cntr_method_0++) {
				NDR_CHECK(ndr_pull_WbemMethod(ndr, NDR_SCALARS, &(r->method)[cntr_method_0]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_method_0, 0);
		}
		if (ndr_flags & NDR_BUFFERS) {
			_mem_save_method_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->method, 0);
			for (cntr_method_0 = 0; cntr_method_0 < r->count; cntr_method_0++) {
				NDR_CHECK(ndr_pull_WbemMethod(ndr, NDR_BUFFERS, &(r->method)[cntr_method_0]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_method_0, 0);
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemMethods(struct ndr_print *ndr, const char *name, const struct WbemMethods *r)
{
	uint32_t cntr_method_0;
	ndr_print_struct(ndr, name, "WbemMethods");
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		ndr->depth++;
		ndr_print_uint16(ndr, "count", r->count);
		ndr_print_uint16(ndr, "u0", r->u0);
		ndr->print(ndr, "%s: ARRAY(%d)", "method", r->count);
		ndr->depth++;
		for (cntr_method_0=0;cntr_method_0<r->count;cntr_method_0++) {
			char *idx_0=NULL;
			asprintf(&idx_0, "[%d]", cntr_method_0);
			if (idx_0) {
				ndr_print_WbemMethod(ndr, "method", &r->method[cntr_method_0]);
				free(idx_0);
			}
		}
		ndr->depth--;
		ndr->depth--;
		ndr->flags = _flags_save_STRUCT;
	}
}

enum ndr_err_code ndr_push_WbemClassObject(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->flags));
	if (r->flags & WCF_CLASS) {
                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
                NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_DECORATIONS) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemClass, r->sup_class));
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemMethods, r->sup_methods));
	}
	if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemClass, r->obj_class));
	}
	if (r->flags & WCF_DECORATIONS) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemMethods, r->obj_methods));
	}
	if (r->flags & WCF_INSTANCE) {
		NDR_CHECK(ndr_push_DataWithStack(ndr, (ndr_push_flags_fn_t)ndr_push_WbemInstance_priv, r));
	}
        return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_WbemInstance_priv(struct ndr_push *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	int i;
	if (ndr_flags & NDR_SCALARS) {
		uint32_t ofs, vofs;

		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->instance->u1_0));
		if (r->instance->__CLASS) {
			NDR_CHECK(ndr_push_relative_ptr1(ndr, r->instance->__CLASS));
		} else {
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0xFFFFFFFF));
		}

		ofs = ndr->offset;
		NDR_PUSH_NEED_BYTES(ndr, r->obj_class->data_size);
		// NdTable
		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			//printf("[%d] %x -> %x\n", i, (int)r->instance->default_flags[i], (int)*(ndr->data + ndr->offset));
			copy_bits(&r->instance->default_flags[i], 0, ndr->data + ndr->offset, 2*r->obj_class->properties[i].desc->nr, 2);
		}
		i = 0xFF;
		copy_bits((uint8_t *)&i, 0, ndr->data + ndr->offset, 2*r->obj_class->__PROPERTY_COUNT, (8 - 2*r->obj_class->__PROPERTY_COUNT) % 7);
		//printf("[] x -> %x\n", (int)*(ndr->data + ndr->offset));
		*(ndr->data + ndr->offset) = 0x30;
		vofs = ofs + ((r->obj_class->__PROPERTY_COUNT + 3) >> 2);
		// ValueTable
		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_push_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].desc->cimtype & CIM_TYPEMASK));
			ndr->offset = vofs + r->obj_class->properties[i].desc->offset;
			NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_SCALARS, &r->instance->data[i]));
		}
		ndr->offset = ofs + r->obj_class->data_size;

		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->instance->u2_4));
		NDR_CHECK(ndr_push_uint8(ndr, NDR_SCALARS, r->instance->u3_1));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->instance->__CLASS) {
				NDR_CHECK(ndr_push_relative_ptr2(ndr, r->instance->__CLASS));
				NDR_CHECK(ndr_push_CIMSTRING(ndr, NDR_SCALARS, &r->instance->__CLASS));
		}
		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_push_CIMVAR(ndr, NDR_BUFFERS, &r->instance->data[i]));
		}
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemInstance_priv(struct ndr_pull *ndr, int ndr_flags, const struct WbemClassObject *r)
{
	int i;

	if (!r->obj_class) {
        DEBUG(1,("ndr_pull_WbemInstance_priv: There is no class for given instance\n"));
		return NDR_ERR_INVALID_POINTER;
	}
        ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t ofs, vofs;
		uint32_t _ptr___CLASS;

		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->instance->u1_0));

                NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr___CLASS));
                if (_ptr___CLASS != 0xFFFFFFFF) {
                        NDR_PULL_ALLOC(ndr, r->instance->__CLASS);
                        NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->instance->__CLASS, _ptr___CLASS));
                } else {
                        r->instance->__CLASS = NULL;
                }

		ofs = ndr->offset;
		NDR_PULL_NEED_BYTES(ndr, r->obj_class->data_size);
                NDR_PULL_ALLOC_N(ndr, r->instance->default_flags, r->obj_class->__PROPERTY_COUNT);
		for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			r->instance->default_flags[i] = 0;
			copy_bits(ndr->data + ndr->offset, 2*r->obj_class->properties[i].desc->nr, &r->instance->default_flags[i], 0, 2);
		}
		vofs = ofs + ((r->obj_class->__PROPERTY_COUNT + 3) >> 2);

                NDR_PULL_ALLOC_N(ndr, r->instance->data, r->obj_class->__PROPERTY_COUNT);
		memset(r->instance->data, 0, sizeof(*r->instance->data) * r->obj_class->__PROPERTY_COUNT);
                for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].desc->cimtype & CIM_TYPEMASK));
			ndr->offset = vofs + r->obj_class->properties[i].desc->offset;
			NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_SCALARS, &r->instance->data[i]));
		}
		ndr->offset = ofs + r->obj_class->data_size;

		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->instance->u2_4));
		NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->instance->u3_1));
	}
	if (ndr_flags & NDR_BUFFERS) {
                if (r->instance->__CLASS) {
                        struct ndr_pull_save _relative_save;
                        ndr_pull_save(ndr, &_relative_save);
                        NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->instance->__CLASS));
                        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->instance->__CLASS));
                        ndr_pull_restore(ndr, &_relative_save);
                }
                for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
			NDR_CHECK(ndr_pull_CIMVAR(ndr, NDR_BUFFERS, &r->instance->data[i]));
		}
	}
	return NDR_ERR_SUCCESS;
}

void ndr_print_WbemInstance_priv(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r)
{
	int i;

	ndr_print_array_uint8(ndr, "default_flags", r->instance->default_flags, r->obj_class->__PROPERTY_COUNT);

	ndr->print(ndr, "%s: ARRAY(%d)", "data", r->obj_class->__PROPERTY_COUNT);
	ndr->depth++;
	for (i = 0; i < r->obj_class->__PROPERTY_COUNT; ++i) {
		ndr->print(ndr, "%s[%d]", "data", i);
		ndr->depth++;
		ndr_print_set_switch_value(ndr, &r->instance->data[i], r->obj_class->properties[i].desc->cimtype & CIM_TYPEMASK);
		ndr_print_CIMVAR(ndr, r->obj_class->properties[i].name, &r->instance->data[i]);
		ndr->depth--;
	}
	ndr->depth--;
}

enum ndr_err_code ndr_pull_WbemClassObject(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r)
{
	//TALLOC_CTX *tc;

	//tc = NDR_PULL_GET_MEM_CTX(ndr);
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
	NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->flags));
	if (r->flags & WCF_DECORATIONS) {
		NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
		NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_CLASS) {
		r->sup_class = talloc_zero(r, struct WbemClass);
		r->sup_methods = talloc_zero(r, struct WbemMethods);
		r->obj_class = talloc_zero(r, struct WbemClass);
		r->obj_methods = talloc_zero(r, struct WbemMethods);
		//
		NDR_PULL_SET_MEM_CTX(ndr, r->sup_class, 0);
		NDR_CHECK(ndr_pull_WbemClass(ndr, r->sup_class));
		NDR_PULL_SET_MEM_CTX(ndr, r->sup_methods, 0);
		NDR_CHECK(ndr_pull_WbemMethods(ndr, r->sup_methods));
		//
		NDR_PULL_SET_MEM_CTX(ndr, r->obj_class, 0);
		NDR_CHECK(ndr_pull_WbemClass(ndr, r->obj_class));
		NDR_PULL_SET_MEM_CTX(ndr, r->obj_methods, 0);
		NDR_CHECK(ndr_pull_WbemMethods(ndr, r->obj_methods));
	}
	if (r->flags & WCF_INSTANCE) {
		r->obj_class = talloc_zero(r, struct WbemClass);
		//
		NDR_PULL_SET_MEM_CTX(ndr, r->obj_class, 0);
		NDR_CHECK(ndr_pull_WbemClass(ndr, r->obj_class));
	}
	// if (r->flags & WCF_DECORATIONS) {
	// 	r->sup_class = talloc_zero(r, struct WbemClass);
	// 	NDR_PULL_SET_MEM_CTX(ndr, r->sup_class, 0);
	// 	//NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemClass, r->sup_class));
    //     NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)NULL, r->sup_class));
	// 	r->sup_methods = talloc_zero(r, struct WbemMethods);
	// 	NDR_PULL_SET_MEM_CTX(ndr, r->sup_methods, 0);
	// 	//NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemMethods, r->sup_methods));
    //     NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)NULL, r->sup_methods));
	// 	NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	// } else
	// 	r->sup_class = NULL;
	// if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
	// 	r->obj_class = talloc_zero(r, struct WbemClass);
	// 	NDR_PULL_SET_MEM_CTX(ndr, r->obj_class, 0);
	// 	//NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemClass, r->obj_class));
    //     NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)NULL, r->obj_class));
	// 	NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	// }
	// if (r->flags & WCF_DECORATIONS) {
	// 	r->obj_methods = talloc_zero(r, struct WbemMethods);
	// 	NDR_PULL_SET_MEM_CTX(ndr, r->obj_methods, 0);
	// 	NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemMethods, r->obj_methods));
	// 	NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	// }
	// if (r->flags & WCF_INSTANCE) {
	// 	r->instance = talloc_zero(r, struct WbemInstance);
	// 	NDR_PULL_SET_MEM_CTX(ndr, r->instance, 0);
	// 	NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemInstance_priv, r));
	// 	NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	// } else
	// 	r->instance = NULL;
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_WbemClassObject_Object(struct ndr_pull *ndr, int ndr_flags, struct WbemClassObject *r)
{
	TALLOC_CTX *tc;

	tc = NDR_PULL_GET_MEM_CTX(ndr);
	ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
    NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->flags));
	if (r->flags & WCF_CLASS) {
        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__SERVER));
        NDR_CHECK(ndr_pull_CIMSTRING(ndr, NDR_SCALARS, &r->__NAMESPACE));
	}
	if (r->flags & WCF_INSTANCE) {
		r->instance = talloc_zero(r, struct WbemInstance);
		NDR_PULL_SET_MEM_CTX(ndr, r->instance, 0);
		NDR_CHECK(ndr_pull_DataWithStack(ndr, (ndr_pull_flags_fn_t)ndr_pull_WbemInstance_priv, r));
		NDR_PULL_SET_MEM_CTX(ndr, tc, 0);
	} else
		r->instance = NULL;
        return NDR_ERR_SUCCESS;
}

void ndr_print_WbemClassObject(struct ndr_print *ndr, const char *name, const struct WbemClassObject *r)
{
    ndr_print_struct(ndr, name, "WbemClassObject");
    {
        uint32_t _flags_save_STRUCT = ndr->flags;
        ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
        ndr->depth++;
        ndr_print_WCO_FLAGS(ndr, "flags", r->flags);
        if (r->flags & WCF_CLASS) {
            ndr_print_ptr(ndr, "__SERVER", r->__SERVER);
            ndr->depth++;
            ndr_print_CIMSTRING(ndr, "__SERVER", &r->__SERVER);
            ndr->depth--;
            ndr_print_ptr(ndr, "__NAMESPACE", r->__NAMESPACE);
            ndr->depth++;
            ndr_print_CIMSTRING(ndr, "__NAMESPACE", &r->__NAMESPACE);
            ndr->depth--;
        }
        if (r->flags & WCF_DECORATIONS) {
            ndr_print_ptr(ndr, "sup_class", r->sup_class);
            ndr->depth++;
            if (r->sup_class) {
                    ndr_print_WbemClass(ndr, "sup_class", r->sup_class);
            }
            ndr->depth--;
            ndr_print_ptr(ndr, "sup_methods", r->sup_methods);
            ndr->depth++;
            if (r->sup_methods) {
                    ndr_print_WbemMethods(ndr, "sup_methods", r->sup_methods);
            }
            ndr->depth--;
        }
        if (r->flags & (WCF_CLASS | WCF_INSTANCE)) {
            ndr_print_ptr(ndr, "obj_class", r->obj_class);
            ndr->depth++;
            if (r->obj_class) {
                    ndr_print_WbemClass(ndr, "obj_class", r->obj_class);
            }
            ndr->depth--;
        }
        if (r->flags & WCF_DECORATIONS) {
            ndr_print_ptr(ndr, "obj_methods", r->obj_methods);
            ndr->depth++;
            if (r->obj_methods) {
                    ndr_print_WbemMethods(ndr, "obj_methods", r->obj_methods);
            }
            ndr->depth--;
        }
        if (r->flags & WCF_INSTANCE) {
            ndr_print_ptr(ndr, "instance", r->instance);
            ndr->depth++;
            if (r->instance) {
                    ndr_print_WbemInstance_priv(ndr, "instance", r);
            }
            ndr->depth--;
        }
        ndr->depth--;
        ndr->flags = _flags_save_STRUCT;
    }
}