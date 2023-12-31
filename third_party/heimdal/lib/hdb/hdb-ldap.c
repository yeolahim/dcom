/*
 * Copyright (c) 1999-2001, 2003, PADL Software Pty Ltd.
 * Copyright (c) 2004, Andrew Bartlett.
 * Copyright (c) 2003 - 2008, Kungliga Tekniska Högskolan.
 * Copyright (c) 2015, Timothy Pearson.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software  nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "hdb_locl.h"

#ifdef OPENLDAP

#include <lber.h>
#include <ldap.h>
#include <sys/un.h>
#include <hex.h>

static krb5_error_code LDAP__connect(krb5_context context, HDB *);
static krb5_error_code LDAP_close(krb5_context context, HDB *);

static krb5_error_code
LDAP_message2entry(krb5_context context, HDB * db, LDAPMessage * msg,
		   int flags, hdb_entry * ent);

static const char *default_structural_object = "account";
static char *structural_object;
static const char *default_ldap_url = "ldapi:///";
static krb5_boolean samba_forwardable;

struct hdbldapdb {
    LDAP *h_lp;
    int   h_msgid;
    char *h_base;
    char *h_url;
    char *h_bind_dn;
    char *h_bind_password;
    krb5_boolean h_start_tls;
    char *h_createbase;
};

#define HDB2LDAP(db) (((struct hdbldapdb *)(db)->hdb_db)->h_lp)
#define HDB2MSGID(db) (((struct hdbldapdb *)(db)->hdb_db)->h_msgid)
#define HDBSETMSGID(db,msgid) \
	do { ((struct hdbldapdb *)(db)->hdb_db)->h_msgid = msgid; } while(0)
#define HDB2BASE(dn) (((struct hdbldapdb *)(db)->hdb_db)->h_base)
#define HDB2URL(dn) (((struct hdbldapdb *)(db)->hdb_db)->h_url)
#define HDB2BINDDN(db) (((struct hdbldapdb *)(db)->hdb_db)->h_bind_dn)
#define HDB2BINDPW(db) (((struct hdbldapdb *)(db)->hdb_db)->h_bind_password)
#define HDB2CREATE(db) (((struct hdbldapdb *)(db)->hdb_db)->h_createbase)

/*
 *
 */

static char * krb5kdcentry_attrs[] = {
    "cn",
    "createTimestamp",
    "creatorsName",
    "krb5EncryptionType",
    "krb5KDCFlags",
    "krb5Key",
    "krb5KeyVersionNumber",
    "krb5MaxLife",
    "krb5MaxRenew",
    "krb5PasswordEnd",
    "krb5PrincipalName",
    "krb5PrincipalRealm",
    "krb5ExtendedAttributes",
    "krb5ValidEnd",
    "krb5ValidStart",
    "modifiersName",
    "modifyTimestamp",
    "objectClass",
    "sambaAcctFlags",
    "sambaKickoffTime",
    "sambaNTPassword",
    "sambaPwdLastSet",
    "sambaPwdMustChange",
    "uid",
    NULL
};

static char *krb5principal_attrs[] = {
    "cn",
    "createTimestamp",
    "creatorsName",
    "krb5PrincipalName",
    "krb5PrincipalRealm",
    "modifiersName",
    "modifyTimestamp",
    "objectClass",
    "uid",
    NULL
};

static int
LDAP_no_size_limit(krb5_context context, LDAP *lp)
{
    int ret, limit = LDAP_NO_LIMIT;

    ret = ldap_set_option(lp, LDAP_OPT_SIZELIMIT, (const void *)&limit);
    if (ret != LDAP_SUCCESS) {
	krb5_set_error_message(context, HDB_ERR_BADVERSION,
			       "ldap_set_option: %s",
			       ldap_err2string(ret));
	return HDB_ERR_BADVERSION;
    }
    return 0;
}

static int
check_ldap(krb5_context context, HDB *db, int ret)
{
    switch (ret) {
    case LDAP_SUCCESS:
	return 0;
    case LDAP_SERVER_DOWN:
	LDAP_close(context, db);
	return 1;
    default:
	return 1;
    }
}

static krb5_error_code
LDAP__setmod(LDAPMod *** modlist, int modop, const char *attribute,
	     int *pIndex)
{
    int cMods;

    if (*modlist == NULL) {
	*modlist = (LDAPMod **)ber_memcalloc(1, sizeof(LDAPMod *));
	if (*modlist == NULL)
	    return ENOMEM;
    }

    for (cMods = 0; (*modlist)[cMods] != NULL; cMods++) {
	if ((*modlist)[cMods]->mod_op == modop &&
	    strcasecmp((*modlist)[cMods]->mod_type, attribute) == 0) {
	    break;
	}
    }

    *pIndex = cMods;

    if ((*modlist)[cMods] == NULL) {
	LDAPMod *mod;

	*modlist = (LDAPMod **)ber_memrealloc(*modlist,
					      (cMods + 2) * sizeof(LDAPMod *));
	if (*modlist == NULL)
	    return ENOMEM;

	(*modlist)[cMods] = (LDAPMod *)ber_memalloc(sizeof(LDAPMod));
	if ((*modlist)[cMods] == NULL)
	    return ENOMEM;

	mod = (*modlist)[cMods];
	mod->mod_op = modop;
	mod->mod_type = ber_strdup(attribute);
	if (mod->mod_type == NULL) {
	    ber_memfree(mod);
	    (*modlist)[cMods] = NULL;
	    return ENOMEM;
	}

	if (modop & LDAP_MOD_BVALUES) {
	    mod->mod_bvalues = NULL;
	} else {
	    mod->mod_values = NULL;
	}

	(*modlist)[cMods + 1] = NULL;
    }

    return 0;
}

static krb5_error_code
LDAP_addmod_len(LDAPMod *** modlist, int modop, const char *attribute,
		unsigned char *value, size_t len)
{
    krb5_error_code ret;
    int cMods, i = 0;

    ret = LDAP__setmod(modlist, modop | LDAP_MOD_BVALUES, attribute, &cMods);
    if (ret)
	return ret;

    if (value != NULL) {
	struct berval **bv;

	bv = (*modlist)[cMods]->mod_bvalues;
	if (bv != NULL) {
	    for (i = 0; bv[i] != NULL; i++)
		;
	    bv = ber_memrealloc(bv, (i + 2) * sizeof(*bv));
	} else
	    bv = ber_memalloc(2 * sizeof(*bv));
	if (bv == NULL)
	    return ENOMEM;

	(*modlist)[cMods]->mod_bvalues = bv;

	bv[i] = ber_memalloc(sizeof(**bv));;
	if (bv[i] == NULL)
	    return ENOMEM;

	bv[i]->bv_val = (void *)value;
	bv[i]->bv_len = len;

	bv[i + 1] = NULL;
    }

    return 0;
}

static krb5_error_code
LDAP_addmod(LDAPMod *** modlist, int modop, const char *attribute,
	    const char *value)
{
    int cMods, i = 0;
    krb5_error_code ret;

    ret = LDAP__setmod(modlist, modop, attribute, &cMods);
    if (ret)
	return ret;

    if (value != NULL) {
	char **bv;

	bv = (*modlist)[cMods]->mod_values;
	if (bv != NULL) {
	    for (i = 0; bv[i] != NULL; i++)
		;
	    bv = ber_memrealloc(bv, (i + 2) * sizeof(*bv));
	} else
	    bv = ber_memalloc(2 * sizeof(*bv));
	if (bv == NULL)
	    return ENOMEM;

	(*modlist)[cMods]->mod_values = bv;

	bv[i] = ber_strdup(value);
	if (bv[i] == NULL)
	    return ENOMEM;

	bv[i + 1] = NULL;
    }

    return 0;
}

static krb5_error_code
LDAP_addmod_generalized_time(LDAPMod *** mods, int modop,
			     const char *attribute, KerberosTime * time)
{
    char buf[22];
    struct tm *tm;

    /* XXX not threadsafe */
    tm = gmtime(time);
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm);

    return LDAP_addmod(mods, modop, attribute, buf);
}

static krb5_error_code
LDAP_addmod_integer(krb5_context context,
		    LDAPMod *** mods, int modop,
		    const char *attribute, unsigned long l)
{
    krb5_error_code ret;
    char *buf;

    ret = asprintf(&buf, "%ld", l);
    if (ret < 0) {
	krb5_set_error_message(context, ENOMEM,
			       "asprintf: out of memory:");
	return ENOMEM;
    }
    ret = LDAP_addmod(mods, modop, attribute, buf);
    free (buf);
    return ret;
}

static krb5_error_code
LDAP_get_string_value(HDB * db, LDAPMessage * entry,
		      const char *attribute, char **ptr)
{
    struct berval **vals;

    vals = ldap_get_values_len(HDB2LDAP(db), entry, attribute);
    if (vals == NULL || vals[0] == NULL) {
	*ptr = NULL;
	return HDB_ERR_NOENTRY;
    }

    *ptr = malloc(vals[0]->bv_len + 1);
    if (*ptr == NULL) {
	ldap_value_free_len(vals);
	return ENOMEM;
    }

    memcpy(*ptr, vals[0]->bv_val, vals[0]->bv_len);
    (*ptr)[vals[0]->bv_len] = 0;

    ldap_value_free_len(vals);

    return 0;
}

static krb5_error_code
LDAP_get_integer_value(HDB * db, LDAPMessage * entry,
		       const char *attribute, int *ptr)
{
    krb5_error_code ret;
    char *val;

    ret = LDAP_get_string_value(db, entry, attribute, &val);
    if (ret)
	return ret;
    *ptr = atoi(val);
    free(val);
    return 0;
}

static krb5_error_code
LDAP_get_generalized_time_value(HDB * db, LDAPMessage * entry,
				const char *attribute, KerberosTime * kt)
{
    char *tmp, *gentime;
    struct tm tm;
    int ret;

    *kt = 0;

    ret = LDAP_get_string_value(db, entry, attribute, &gentime);
    if (ret)
	return ret;

    tmp = strptime(gentime, "%Y%m%d%H%M%SZ", &tm);
    if (tmp == NULL) {
	free(gentime);
	return HDB_ERR_NOENTRY;
    }

    free(gentime);

    *kt = timegm(&tm);

    return 0;
}

static int
bervalstrcmp(struct berval *v, const char *str)
{
    size_t len = strlen(str);
    return (v->bv_len == len) && strncasecmp(str, (char *)v->bv_val, len) == 0;
}


static krb5_error_code
LDAP_entry2mods(krb5_context context, HDB * db, hdb_entry * ent,
		LDAPMessage * msg, LDAPMod *** pmods, krb5_boolean *pis_new_entry)
{
    krb5_error_code ret;
    krb5_boolean is_new_entry = FALSE;
    char *tmp = NULL;
    LDAPMod **mods = NULL;
    hdb_entry orig;
    unsigned long oflags, nflags;
    int i;

    krb5_boolean is_samba_account = FALSE;
    krb5_boolean is_account = FALSE;
    krb5_boolean is_heimdal_entry = FALSE;
    krb5_boolean is_heimdal_principal = FALSE;

    struct berval **vals;

    *pmods = NULL;

    if (msg != NULL) {

	ret = LDAP_message2entry(context, db, msg, 0, &orig);
	if (ret)
	    goto out;

	vals = ldap_get_values_len(HDB2LDAP(db), msg, "objectClass");
	if (vals) {
	    int num_objectclasses = ldap_count_values_len(vals);
	    for (i=0; i < num_objectclasses; i++) {
		if (bervalstrcmp(vals[i], "sambaSamAccount"))
		    is_samba_account = TRUE;
		else if (bervalstrcmp(vals[i], structural_object))
		    is_account = TRUE;
		else if (bervalstrcmp(vals[i], "krb5Principal"))
		    is_heimdal_principal = TRUE;
		else if (bervalstrcmp(vals[i], "krb5KDCEntry"))
		    is_heimdal_entry = TRUE;
	    }
	    ldap_value_free_len(vals);
	}

	/*
	 * If this is just a "account" entry and no other objectclass
	 * is hanging on this entry, it's really a new entry.
	 */
	if (is_samba_account == FALSE && is_heimdal_principal == FALSE &&
	    is_heimdal_entry == FALSE) {
	    if (is_account == TRUE) {
		is_new_entry = TRUE;
	    } else {
		ret = HDB_ERR_NOENTRY;
		goto out;
	    }
	}
    } else
	is_new_entry = TRUE;

    if (is_new_entry) {

	/* to make it perfectly obvious we're depending on
	 * orig being intiialized to zero */
	memset(&orig, 0, sizeof(orig));

	/* account is the structural object class */
	if (is_account == FALSE) {
	    ret = LDAP_addmod(&mods, LDAP_MOD_ADD, "objectClass", "top");
	    if (ret)
		goto out;

	    ret = LDAP_addmod(&mods, LDAP_MOD_ADD, "objectClass",
			      structural_object);
	    is_account = TRUE;
	    if (ret)
		goto out;
	}

	ret = LDAP_addmod(&mods, LDAP_MOD_ADD, "objectClass", "krb5Principal");
	is_heimdal_principal = TRUE;
	if (ret)
	    goto out;

	ret = LDAP_addmod(&mods, LDAP_MOD_ADD, "objectClass", "krb5KDCEntry");
	is_heimdal_entry = TRUE;
	if (ret)
	    goto out;
    }

    if (is_new_entry ||
	krb5_principal_compare(context, ent->principal, orig.principal)
	== FALSE)
    {
	if (is_heimdal_principal || is_heimdal_entry) {

	    ret = krb5_unparse_name(context, ent->principal, &tmp);
	    if (ret)
		goto out;

	    ret = LDAP_addmod(&mods, LDAP_MOD_REPLACE,
			      "krb5PrincipalName", tmp);
	    if (ret) {
		free(tmp);
		goto out;
	    }
	    free(tmp);
	}

	if (is_account || is_samba_account) {
	    ret = krb5_unparse_name_short(context, ent->principal, &tmp);
	    if (ret)
		goto out;
	    ret = LDAP_addmod(&mods, LDAP_MOD_REPLACE, "uid", tmp);
	    if (ret) {
		free(tmp);
		goto out;
	    }
	    free(tmp);
	}
    }

    if (is_heimdal_entry && (ent->kvno != orig.kvno || is_new_entry)) {
	ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
			    "krb5KeyVersionNumber",
			    ent->kvno);
	if (ret)
	    goto out;
    }

    if (is_heimdal_entry && ent->extensions) {
	if (!is_new_entry) {
	    vals = ldap_get_values_len(HDB2LDAP(db), msg, "krb5ExtendedAttributes");
	    if (vals) {
		ldap_value_free_len(vals);
		ret = LDAP_addmod(&mods, LDAP_MOD_DELETE, "krb5ExtendedAttributes", NULL);
		if (ret)
		    goto out;
	    }
	}

	for (i = 0; i < ent->extensions->len; i++) {
	    unsigned char *buf;
	    size_t size, sz = 0;

	    ASN1_MALLOC_ENCODE(HDB_extension, buf, size, &ent->extensions->val[i], &sz, ret);
	    if (ret)
		goto out;
	    if (size != sz)
		krb5_abortx(context, "internal error in ASN.1 encoder");

	    ret = LDAP_addmod_len(&mods, LDAP_MOD_ADD, "krb5ExtendedAttributes", buf, sz);
	    if (ret)
		goto out;
	}
    }

    if (is_heimdal_entry && ent->valid_start) {
	if (orig.valid_end == NULL
	    || (*(ent->valid_start) != *(orig.valid_start))) {
	    ret = LDAP_addmod_generalized_time(&mods, LDAP_MOD_REPLACE,
					       "krb5ValidStart",
					       ent->valid_start);
	    if (ret)
		goto out;
	}
    }

    if (ent->valid_end) {
 	if (orig.valid_end == NULL || (*(ent->valid_end) != *(orig.valid_end))) {
	    if (is_heimdal_entry) {
		ret = LDAP_addmod_generalized_time(&mods, LDAP_MOD_REPLACE,
						   "krb5ValidEnd",
						   ent->valid_end);
		if (ret)
		    goto out;
            }
	    if (is_samba_account) {
		ret = LDAP_addmod_integer(context, &mods,  LDAP_MOD_REPLACE,
					  "sambaKickoffTime",
					  *(ent->valid_end));
		if (ret)
		    goto out;
	    }
   	}
    }

    if (ent->pw_end) {
	if (orig.pw_end == NULL || (*(ent->pw_end) != *(orig.pw_end))) {
	    if (is_heimdal_entry) {
		ret = LDAP_addmod_generalized_time(&mods, LDAP_MOD_REPLACE,
						   "krb5PasswordEnd",
						   ent->pw_end);
		if (ret)
		    goto out;
	    }

	    if (is_samba_account) {
		ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
					  "sambaPwdMustChange",
					  *(ent->pw_end));
		if (ret)
		    goto out;
	    }
	}
    }


#if 0 /* we we have last_pw_change */
    if (is_samba_account && ent->last_pw_change) {
	if (orig.last_pw_change == NULL || (*(ent->last_pw_change) != *(orig.last_pw_change))) {
	    ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
				      "sambaPwdLastSet",
				      *(ent->last_pw_change));
	    if (ret)
		goto out;
	}
    }
#endif

    if (is_heimdal_entry && ent->max_life) {
	if (orig.max_life == NULL
	    || (*(ent->max_life) != *(orig.max_life))) {

	    ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
				      "krb5MaxLife",
				      *(ent->max_life));
	    if (ret)
		goto out;
	}
    }

    if (is_heimdal_entry && ent->max_renew) {
	if (orig.max_renew == NULL
	    || (*(ent->max_renew) != *(orig.max_renew))) {

	    ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
				      "krb5MaxRenew",
				      *(ent->max_renew));
	    if (ret)
		goto out;
	}
    }

    oflags = HDBFlags2int(orig.flags);
    nflags = HDBFlags2int(ent->flags);

    if (is_heimdal_entry && oflags != nflags) {

	ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
				  "krb5KDCFlags",
				  nflags);
	if (ret)
	    goto out;
    }

    /* Remove keys if they exists, and then replace keys. */
    if (!is_new_entry && orig.keys.len > 0) {
	vals = ldap_get_values_len(HDB2LDAP(db), msg, "krb5Key");
	if (vals) {
	    ldap_value_free_len(vals);

	    ret = LDAP_addmod(&mods, LDAP_MOD_DELETE, "krb5Key", NULL);
	    if (ret)
		goto out;
	}
    }

    for (i = 0; i < ent->keys.len; i++) {

	if (is_samba_account
	    && ent->keys.val[i].key.keytype == ETYPE_ARCFOUR_HMAC_MD5) {
	    char *ntHexPassword;
	    char *nt;
	    time_t now = time(NULL);

	    /* the key might have been 'sealed', but samba passwords
	       are clear in the directory */
	    ret = hdb_unseal_key(context, db, &ent->keys.val[i]);
	    if (ret)
		goto out;

	    nt = ent->keys.val[i].key.keyvalue.data;
	    /* store in ntPassword, not krb5key */
	    ret = hex_encode(nt, 16, &ntHexPassword);
	    if (ret < 0) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "hdb-ldap: failed to "
				      "hex encode key");
		goto out;
	    }
	    ret = LDAP_addmod(&mods, LDAP_MOD_REPLACE, "sambaNTPassword",
			      ntHexPassword);
	    free(ntHexPassword);
	    if (ret)
		goto out;
	    ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_REPLACE,
				      "sambaPwdLastSet", now);
	    if (ret)
		goto out;

	    /* have to kill the LM passwod if it exists */
	    vals = ldap_get_values_len(HDB2LDAP(db), msg, "sambaLMPassword");
	    if (vals) {
		ldap_value_free_len(vals);
		ret = LDAP_addmod(&mods, LDAP_MOD_DELETE,
				  "sambaLMPassword", NULL);
		if (ret)
		    goto out;
	    }

	} else if (is_heimdal_entry) {
	    unsigned char *buf;
	    size_t len, buf_size;

	    ASN1_MALLOC_ENCODE(Key, buf, buf_size, &ent->keys.val[i], &len, ret);
	    if (ret)
		goto out;
	    if(buf_size != len)
		krb5_abortx(context, "internal error in ASN.1 encoder");

	    /* addmod_len _owns_ the key, doesn't need to copy it */
	    ret = LDAP_addmod_len(&mods, LDAP_MOD_ADD, "krb5Key", buf, len);
	    if (ret)
		goto out;
	}
    }

    if (ent->etypes) {
	int add_krb5EncryptionType = 0;

	/*
	 * Only add/modify krb5EncryptionType if it's a new heimdal
	 * entry or krb5EncryptionType already exists on the entry.
	 */

	if (!is_new_entry) {
	    vals = ldap_get_values_len(HDB2LDAP(db), msg, "krb5EncryptionType");
	    if (vals) {
		ldap_value_free_len(vals);
		ret = LDAP_addmod(&mods, LDAP_MOD_DELETE, "krb5EncryptionType",
				  NULL);
		if (ret)
		    goto out;
		add_krb5EncryptionType = 1;
	    }
	} else if (is_heimdal_entry)
	    add_krb5EncryptionType = 1;

	if (add_krb5EncryptionType) {
	    for (i = 0; i < ent->etypes->len; i++) {
		if (is_samba_account &&
		    ent->keys.val[i].key.keytype == ETYPE_ARCFOUR_HMAC_MD5)
		{
		    ;
		} else if (is_heimdal_entry) {
		    ret = LDAP_addmod_integer(context, &mods, LDAP_MOD_ADD,
					      "krb5EncryptionType",
					      ent->etypes->val[i]);
		    if (ret)
			goto out;
		}
	    }
	}
    }

    /* for clarity */
    ret = 0;

 out:

    *pis_new_entry = is_new_entry;

    if (ret == 0)
	*pmods = mods;
    else if (mods != NULL) {
	ldap_mods_free(mods, 1);
	*pmods = NULL;
    }

    if (msg)
	hdb_free_entry(context, db, &orig);

    return ret;
}

static krb5_error_code
LDAP_dn2principal(krb5_context context, HDB * db, const char *dn,
		  krb5_principal * principal)
{
    krb5_error_code ret;
    int rc;
    const char *filter = "(objectClass=krb5Principal)";
    LDAPMessage *res = NULL, *e;
    char *p;

    ret = LDAP_no_size_limit(context, HDB2LDAP(db));
    if (ret)
	goto out;

    rc = ldap_search_ext_s(HDB2LDAP(db), dn, LDAP_SCOPE_SUBTREE,
			   filter, krb5principal_attrs, 0,
			   NULL, NULL, NULL,
			   0, &res);
    if (check_ldap(context, db, rc)) {
	ret = HDB_ERR_NOENTRY;
	krb5_set_error_message(context, ret, "ldap_search_ext_s: "
			       "filter: %s error: %s",
			       filter, ldap_err2string(rc));
	goto out;
    }

    e = ldap_first_entry(HDB2LDAP(db), res);
    if (e == NULL) {
	ret = HDB_ERR_NOENTRY;
	goto out;
    }

    ret = LDAP_get_string_value(db, e, "krb5PrincipalName", &p);
    if (ret) {
	ret = HDB_ERR_NOENTRY;
	goto out;
    }

    ret = krb5_parse_name(context, p, principal);
    free(p);

  out:
    if (res)
	ldap_msgfree(res);

    return ret;
}

static int
need_quote(unsigned char c)
{
    return (c & 0x80) ||
	(c < 32) ||
	(c == '(') ||
	(c == ')') ||
	(c == '*') ||
	(c == '\\') ||
	(c == 0x7f);
}

static const char hexchar[] = "0123456789ABCDEF";

static krb5_error_code
escape_value(krb5_context context, const char *unquoted, char **quoted)
{
    size_t i, len;

    for (i = 0, len = 0; unquoted[i] != '\0'; i++, len++) {
	if (need_quote((unsigned char)unquoted[i]))
	    len += 2;
    }

    *quoted = malloc(len + 1);
    if (*quoted == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    for (i = 0; unquoted[0] ; unquoted++) {
	if (need_quote((unsigned char)unquoted[0])) {
	    (*quoted)[i++] = '\\';
	    (*quoted)[i++] = hexchar[(unquoted[0] >> 4) & 0xf];
	    (*quoted)[i++] = hexchar[(unquoted[0]     ) & 0xf];
	} else
	    (*quoted)[i++] = (char)unquoted[0];
    }
    (*quoted)[i] = '\0';
    return 0;
}


static krb5_error_code
LDAP__lookup_princ(krb5_context context,
		   HDB *db,
		   const char *princname,
		   const char *userid,
		   LDAPMessage **msg)
{
    krb5_error_code ret;
    int rc;
    char *quote, *filter = NULL;

    ret = LDAP__connect(context, db);
    if (ret)
	return ret;

    /*
     * Quote searches that contain filter language, this quote
     * searches for *@REALM, which takes very long time.
     */

    ret = escape_value(context, princname, &quote);
    if (ret)
	goto out;

    rc = asprintf(&filter,
		  "(&(objectClass=krb5Principal)(krb5PrincipalName=%s))",
		  quote);
    free(quote);

    if (rc < 0) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, "malloc: out of memory");
	goto out;
    }

    ret = LDAP_no_size_limit(context, HDB2LDAP(db));
    if (ret)
	goto out;

    rc = ldap_search_ext_s(HDB2LDAP(db), HDB2BASE(db),
			   LDAP_SCOPE_SUBTREE, filter,
			   krb5kdcentry_attrs, 0,
			   NULL, NULL, NULL,
			   0, msg);
    if (check_ldap(context, db, rc)) {
	ret = HDB_ERR_NOENTRY;
	krb5_set_error_message(context, ret, "ldap_search_ext_s: "
			      "filter: %s - error: %s",
			      filter, ldap_err2string(rc));
	goto out;
    }

    if (userid && ldap_count_entries(HDB2LDAP(db), *msg) == 0) {
	free(filter);
	filter = NULL;
	ldap_msgfree(*msg);
	*msg = NULL;

	ret = escape_value(context, userid, &quote);
	if (ret)
	    goto out;

	rc = asprintf(&filter,
	    "(&(|(objectClass=sambaSamAccount)(objectClass=%s))(uid=%s))",
		      structural_object, quote);
	free(quote);
	if (rc < 0) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "asprintf: out of memory");
	    goto out;
	}

	ret = LDAP_no_size_limit(context, HDB2LDAP(db));
	if (ret)
	    goto out;

	rc = ldap_search_ext_s(HDB2LDAP(db), HDB2BASE(db), LDAP_SCOPE_SUBTREE,
			       filter, krb5kdcentry_attrs, 0,
			       NULL, NULL, NULL,
			       0, msg);
	if (check_ldap(context, db, rc)) {
	    ret = HDB_ERR_NOENTRY;
	    krb5_set_error_message(context, ret,
				   "ldap_search_ext_s: filter: %s error: %s",
				   filter, ldap_err2string(rc));
	    goto out;
	}
    }

    ret = 0;

  out:
    if (filter)
	free(filter);

    return ret;
}

static krb5_error_code
LDAP_principal2message(krb5_context context, HDB * db,
		       krb5_const_principal princ, LDAPMessage ** msg)
{
    char *name, *name_short = NULL;
    krb5_error_code ret;
    krb5_realm *r, *r0;

    *msg = NULL;

    ret = krb5_unparse_name(context, princ, &name);
    if (ret)
	return ret;

    ret = krb5_get_default_realms(context, &r0);
    if(ret) {
	free(name);
	return ret;
    }
    for (r = r0; *r != NULL; r++) {
	if(strcmp(krb5_principal_get_realm(context, princ), *r) == 0) {
	    ret = krb5_unparse_name_short(context, princ, &name_short);
	    if (ret) {
		krb5_free_host_realm(context, r0);
		free(name);
		return ret;
	    }
	    break;
	}
    }
    krb5_free_host_realm(context, r0);

    ret = LDAP__lookup_princ(context, db, name, name_short, msg);
    free(name);
    free(name_short);

    return ret;
}

/*
 * Construct an hdb_entry from a directory entry.
 */
static krb5_error_code
LDAP_message2entry(krb5_context context, HDB * db, LDAPMessage * msg,
		   int flags, hdb_entry * ent)
{
    char *unparsed_name = NULL, *dn = NULL, *ntPasswordIN = NULL;
    char *samba_acct_flags = NULL;
    struct berval **keys;
    struct berval **extensions;
    struct berval **vals;
    int tmp, tmp_time, i, ret, have_arcfour = 0;

    memset(ent, 0, sizeof(*ent));
    ent->flags = int2HDBFlags(0);

    ret = LDAP_get_string_value(db, msg, "krb5PrincipalName", &unparsed_name);
    if (ret == 0) {
	ret = krb5_parse_name(context, unparsed_name, &ent->principal);
	if (ret)
	    goto out;
    } else {
	ret = LDAP_get_string_value(db, msg, "uid",
				    &unparsed_name);
	if (ret == 0) {
	    ret = krb5_parse_name(context, unparsed_name, &ent->principal);
	    if (ret)
		goto out;
	} else {
	    krb5_set_error_message(context, HDB_ERR_NOENTRY,
				   "hdb-ldap: ldap entry missing"
				  "principal name");
	    return HDB_ERR_NOENTRY;
	}
    }

    {
	int integer;
	ret = LDAP_get_integer_value(db, msg, "krb5KeyVersionNumber",
				     &integer);
	if (ret)
	    ent->kvno = 0;
	else
	    ent->kvno = integer;
    }

    keys = ldap_get_values_len(HDB2LDAP(db), msg, "krb5Key");
    if (keys != NULL) {
	size_t l;

	ent->keys.len = ldap_count_values_len(keys);
	ent->keys.val = (Key *) calloc(ent->keys.len, sizeof(Key));
	if (ent->keys.val == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "calloc: out of memory");
	    goto out;
	}
	for (i = 0; i < ent->keys.len; i++) {
	    decode_Key((unsigned char *) keys[i]->bv_val,
		       (size_t) keys[i]->bv_len, &ent->keys.val[i], &l);
	}
	ber_bvecfree(keys);
    } else {
#if 1
	/*
	 * This violates the ASN1 but it allows a principal to
	 * be related to a general directory entry without creating
	 * the keys. Hopefully it's OK.
	 */
	ent->keys.len = 0;
	ent->keys.val = NULL;
#else
	ret = HDB_ERR_NOENTRY;
	goto out;
#endif
    }

    extensions = ldap_get_values_len(HDB2LDAP(db), msg, "krb5ExtendedAttributes");
    if (extensions != NULL) {
	size_t l;

	ent->extensions = calloc(1, sizeof(*(ent->extensions)));
	if (ent->extensions == NULL) {
	    ret = krb5_enomem(context);
	    goto out;
	}
	ent->extensions->len = ldap_count_values_len(extensions);
	ent->extensions->val = (HDB_extension *) calloc(ent->extensions->len, sizeof(HDB_extension));
	if (ent->extensions->val == NULL) {
	    ent->extensions->len = 0;
	    ret = krb5_enomem(context);
	    goto out;
	}
	for (i = 0; i < ent->extensions->len; i++) {
	    ret = decode_HDB_extension((unsigned char *) extensions[i]->bv_val,
		       (size_t) extensions[i]->bv_len, &ent->extensions->val[i], &l);
	    if (ret)
		krb5_set_error_message(context, ret, "decode_HDB_extension failed");
	}
	ber_bvecfree(extensions);
    } else {
	ent->extensions = NULL;
    }

    vals = ldap_get_values_len(HDB2LDAP(db), msg, "krb5EncryptionType");
    if (vals != NULL) {
	ent->etypes = malloc(sizeof(*(ent->etypes)));
	if (ent->etypes == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret,"malloc: out of memory");
	    goto out;
	}
	ent->etypes->len = ldap_count_values_len(vals);
	ent->etypes->val = calloc(ent->etypes->len,
                                        sizeof(ent->etypes->val[0]));
	if (ent->etypes->val == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    ent->etypes->len = 0;
	    goto out;
	}
	for (i = 0; i < ent->etypes->len; i++) {
	    char *buf;

	    buf = malloc(vals[i]->bv_len + 1);
	    if (buf == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "malloc: out of memory");
		goto out;
	    }
	    memcpy(buf, vals[i]->bv_val, vals[i]->bv_len);
	    buf[vals[i]->bv_len] = '\0';
	    ent->etypes->val[i] = atoi(buf);
	    free(buf);
	}
	ldap_value_free_len(vals);
    }

    for (i = 0; i < ent->keys.len; i++) {
	if (ent->keys.val[i].key.keytype == ETYPE_ARCFOUR_HMAC_MD5) {
	    have_arcfour = 1;
	    break;
	}
    }

    /* manually construct the NT (type 23) key */
    ret = LDAP_get_string_value(db, msg, "sambaNTPassword", &ntPasswordIN);
    if (ret == 0 && have_arcfour == 0) {
	unsigned *etypes;
        Key *ks;

	ks = realloc(ent->keys.val,
		     (ent->keys.len + 1) *
                     sizeof(ent->keys.val[0]));
	if (ks == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    goto out;
	}
	ent->keys.val = ks;
	memset(&ent->keys.val[ent->keys.len], 0, sizeof(Key));
	ent->keys.val[ent->keys.len].key.keytype = ETYPE_ARCFOUR_HMAC_MD5;
	ret = krb5_data_alloc (&ent->keys.val[ent->keys.len].key.keyvalue, 16);
	if (ret) {
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    ret = ENOMEM;
	    goto out;
	}
	ret = hex_decode(ntPasswordIN,
			 ent->keys.val[ent->keys.len].key.keyvalue.data, 16);
	ent->keys.len++;
        if (ret == -1) {
            krb5_set_error_message(context, ret = EINVAL,
                                   "invalid hex encoding of password");
            goto out;
        }

	if (ent->etypes == NULL) {
	    ent->etypes = malloc(sizeof(*(ent->etypes)));
	    if (ent->etypes == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "malloc: out of memory");
		goto out;
	    }
	    ent->etypes->val = NULL;
	    ent->etypes->len = 0;
	}

	for (i = 0; i < ent->etypes->len; i++)
	    if (ent->etypes->val[i] == ETYPE_ARCFOUR_HMAC_MD5)
		break;
	/* If there is no ARCFOUR enctype, add one */
	if (i == ent->etypes->len) {
	    etypes = realloc(ent->etypes->val,
			     (ent->etypes->len + 1) *
			     sizeof(ent->etypes->val[0]));
	    if (etypes == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "malloc: out of memory");
		goto out;
	    }
	    ent->etypes->val = etypes;
	    ent->etypes->val[ent->etypes->len] =
		ETYPE_ARCFOUR_HMAC_MD5;
	    ent->etypes->len++;
	}
    }

    ret = LDAP_get_generalized_time_value(db, msg, "createTimestamp",
					  &ent->created_by.time);
    if (ret)
	ent->created_by.time = time(NULL);

    ent->created_by.principal = NULL;

    if (flags & HDB_F_ADMIN_DATA) {
	ret = LDAP_get_string_value(db, msg, "creatorsName", &dn);
	if (ret == 0) {
	    LDAP_dn2principal(context, db, dn, &ent->created_by.principal);
	    free(dn);
	}

	ent->modified_by = calloc(1, sizeof(*ent->modified_by));
	if (ent->modified_by == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    goto out;
	}

	ret = LDAP_get_generalized_time_value(db, msg, "modifyTimestamp",
					      &ent->modified_by->time);
	if (ret == 0) {
	    ret = LDAP_get_string_value(db, msg, "modifiersName", &dn);
	    if (ret == 0) {
		LDAP_dn2principal(context, db, dn, &ent->modified_by->principal);
		free(dn);
	    } else {
		free(ent->modified_by);
		ent->modified_by = NULL;
	    }
	}
    }

    ent->valid_start = malloc(sizeof(*ent->valid_start));
    if (ent->valid_start == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, "malloc: out of memory");
	goto out;
    }
    ret = LDAP_get_generalized_time_value(db, msg, "krb5ValidStart",
					  ent->valid_start);
    if (ret) {
	/* OPTIONAL */
	free(ent->valid_start);
	ent->valid_start = NULL;
    }

    ent->valid_end = malloc(sizeof(*ent->valid_end));
    if (ent->valid_end == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, "malloc: out of memory");
	goto out;
    }
    ret = LDAP_get_generalized_time_value(db, msg, "krb5ValidEnd",
					  ent->valid_end);
    if (ret) {
	/* OPTIONAL */
	free(ent->valid_end);
	ent->valid_end = NULL;
    }

    ret = LDAP_get_integer_value(db, msg, "sambaKickoffTime", &tmp_time);
    if (ret == 0) {
 	if (ent->valid_end == NULL) {
 	    ent->valid_end = malloc(sizeof(*ent->valid_end));
 	    if (ent->valid_end == NULL) {
 		ret = ENOMEM;
 		krb5_set_error_message(context, ret, "malloc: out of memory");
 		goto out;
 	    }
 	}
 	*ent->valid_end = tmp_time;
    }

    ent->pw_end = malloc(sizeof(*ent->pw_end));
    if (ent->pw_end == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(context, ret, "malloc: out of memory");
	goto out;
    }
    ret = LDAP_get_generalized_time_value(db, msg, "krb5PasswordEnd",
					  ent->pw_end);
    if (ret) {
	/* OPTIONAL */
	free(ent->pw_end);
	ent->pw_end = NULL;
    }

    ret = LDAP_get_integer_value(db, msg, "sambaPwdLastSet", &tmp_time);
    if (ret == 0) {
	time_t delta;

	delta = krb5_config_get_time_default(context, NULL,
					     0,
					     "kadmin",
					     "password_lifetime",
					     NULL);

	if (delta) {
		if (ent->pw_end == NULL) {
		    ent->pw_end = malloc(sizeof(*ent->pw_end));
		    if (ent->pw_end == NULL) {
			ret = ENOMEM;
			krb5_set_error_message(context, ret, "malloc: out of memory");
			goto out;
		    }
		}

		*ent->pw_end = tmp_time + delta;
	}
    }

    ret = LDAP_get_integer_value(db, msg, "sambaPwdMustChange", &tmp_time);
    if (ret == 0) {
	if (ent->pw_end == NULL) {
	    ent->pw_end = malloc(sizeof(*ent->pw_end));
	    if (ent->pw_end == NULL) {
		ret = ENOMEM;
		krb5_set_error_message(context, ret, "malloc: out of memory");
		goto out;
	    }
	}
	*ent->pw_end = tmp_time;
    }

    /* OPTIONAL */
    ret = LDAP_get_integer_value(db, msg, "sambaPwdLastSet", &tmp_time);
    if (ret == 0)
	hdb_entry_set_pw_change_time(context, ent, tmp_time);

    {
	int max_life;

	ent->max_life = malloc(sizeof(*ent->max_life));
	if (ent->max_life == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    goto out;
	}
	ret = LDAP_get_integer_value(db, msg, "krb5MaxLife", &max_life);
	if (ret) {
	    free(ent->max_life);
	    ent->max_life = NULL;
	} else
	    *ent->max_life = max_life;
    }

    {
	int max_renew;

	ent->max_renew = malloc(sizeof(*ent->max_renew));
	if (ent->max_renew == NULL) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "malloc: out of memory");
	    goto out;
	}
	ret = LDAP_get_integer_value(db, msg, "krb5MaxRenew", &max_renew);
	if (ret) {
	    free(ent->max_renew);
	    ent->max_renew = NULL;
	} else
	    *ent->max_renew = max_renew;
    }

    ret = LDAP_get_integer_value(db, msg, "krb5KDCFlags", &tmp);
    if (ret)
	tmp = 0;

    ent->flags = int2HDBFlags(tmp);

    /* Try and find Samba flags to put into the mix */
    ret = LDAP_get_string_value(db, msg, "sambaAcctFlags", &samba_acct_flags);
    if (ret == 0) {
	/* parse the [UXW...] string:

	   'N'    No password
	   'D'    Disabled
	   'H'    Homedir required
	   'T'    Temp account.
	   'U'    User account (normal)
	   'M'    MNS logon user account - what is this ?
	   'W'    Workstation account
	   'S'    Server account
	   'L'    Locked account
	   'X'    No Xpiry on password
	   'I'    Interdomain trust account

	*/

	int flags_len = strlen(samba_acct_flags);

	if (flags_len < 2)
	    goto out2;

	if (samba_acct_flags[0] != '['
	    || samba_acct_flags[flags_len - 1] != ']')
	    goto out2;

	/* Allow forwarding */
	if (samba_forwardable)
	    ent->flags.forwardable = TRUE;

	for (i=0; i < flags_len; i++) {
	    switch (samba_acct_flags[i]) {
	    case ' ':
	    case '[':
	    case ']':
		break;
	    case 'N':
		/* how to handle no password in kerberos? */
		break;
	    case 'D':
		ent->flags.invalid = TRUE;
		break;
	    case 'H':
		break;
	    case 'T':
		/* temp duplicate */
		ent->flags.invalid = TRUE;
		break;
	    case 'U':
		ent->flags.client = TRUE;
		break;
	    case 'M':
		break;
	    case 'W':
	    case 'S':
		ent->flags.server = TRUE;
		ent->flags.client = TRUE;
		break;
	    case 'L':
		ent->flags.invalid = TRUE;
		break;
	    case 'X':
		if (ent->pw_end) {
		    free(ent->pw_end);
		    ent->pw_end = NULL;
		}
		break;
	    case 'I':
		ent->flags.server = TRUE;
		ent->flags.client = TRUE;
		break;
	    }
	}
    out2:
	free(samba_acct_flags);
    }

    ret = 0;

out:
    free(unparsed_name);
    free(ntPasswordIN);

    if (ret)
	hdb_free_entry(context, db, ent);

    return ret;
}

static krb5_error_code
LDAP_close(krb5_context context, HDB * db)
{
    if (HDB2LDAP(db)) {
	ldap_unbind_ext(HDB2LDAP(db), NULL, NULL);
	((struct hdbldapdb *)db->hdb_db)->h_lp = NULL;
    }

    return 0;
}

static krb5_error_code
LDAP_lock(krb5_context context, HDB * db, int operation)
{
    return 0;
}

static krb5_error_code
LDAP_unlock(krb5_context context, HDB * db)
{
    return 0;
}

static krb5_error_code
LDAP_seq(krb5_context context, HDB * db, unsigned flags, hdb_entry * entry)
{
    int msgid, rc, parserc;
    krb5_error_code ret;
    LDAPMessage *e;

    msgid = HDB2MSGID(db);
    if (msgid < 0)
	return HDB_ERR_NOENTRY;

    do {
	rc = ldap_result(HDB2LDAP(db), msgid, LDAP_MSG_ONE, NULL, &e);
	switch (rc) {
	case LDAP_RES_SEARCH_REFERENCE:
	    ldap_msgfree(e);
	    ret = 0;
	    break;
	case LDAP_RES_SEARCH_ENTRY:
	    /* We have an entry. Parse it. */
	    ret = LDAP_message2entry(context, db, e, flags, entry);
	    ldap_msgfree(e);
	    break;
	case LDAP_RES_SEARCH_RESULT:
	    /* We're probably at the end of the results. If not, abandon. */
	    parserc =
		ldap_parse_result(HDB2LDAP(db), e, NULL, NULL, NULL,
				  NULL, NULL, 1);
	    ret = HDB_ERR_NOENTRY;
	    if (parserc != LDAP_SUCCESS
		&& parserc != LDAP_MORE_RESULTS_TO_RETURN) {
	        krb5_set_error_message(context, ret, "ldap_parse_result: %s",
				       ldap_err2string(parserc));
		ldap_abandon_ext(HDB2LDAP(db), msgid, NULL, NULL);
	    }
	    HDBSETMSGID(db, -1);
	    break;
	case LDAP_SERVER_DOWN:
	    ldap_msgfree(e);
	    LDAP_close(context, db);
	    HDBSETMSGID(db, -1);
	    ret = ENETDOWN;
	    break;
	default:
	    /* Some unspecified error (timeout?). Abandon. */
	    ldap_msgfree(e);
	    ldap_abandon_ext(HDB2LDAP(db), msgid, NULL, NULL);
	    ret = HDB_ERR_NOENTRY;
	    HDBSETMSGID(db, -1);
	    break;
	}
    } while (rc == LDAP_RES_SEARCH_REFERENCE);

    if (ret == 0) {
	if (db->hdb_master_key_set && (flags & HDB_F_DECRYPT)) {
	    ret = hdb_unseal_keys(context, db, entry);
	    if (ret)
		hdb_free_entry(context, db, entry);
	}
    }

    return ret;
}

static krb5_error_code
LDAP_firstkey(krb5_context context, HDB *db, unsigned flags,
	      hdb_entry *entry)
{
    krb5_error_code ret;
    int msgid;

    ret = LDAP__connect(context, db);
    if (ret)
	return ret;

    ret = LDAP_no_size_limit(context, HDB2LDAP(db));
    if (ret)
	return ret;

    ret = ldap_search_ext(HDB2LDAP(db), HDB2BASE(db),
			LDAP_SCOPE_SUBTREE,
			"(|(objectClass=krb5Principal)(objectClass=sambaSamAccount))",
			krb5kdcentry_attrs, 0,
			NULL, NULL, NULL, 0, &msgid);
    if (ret != LDAP_SUCCESS || msgid < 0)
	return HDB_ERR_NOENTRY;

    HDBSETMSGID(db, msgid);

    return LDAP_seq(context, db, flags, entry);
}

static krb5_error_code
LDAP_nextkey(krb5_context context, HDB * db, unsigned flags,
	     hdb_entry * entry)
{
    return LDAP_seq(context, db, flags, entry);
}

static krb5_error_code
LDAP__connect(krb5_context context, HDB * db)
{
    int rc, version = LDAP_VERSION3;
    /*
     * Empty credentials to do a SASL bind with LDAP. Note that empty
     * different from NULL credentials. If you provide NULL
     * credentials instead of empty credentials you will get a SASL
     * bind in progress message.
     */
    struct berval bv = { 0, "" };
    const char *sasl_method = "EXTERNAL";
    const char *bind_dn = NULL;

    if (HDB2BINDDN(db) != NULL && HDB2BINDPW(db) != NULL) {
	/* A bind DN was specified; use SASL SIMPLE */
	bind_dn = HDB2BINDDN(db);
	sasl_method = LDAP_SASL_SIMPLE;
	bv.bv_val = HDB2BINDPW(db);
	bv.bv_len = strlen(bv.bv_val);
    }

    if (HDB2LDAP(db)) {
	/* connection has been opened. ping server. */
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sd;

	if (ldap_get_option(HDB2LDAP(db), LDAP_OPT_DESC, &sd) == 0 &&
	    getpeername(sd, (struct sockaddr *) &addr, &len) < 0) {
	    /* the other end has died. reopen. */
	    LDAP_close(context, db);
	}
    }

    if (HDB2LDAP(db) != NULL) /* server is UP */
	return 0;

    rc = ldap_initialize(&((struct hdbldapdb *)db->hdb_db)->h_lp, HDB2URL(db));
    if (rc != LDAP_SUCCESS) {
	krb5_set_error_message(context, HDB_ERR_NOENTRY, "ldap_initialize: %s",
			       ldap_err2string(rc));
	return HDB_ERR_NOENTRY;
    }

    rc = ldap_set_option(HDB2LDAP(db), LDAP_OPT_PROTOCOL_VERSION,
			 (const void *)&version);
    if (rc != LDAP_SUCCESS) {
	krb5_set_error_message(context, HDB_ERR_BADVERSION,
			       "ldap_set_option: %s", ldap_err2string(rc));
	LDAP_close(context, db);
	return HDB_ERR_BADVERSION;
    }

    if (((struct hdbldapdb *)db->hdb_db)->h_start_tls) {
	rc = ldap_start_tls_s(HDB2LDAP(db), NULL, NULL);

	if (rc != LDAP_SUCCESS) {
	    krb5_set_error_message(context, HDB_ERR_BADVERSION,
				   "ldap_start_tls_s: %s", ldap_err2string(rc));
	    LDAP_close(context, db);
	    return HDB_ERR_BADVERSION;
	}
    }

    rc = ldap_sasl_bind_s(HDB2LDAP(db), bind_dn, sasl_method, &bv,
			  NULL, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
	krb5_set_error_message(context, HDB_ERR_BADVERSION,
			      "ldap_sasl_bind_s: %s", ldap_err2string(rc));
	LDAP_close(context, db);
	return HDB_ERR_BADVERSION;
    }

    return 0;
}

static krb5_error_code
LDAP_open(krb5_context context, HDB * db, int flags, mode_t mode)
{
    /* Not the right place for this. */
#ifdef HAVE_SIGACTION
    struct sigaction sa;

    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGPIPE, &sa, NULL);
#else
    signal(SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGACTION */

    return LDAP__connect(context, db);
}

static krb5_error_code
LDAP_fetch_kvno(krb5_context context, HDB * db, krb5_const_principal principal,
		unsigned flags, krb5_kvno kvno, hdb_entry * entry)
{
    LDAPMessage *msg, *e;
    krb5_error_code ret;

    ret = LDAP_principal2message(context, db, principal, &msg);
    if (ret)
	return ret;

    e = ldap_first_entry(HDB2LDAP(db), msg);
    if (e == NULL) {
	ret = HDB_ERR_NOENTRY;
	goto out;
    }

    ret = LDAP_message2entry(context, db, e, flags, entry);
    if (ret == 0) {
	if (db->hdb_master_key_set && (flags & HDB_F_DECRYPT)) {
	    ret = hdb_unseal_keys(context, db, entry);
	    if (ret)
		hdb_free_entry(context, db, entry);
	}
    }

  out:
    ldap_msgfree(msg);

    return ret;
}

#if 0
static krb5_error_code
LDAP_fetch(krb5_context context, HDB * db, krb5_const_principal principal,
	   unsigned flags, hdb_entry * entry)
{
    return LDAP_fetch_kvno(context, db, principal,
			   flags & (~HDB_F_KVNO_SPECIFIED), 0, entry);
}
#endif

static krb5_error_code
LDAP_store(krb5_context context, HDB * db, unsigned flags,
	   hdb_entry * entry)
{
    LDAPMod **mods = NULL;
    krb5_error_code ret;
    const char *errfn;
    int rc;
    LDAPMessage *msg = NULL, *e = NULL;
    char *dn = NULL, *name = NULL;
    krb5_boolean is_new_entry;

    if ((flags & HDB_F_PRECHECK))
        return 0; /* we can't guarantee whether we'll be able to perform it */

    ret = LDAP_principal2message(context, db, entry->principal, &msg);
    if (ret == 0)
	e = ldap_first_entry(HDB2LDAP(db), msg);

    ret = krb5_unparse_name(context, entry->principal, &name);
    if (ret) {
	free(name);
	return ret;
    }

    ret = hdb_seal_keys(context, db, entry);
    if (ret)
	goto out;

    /* turn new entry into LDAPMod array */
    ret = LDAP_entry2mods(context, db, entry, e, &mods, &is_new_entry);
    if (ret)
	goto out;

    if (e == NULL) {
	ret = asprintf(&dn, "krb5PrincipalName=%s,%s", name, HDB2CREATE(db));
	if (ret < 0) {
	    ret = ENOMEM;
	    krb5_set_error_message(context, ret, "asprintf: out of memory");
	    goto out;
	}
    } else if ((flags & HDB_F_REPLACE) || (is_new_entry)) {
	/* Entry exists, and we're allowed to replace it. */
	/* Entry may also exist but need to be modified to create a new principal. */
	dn = ldap_get_dn(HDB2LDAP(db), e);
    } else {
	/* Entry exists, but we're not allowed to replace it. Bail. */
	ret = HDB_ERR_EXISTS;
	goto out;
    }

    /* write entry into directory */
    if (e == NULL) {
	/* didn't exist before */
	rc = ldap_add_ext_s(HDB2LDAP(db), dn, mods, NULL, NULL );
	errfn = "ldap_add_ext_s";
    } else {
	/* already existed, send deltas only */
	rc = ldap_modify_ext_s(HDB2LDAP(db), dn, mods, NULL, NULL );
	errfn = "ldap_modify_ext_s";
    }

    if (check_ldap(context, db, rc)) {
	char *ld_error = NULL;
	ldap_get_option(HDB2LDAP(db), LDAP_OPT_ERROR_STRING,
			&ld_error);
	ret = HDB_ERR_CANT_LOCK_DB;
	krb5_set_error_message(context, ret, "%s: %s (DN=%s) %s: %s",
			      errfn, name, dn, ldap_err2string(rc), ld_error);
    } else
	ret = 0;

  out:
    /* free stuff */
    if (dn)
	free(dn);
    if (msg)
	ldap_msgfree(msg);
    if (mods)
	ldap_mods_free(mods, 1);
    if (name)
	free(name);

    return ret;
}

static krb5_error_code
LDAP_remove(krb5_context context, HDB *db,
            unsigned flags, krb5_const_principal principal)
{
    krb5_error_code ret;
    LDAPMessage *msg, *e;
    char *dn = NULL;
    int rc, limit = LDAP_NO_LIMIT;

    if ((flags & HDB_F_PRECHECK))
        return 0; /* we can't guarantee whether we'll be able to perform it */

    ret = LDAP_principal2message(context, db, principal, &msg);
    if (ret)
	goto out;

    e = ldap_first_entry(HDB2LDAP(db), msg);
    if (e == NULL) {
	ret = HDB_ERR_NOENTRY;
	goto out;
    }

    dn = ldap_get_dn(HDB2LDAP(db), e);
    if (dn == NULL) {
	ret = HDB_ERR_NOENTRY;
	goto out;
    }

    rc = ldap_set_option(HDB2LDAP(db), LDAP_OPT_SIZELIMIT, (const void *)&limit);
    if (rc != LDAP_SUCCESS) {
	ret = HDB_ERR_BADVERSION;
	krb5_set_error_message(context, ret, "ldap_set_option: %s",
			      ldap_err2string(rc));
	goto out;
    }

    /* HACK: This should check if we need to delete the object or just some attributes */

    rc = ldap_delete_ext_s(HDB2LDAP(db), dn, NULL, NULL );
    if (check_ldap(context, db, rc)) {
	ret = HDB_ERR_CANT_LOCK_DB;
	krb5_set_error_message(context, ret, "ldap_delete_ext_s: %s",
			       ldap_err2string(rc));
    } else
	ret = 0;

  out:
    if (dn != NULL)
	free(dn);
    if (msg != NULL)
	ldap_msgfree(msg);

    return ret;
}

static krb5_error_code
LDAP_destroy(krb5_context context, HDB * db)
{
    krb5_error_code ret;

    LDAP_close(context, db);

    ret = hdb_clear_master_key(context, db);
    if (HDB2BASE(db))
	free(HDB2BASE(db));
    if (HDB2CREATE(db))
	free(HDB2CREATE(db));
    if (HDB2URL(db))
	free(HDB2URL(db));
    krb5_config_free_strings(db->virtual_hostbased_princ_svcs);
    if (db->hdb_name)
	free(db->hdb_name);
    free(db->hdb_db);
    free(db);

    return ret;
}

static krb5_error_code
LDAP_set_sync(krb5_context context, HDB * db, int on)
{
    (void)on;
    return 0;
}

static krb5_error_code
hdb_ldap_common(krb5_context context,
		HDB ** db,
		const char *search_base,
		const char *url)
{
    struct hdbldapdb *h;
    const char *create_base = NULL;
    const char *ldap_secret_file = NULL;

    if (url == NULL || url[0] == '\0') {
	const char *p;
	p = krb5_config_get_string(context, NULL, "kdc",
				   "hdb-ldap-url", NULL);
	if (p == NULL)
		p = default_ldap_url;

	url = p;
    }

    if (search_base == NULL || search_base[0] == '\0') {
	krb5_set_error_message(context, ENOMEM, "ldap search base not configured");
	return ENOMEM; /* XXX */
    }

    if (structural_object == NULL) {
	const char *p;

	p = krb5_config_get_string(context, NULL, "kdc",
				   "hdb-ldap-structural-object", NULL);
	if (p == NULL)
	    p = default_structural_object;
	structural_object = strdup(p);
	if (structural_object == NULL) {
	    krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	    return ENOMEM;
	}
    }

    samba_forwardable =
	krb5_config_get_bool_default(context, NULL, TRUE,
				     "kdc", "hdb-samba-forwardable", NULL);

    *db = calloc(1, sizeof(**db));
    if (*db == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    memset(*db, 0, sizeof(**db));

    h = calloc(1, sizeof(*h));
    if (h == NULL) {
	free(*db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }
    (*db)->hdb_db = h;

    /* XXX */
    if (asprintf(&(*db)->hdb_name, "ldap:%s", search_base) == -1) {
	LDAP_destroy(context, *db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "strdup: out of memory");
	return ENOMEM;
    }

    h->h_url = strdup(url);
    h->h_base = strdup(search_base);
    if (h->h_url == NULL || h->h_base == NULL) {
	LDAP_destroy(context, *db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "strdup: out of memory");
	return ENOMEM;
    }

    ldap_secret_file = krb5_config_get_string(context, NULL, "kdc",
					      "hdb-ldap-secret-file", NULL);
    if (ldap_secret_file != NULL) {
	krb5_config_binding *tmp;
	krb5_error_code ret;
	const char *p;
	
	ret = krb5_config_parse_file(context, ldap_secret_file, &tmp);
	if (ret)
	    return ret;

	p = krb5_config_get_string(context, tmp, "kdc",
				   "hdb-ldap-bind-dn", NULL);
	if (p != NULL)
	    h->h_bind_dn = strdup(p);
	
	p = krb5_config_get_string(context, tmp, "kdc",
				   "hdb-ldap-bind-password", NULL);
	if (p != NULL)
	    h->h_bind_password = strdup(p);

	krb5_config_file_free(context, tmp);
    }

    h->h_start_tls =
	krb5_config_get_bool_default(context, NULL, FALSE,
				     "kdc", "hdb-ldap-start-tls", NULL);

    create_base = krb5_config_get_string(context, NULL, "kdc",
					 "hdb-ldap-create-base", NULL);
    if (create_base == NULL)
	create_base = h->h_base;

    h->h_createbase = strdup(create_base);
    if (h->h_createbase == NULL) {
	LDAP_destroy(context, *db);
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "strdup: out of memory");
	return ENOMEM;
    }

    (*db)->hdb_master_key_set = 0;
    (*db)->hdb_openp = 0;
    (*db)->hdb_capability_flags = HDB_CAP_F_SHARED_DIRECTORY;
    (*db)->hdb_open = LDAP_open;
    (*db)->hdb_close = LDAP_close;
    (*db)->hdb_fetch_kvno = LDAP_fetch_kvno;
    (*db)->hdb_store = LDAP_store;
    (*db)->hdb_remove = LDAP_remove;
    (*db)->hdb_firstkey = LDAP_firstkey;
    (*db)->hdb_nextkey = LDAP_nextkey;
    (*db)->hdb_lock = LDAP_lock;
    (*db)->hdb_unlock = LDAP_unlock;
    (*db)->hdb_rename = NULL;
    (*db)->hdb__get = NULL;
    (*db)->hdb__put = NULL;
    (*db)->hdb__del = NULL;
    (*db)->hdb_destroy = LDAP_destroy;
    (*db)->hdb_set_sync = LDAP_set_sync;

    return 0;
}

#ifdef OPENLDAP_MODULE
static
#endif

krb5_error_code
hdb_ldap_create(krb5_context context, HDB ** db, const char *arg)
{
    return hdb_ldap_common(context, db, arg, NULL);
}

#ifdef OPENLDAP_MODULE
static
#endif

krb5_error_code
hdb_ldapi_create(krb5_context context, HDB ** db, const char *arg)
{
    krb5_error_code ret;
    char *search_base, *p;

    if (asprintf(&p, "ldapi:%s", arg) == -1 || p == NULL) {
	*db = NULL;
	krb5_set_error_message(context, ENOMEM, "out of memory");
	return ENOMEM;
    }
    search_base = strchr(p + strlen("ldapi://"), ':');
    if (search_base == NULL) {
	*db = NULL;
	krb5_set_error_message(context, HDB_ERR_BADVERSION,
			       "search base missing");
	return HDB_ERR_BADVERSION;
    }
    *search_base = '\0';
    search_base++;

    ret = hdb_ldap_common(context, db, search_base, p);
    free(p);
    return ret;
}

#ifdef OPENLDAP_MODULE
static krb5_error_code
init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void
fini(void *ctx)
{
}

struct hdb_method hdb_ldap_interface = {
    HDB_INTERFACE_VERSION,
    init,
    fini,
    0 /*is_file_based*/, 0 /*can_taste*/,
    "ldap",
    hdb_ldap_create
};

struct hdb_method hdb_ldapi_interface = {
    HDB_INTERFACE_VERSION,
    init,
    fini,
    0 /*is_file_based*/, 0 /*can_taste*/,
    "ldapi",
    hdb_ldapi_create
};
#endif

#endif				/* OPENLDAP */
