/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id$ */

#ifndef HEIMDAL_KRB5_SEND_TO_KDC_PLUGIN_H
#define HEIMDAL_KRB5_SEND_TO_KDC_PLUGIN_H 1

#include <krb5.h>
#include <heimbase-svc.h>

#define KRB5_PLUGIN_SEND_TO_KDC "send_to_kdc"

#define KRB5_PLUGIN_SEND_TO_KDC_VERSION_0 0
#define KRB5_PLUGIN_SEND_TO_KDC_VERSION_2 2
#define KRB5_PLUGIN_SEND_TO_KDC_VERSION KRB5_PLUGIN_SEND_TO_KDC_VERSION_2

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_send_to_kdc_func)(krb5_context,
			       void *,
			       krb5_krbhst_info *,
			       time_t timeout,
			       const krb5_data *,
			       krb5_data *);
typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_send_to_realm_func)(krb5_context,
				 void *,
				 krb5_const_realm,
				 time_t timeout,
				 const krb5_data *,
				 krb5_data *);


typedef struct krb5plugin_send_to_kdc_ftable {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    krb5plugin_send_to_kdc_func send_to_kdc;
    krb5plugin_send_to_realm_func send_to_realm; /* added in version 2 */
} krb5plugin_send_to_kdc_ftable;

#endif /* HEIMDAL_KRB5_SEND_TO_KDC_PLUGIN_H */
