// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-chk_ctx.h
 * Civil check context function header
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#ifndef _CIVIL_CHK_CTX_H_
#define _CIVIL_CHK_CTX_H_

#define MAX_CHK_CTX 2
#define true 1
#define false 0
#include "civil-protos.h"
#include "common-protos.h"

typedef struct {
	gen_crypt_sig_id sid;
	EVP_PKEY *evpkey;
	string_t hash;
} cached_cert_info;

X509_STORE *get_store(const gen_crypt_chk_ctx chk_ctx);

X509 *get_trusted_x509(const gen_crypt_chk_ctx chk_ctx);

int init_chk_session(gen_crypt_chk_ctx chk_ctx, X509_STORE *store,
                     X509 *trusted_ca);

int get_cached_cert_info(const gen_crypt_chk_ctx chk_ctx,
                         cached_cert_info *my_cache);

int is_cached_cert(gen_crypt_chk_ctx chk_ctx, string_t *hash);

int set_cached_cert_info(gen_crypt_chk_ctx chk_ctx, cached_cert_info *my_cache);

int get_new_chk_ctx(gen_crypt_chk_ctx *chk_ctx);

int free_chk_ctx(gen_crypt_chk_ctx chk_ctx);

#endif /* _CIVIL_CHK_CTX_H_ */
