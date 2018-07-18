// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-chk_ctx.c
 * Civil check context functions
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "civil-chk_ctx.h"
#include "common-protos.h"

/*
 * Implementation of the checking context and of the cache of certificate :
 * TODO : comments
 * No manipulation of chk_session should be done using ways outside of
 * what is implemented here.
 *  */

typedef struct {
	bool initialized;
	X509_STORE *store;
	cached_cert_info cache;
	X509 *trusted_x509;
	bool cache_valid;
} chk_session;
/* For the time being, one certificate is cached by context, so there
 * is no use in declaring a cached_cert_info *cache in the struct
 * but it could be changed so that a list of certificates and their
 * hashes are stored.
 * /!\ The user of this functionality has to be conscious that
 * cached certificate are not reverified- which is the point (!) -
 * NOR IS THE NON-REVOCATION OF MEMBERS OF THEIR CERT_CHAIN
 * OR THEIR PEREMPTION ! */

static chk_session chk_ctx_table[MAX_CHK_CTX];

X509_STORE *
get_store(const gen_crypt_chk_ctx chk_ctx)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1)
		return NULL;
	if (!chk_ctx_table[chk_ctx].initialized)
		return NULL;
	return (chk_ctx_table[chk_ctx].store);
}

X509 *
get_trusted_x509(const gen_crypt_chk_ctx chk_ctx)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1)
		return NULL;
	if (!chk_ctx_table[chk_ctx].initialized)
		return NULL;
	return (chk_ctx_table[chk_ctx].trusted_x509);
}

int
init_chk_session(gen_crypt_chk_ctx chk_ctx, X509_STORE *store, X509 *trusted_ca)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1)
		return -1;
	chk_ctx_table[chk_ctx].store = store;
	chk_ctx_table[chk_ctx].trusted_x509 = trusted_ca;
	chk_ctx_table[chk_ctx].initialized = true;
	chk_ctx_table[chk_ctx].cache_valid = false;
	return 0;
}

int
get_cached_cert_info(const gen_crypt_chk_ctx chk_ctx,
                     cached_cert_info *my_cache)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1)
		return -1;
	if (!chk_ctx_table[chk_ctx].initialized) {
		ERROR("Check context not initialized");
		return -2;
	}
	if (!chk_ctx_table[chk_ctx].cache_valid) {
		ERROR("Cached certificate is not valid");
		return -3;
	}
	my_cache->sid = chk_ctx_table[chk_ctx].cache.sid;
	my_cache->evpkey = chk_ctx_table[chk_ctx].cache.evpkey;
	return 0;
}

/* Returns 1 if cached certificate has same hash as hash->data,
 * 0 if cached certificate is invalid or hashes do not match,
 * and negative value on error.*/
int
is_cached_cert(gen_crypt_chk_ctx chk_ctx, string_t *hash)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1) {
		ERROR("Invalid check context");
		return -1;
	}
	if (!chk_ctx_table[chk_ctx].initialized) {
		ERROR("Check context not initialized");
		return -2;
	}
	if (!chk_ctx_table[chk_ctx].cache_valid || hash == NULL) {
		return 0;
	}
	if (hash->len != chk_ctx_table[chk_ctx].cache.hash.len ||
	    memcmp(chk_ctx_table[chk_ctx].cache.hash.data, hash->data, hash->len)) {
		return 0;
	}
	return 1;
}

/* Updates chk_ctx with a cache refered to by my_cache.
 * The validity of cached values have to be checked by the caller, it is
 * taken for granted here.*/
int
set_cached_cert_info(gen_crypt_chk_ctx chk_ctx, cached_cert_info *my_cache)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1) {
		ERROR("Invalid check context");
		return -1;
	}
	if (!chk_ctx_table[chk_ctx].initialized) {
		ERROR("Check context not initialized");
		return -2;
	}
	if (chk_ctx_table[chk_ctx].cache_valid) {
		if (chk_ctx_table[chk_ctx].cache.evpkey != NULL)
			EVP_PKEY_free(chk_ctx_table[chk_ctx].cache.evpkey);
		if (chk_ctx_table[chk_ctx].cache.hash.data != NULL)
			free(chk_ctx_table[chk_ctx].cache.hash.data);
	}
	chk_ctx_table[chk_ctx].cache.sid = my_cache->sid;
	chk_ctx_table[chk_ctx].cache.evpkey = my_cache->evpkey;
	chk_ctx_table[chk_ctx].cache.hash = my_cache->hash;
	chk_ctx_table[chk_ctx].cache_valid = true;
	return 0;
}

int
get_new_chk_ctx(gen_crypt_chk_ctx *chk_ctx)
{
	int i = 0;
	while (i < MAX_CHK_CTX) {
		if (!(chk_ctx_table[i].initialized)) {
			*chk_ctx = i;
			return 0;
		}
		i++;
	}
	return -1;
}

int
free_chk_ctx(gen_crypt_chk_ctx chk_ctx)
{
	if (chk_ctx < 0 || chk_ctx > MAX_CHK_CTX - 1)
		return -1;
	if (!chk_ctx_table[chk_ctx].initialized) {
		return 0;
	}
	if (chk_ctx_table[chk_ctx].cache_valid) {
		if (chk_ctx_table[chk_ctx].cache.evpkey != NULL)
			EVP_PKEY_free(chk_ctx_table[chk_ctx].cache.evpkey);
		if (chk_ctx_table[chk_ctx].cache.hash.data != NULL)
			free(chk_ctx_table[chk_ctx].cache.hash.data);
	}
	if (chk_ctx_table[chk_ctx].store != NULL) {
		X509_STORE_free(chk_ctx_table[chk_ctx].store);
	}
	if (chk_ctx_table[chk_ctx].trusted_x509 != NULL) {
		X509_free(chk_ctx_table[chk_ctx].trusted_x509);
	}

	chk_ctx_table[chk_ctx].initialized = false;
	return 0;
}
/*END OF IMPLEM OF CHECKING CONTEXT*/
