// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-structures.c
 * Civil specific structures functions
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "civil-structures.h"

/* Implementations of structures to collect inputs to the library,
 * together with initializing functions and 'getters'.
 * */

/* ca_dir and crl are paths to directories - they can contain up
 * to PATH_MAX characters.
 * trusted_ca is a file name, which can contain up to NAME_MAX characters.
 * Additional characters will be truncated.
 * As there shoud always be a ca_dir and a trusted_ca referenced,
 * ca_dir and trusted_ca should not have a NULL pointer in their
 * data field. This is controlled by get_ca_dir and get_trusted_ca.
 * This is not the case for the crl directory.
 */

struct gen_crypt_ca_info {
	string_t ca_dir;
	string_t crl;
	string_t trusted_ca;
};

/* key and pwd are paths to files, they can contain up to PATH_MAX characters.
 * Additional characters will be truncated.
 * As there should always be a private key referenced, if key.data is NULL
 * get_key raises an error. The pwd field, however, can have NULL as a data
 * value.
 */
struct gen_crypt_priv_info {
	string_t pwd;
	string_t key;
};

/**
 * Copy the content of char* chain to str->data, up to 'max' characters,
 * including the terminating null byte.
 *
 * If chain is longer than max characters (including the terminating null
 * byte), it is truncated to fit in 'max', making sure the string is null
 * terminated.
**/
static gen_crypt_ret
copy_to_string_t(const char *chain, const size_t max, string_t *str)
{
	if (chain == NULL) {
		str->data = NULL;
		str->len = 0;
		DEBUG("Created an empty string_t");
		return C_OK;
	}

	str->data = malloc(max);
	if (str->data == NULL) {
		ERROR("Error allocating memory, size: %zu", max);
		return C_NOK;
	}

	strncpy(str->data, chain, max - 1);
	str->data[max - 1] = '\0';
	str->len = strlen(str->data);
	if (str->len == max - 1) {
		ERROR("string_t potentially truncated (input longer than %zu?)", max);
	}
	return C_OK;
}

gen_crypt_ret
gen_crypt_init_ca_info(const char *ca_dir, const char *crl,
                       const char *trusted_ca, const char *pwd,
                       gen_crypt_ca_info **ca_info)
{
	if (pwd != NULL) {
		LOG("Password specified, but argument unused in current "
		    "implementation");
	}

	gen_crypt_ca_info *tmp_ca_info = malloc(sizeof(gen_crypt_ca_info));
	if (tmp_ca_info == NULL) {
		ERROR("Error allocating memory");
		return C_NOK;
	}

	if (copy_to_string_t(ca_dir, PATH_MAX, &tmp_ca_info->ca_dir) != C_OK) {
		goto end_free;
	}
	if (copy_to_string_t(crl, PATH_MAX, &tmp_ca_info->crl) != C_OK) {
		goto end_free;
	}
	if (copy_to_string_t(trusted_ca, NAME_MAX, &tmp_ca_info->trusted_ca) !=
	    C_OK) {
		goto end_free;
	}
	*ca_info = tmp_ca_info;

	return C_OK;

end_free:
	free(tmp_ca_info);
	return C_NOK;
}

void
gen_crypt_free_ca_info(gen_crypt_ca_info *ca_info)
{
	if (ca_info == NULL) {
		return;
	}
	free(ca_info->ca_dir.data);
	free(ca_info->crl.data);
	free(ca_info->trusted_ca.data);
	free(ca_info);
	return;
}

gen_crypt_ret
get_ca_dir(const gen_crypt_ca_info *ca_info, const string_t **ca_dir)
{
	if (ca_info == NULL) {
		ERROR("Null pointer as an argument");
		return C_NOK;
	}
	if (ca_info->ca_dir.data == NULL) {
		ERROR("No CA directory specified");
		return C_NOK;
	}
	*ca_dir = &(ca_info->ca_dir);
	return C_OK;
}

gen_crypt_ret
get_crl(const gen_crypt_ca_info *ca_info, const string_t **crl)
{
	if (ca_info == NULL) {
		ERROR("Null pointer as an argument");
		return C_NOK;
	}
	*crl = &(ca_info->crl);
	return C_OK;
}

gen_crypt_ret
get_trusted_ca(const gen_crypt_ca_info *ca_info, const string_t **trusted_ca)
{
	if (ca_info == NULL) {
		ERROR("Null pointer as an argument");
		return C_NOK;
	}
	if (ca_info->trusted_ca.data == NULL) {
		ERROR("No CA specified");
		return C_NOK;
	}
	*trusted_ca = &(ca_info->trusted_ca);
	return C_OK;
}

gen_crypt_ret
gen_crypt_init_priv_info(const char *key, const char *pwd,
                         gen_crypt_priv_info **priv_info)
{
	gen_crypt_priv_info *tmp_info = malloc(sizeof(gen_crypt_priv_info));
	if (tmp_info == NULL) {
		ERROR("Error allocating memory");
		return C_NOK;
	}

	if (copy_to_string_t(key, PATH_MAX, &tmp_info->key) != C_OK) {
		goto end_free;
	}
	if (copy_to_string_t(pwd, PATH_MAX, &tmp_info->pwd) != C_OK) {
		goto end_free;
	}
	*priv_info = tmp_info;

	return C_OK;

end_free:
	free(tmp_info);
	return C_NOK;
}

void
gen_crypt_free_priv_info(gen_crypt_priv_info *priv_info)
{
	if (priv_info == NULL) {
		return;
	}
	free(priv_info->key.data);
	free(priv_info->pwd.data);
	free(priv_info);
	return;
}

gen_crypt_ret
get_pwd(const gen_crypt_priv_info *priv_info, const string_t **pwd)
{
	if (priv_info == NULL) {
		ERROR("Null pointer as an argument");
		return C_NOK;
	}
	*pwd = &(priv_info->pwd);
	return C_OK;
}

gen_crypt_ret
get_key(const gen_crypt_priv_info *priv_info, const string_t **key)
{
	if (priv_info == NULL) {
		ERROR("Null pointer as an argument");
		return C_NOK;
	}
	if (priv_info->key.data == NULL) {
		ERROR("Path to a key must be specified");
		return C_NOK;
	}
	*key = &(priv_info->key);
	return C_OK;
}
