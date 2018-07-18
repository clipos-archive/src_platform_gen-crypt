// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-structures.h
 * Civil specific structure access function header
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#ifndef _CIVIL_STRUCTURES_H_
#define _CIVIL_STRUCTURES_H_

#include "common-protos.h"
#include "gen_crypt.h"

#include <dirent.h>

/* Implementations of structures to collect inputs to the library,
 * together with initializing functions and 'getters'.
 * */

gen_crypt_ret
get_ca_dir(const gen_crypt_ca_info *ca_info, const string_t **ca_dir);

gen_crypt_ret get_crl(const gen_crypt_ca_info *ca_info, const string_t **crl);

gen_crypt_ret
get_trusted_ca(const gen_crypt_ca_info *ca_info, const string_t **trusted_ca);

gen_crypt_ret
get_pwd(const gen_crypt_priv_info *priv_info, const string_t **pwd);

gen_crypt_ret
get_key(const gen_crypt_priv_info *priv_info, const string_t **key);

#endif /* _CIVIL_STRUCTURES_H_ */
