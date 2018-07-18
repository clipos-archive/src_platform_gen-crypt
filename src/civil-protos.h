// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-protos.h
 * Civil crypto header
 *
 * Copyright (C) 2008 SGDN/DCSSI
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#ifndef _CIVIL_PROTOS_H_
#define _CIVIL_PROTOS_H_

#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

#define MAX_CHK_CTX 2

#define true 1
#define false 0

typedef EVP_PKEY *gen_crypt_ctx;

typedef enum { C_OK = 0, C_NOK = 1 } gen_crypt_ret;

typedef int gen_crypt_chk_ctx;

typedef int gen_crypt_sig_id;

#endif /* _CIVIL_PROTOS_H_ */
