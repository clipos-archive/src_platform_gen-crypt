// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file x509_get_ext.h
 * Utility functions temporarily imported from OpenSSL to retrieve x509
 * certificate extensions (basic constraints, key usage...).
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
**/

#ifndef _X509_GET_EXT_H_
#define _X509_GET_EXT_H_

#include "common-protos.h"
#include "civil-protos.h"

/**
 * Those functions are imported from OpenSSL development sources as they are
 * not available in the currently used version (OpenSSL 1.0.2e). Imported from
 * OpenSSL repository, commit: 063f1f0c693a10aab6a7227df15d4120ed824856.
 *
 * Those functions are intentionally conflicting with the ones from a future
 * version of OpenSSL as they should be removed as soon as OpenSSL supports
 * them directly.
 *
 * In OpenSSL 1.0.2e, cert->ex_flags is unsigned long.
 * In OpenSSL master branch, cert->ex_flags is uint32_t.
 *
 * Thus the following temporary change has been made to the OpenSSL API:
 * X509_get_extension_flags and X509_get_key_usage will return UINT32_MAX if
 * the value of cert->ex_flags exceeds UINT32_MAX.
 *
 * As the x509 typedef struct will become private in a future version of
 * OpenSSL, no manual manipulation of the X509 structure should take place in
 * any function not explicitly included here.
 *
 * Warning: Those functions call a modified version of x509v3_cache_extensions
 * that only sets the following flags: EXFLAG_V1, EXFLAG_CA, EXFLAG_SET,
 * EXFLAG_INVALID, EXFLAG_BCONS, EXFLAG_KUSAGE.
 *
 * Locking has been intentionally removed as the gencrypt API is not thread
 * safe anyway.
 */

/**
 * Imported and modified version of X509_get_extension_flags OpenSSL function.
 *
 * Parse x509 extension flags, cache them in the X509 struct and return them.
 * UINT32_MAX is returned in the unlikely event that the flags cannot be stored
 * in a uint32_t.
 *
 * Notice: As flags are cached in the X509 struct, x cannot be const.
 */
uint32_t X509_get_extension_flags(X509 *x);

/**
 * Imported and modified version of X509_get_key_usage OpenSSL function.
 *
 * Parse x509 extension flags, cache them in the X509 struct and return key
 * usage flags if they are set, UINT32_MAX if the attribute is not present in
 * the certificate. UINT32_MAX is also returned in the unlikely event that the
 * flags cannot be stored in a uint32_t.
 *
 * Notice: As flags are cached in the X509 struct, x cannot be const.
 */
uint32_t X509_get_key_usage(X509 *x);

#endif /* _X509_GET_EXT_H_ */
