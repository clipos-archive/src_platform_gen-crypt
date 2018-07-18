// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
#include "x509_get_ext.h"

#include <openssl/x509v3.h>

static void
x509v3_cache_extensions(X509 *x)
{
	BASIC_CONSTRAINTS *bs;
	ASN1_BIT_STRING *usage;

	if (x->ex_flags & EXFLAG_SET)
		return;
	/* V1 should mean no extensions ... */
	if (!X509_get_version(x))
		x->ex_flags |= EXFLAG_V1;
	/* Handle basic constraints */
	if ((bs = X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL))) {
		if (bs->ca)
			x->ex_flags |= EXFLAG_CA;
		if (bs->pathlen) {
			if ((bs->pathlen->type == V_ASN1_NEG_INTEGER) || !bs->ca) {
				x->ex_flags |= EXFLAG_INVALID;
				x->ex_pathlen = 0;
			} else
				x->ex_pathlen = ASN1_INTEGER_get(bs->pathlen);
		} else
			x->ex_pathlen = -1;
		BASIC_CONSTRAINTS_free(bs);
		x->ex_flags |= EXFLAG_BCONS;
	}
	/* Handle key usage */
	if ((usage = X509_get_ext_d2i(x, NID_key_usage, NULL, NULL))) {
		/* Additional test not present in the original OpenSSL code */
		if (usage->length > 3) {
			/* Usage not conform to the RFC, dropping. */
			x->ex_kusage = 0;
		}
		if (usage->length > 0) {
			x->ex_kusage = usage->data[0];
			if (usage->length > 1) {
				/* usage->data is a unsigned char * which
				 * contains in its second to fourth byte (i.e.
				 * from data[1] to data[3]) the key usage
				 * encoding. Hence we are sure that no info is
				 * supposed to be encoded on an integer of more
				 * than 32 bits. OpenSSL X509 structure defines
				 * ex_kusage as unsigned long. Additional cast
				 * added (to the code imported from OpenSSL) to
				 * silence compiler warning. */
				x->ex_kusage |= (unsigned long)(usage->data[1] << 8);
			}
		} else {
			x->ex_kusage = 0;
		}
		x->ex_flags |= EXFLAG_KUSAGE;
		ASN1_BIT_STRING_free(usage);
	}
	x->ex_flags |= EXFLAG_SET;
	return;
}

uint32_t
X509_get_extension_flags(X509 *x)
{
	/* The PEM_read call from OpenSSL does not fill in the ex_flags member
	 * in the x509 struct. Thus we have to manually call the "caching"
	 * function if the flags are not set. */
	if (!(x->ex_flags & EXFLAG_SET)) {
		x509v3_cache_extensions(x);
	}
	/* Flags are currently internally defined with values below 0x2000 and
	 * thus it is safe to perform the unsigned long -> uint32_t conversion.
	 */
	if (x->ex_flags > UINT32_MAX) {
		ERROR("x509 certificate extension flags value is > UINT32_MAX."
		      " Capping at UINT32_MAX.");
		return UINT32_MAX;
	}
	return (uint32_t)x->ex_flags;
}

uint32_t
X509_get_key_usage(X509 *x)
{
	/* The PEM_read call from OpenSSL does not fill in the ex_flags member
	 * in the x509 struct. Thus we have to manually call the "caching"
	 * function if the flags are not set. */
	if (!(x->ex_flags & EXFLAG_SET)) {
		x509v3_cache_extensions(x);
	}
	/* Flags are currently internally defined with values below 0x2000 and
	 * thus it is safe to perform the unsigned long -> uint32_t conversion.
	 */
	if (x->ex_flags > UINT32_MAX) {
		ERROR("x509 certificate extension flags value is > UINT32_MAX."
		      " Capping at UINT32_MAX.");
		return UINT32_MAX;
	}
	if (x->ex_flags & EXFLAG_KUSAGE) {
		return (uint32_t)x->ex_kusage;
	}
	return UINT32_MAX;
}
