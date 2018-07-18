// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file arutils.c
 * ar archive utilities
 *
 * Copyright (C) 2008 SGDN
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "common-protos.h"

#include <ar.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

// Translates a size encoded as digits in ASCII
// into a uint32_t value.
// @ str : points to the string with the digits
// @ len : length of the string
// @ res : where the encoded value is stored when successful
// Returns -1 in case of error, 0 when successful.
static inline int
get_len(const char *str, uint32_t len, uint32_t *res)
{
	char buf[len + 1], *ptr, *endp = NULL;
	unsigned long int ret;

	if (memchr(str, 0, len)) {
		ERROR("Length field contains NULL byte");
		return -1;
	}

	memcpy(buf, str, len);
	buf[len] = '\0';
	ptr = memchr(buf, ' ', len);
	if (ptr)
		*ptr = '\0';

	errno = 0;
	ret = strtoul(buf, &endp, 10);
	if (errno || ret >= UINT32_MAX) {
		ERROR("Member length is too long (%lu)", ret);
		return -1;
	}

	if (*endp) {
		ERROR("Length field contains invalid bytes (%s)", endp);
		return -1;
	}
	*res = (uint32_t)ret;
	return 0;
}

// Function to parse an ar archive to try and find a file
// named name in an ar archive.
// @ arch : pointer to archive
// @ name : name of the file searched for in the archive
// @ off : offset of the archive where the named file is when successful
// (n.b. offset of the real start of the file, no the ar header offset)
// @ len : length of file referenced at offset.
// returns -1 in case of error and in case there is no file matching the search
// 0 in case there is.
int
ar_find_member(string_t *arch, const char *name, uint32_t *off, uint32_t *len)
{
	const struct ar_hdr *arh;
	const char *ptr; // holds the position in archive arch
	uint32_t curlen; // length of remaining archive to go through
	size_t slen;
	uint32_t mlen;

	// name has to be fit ar spec, otherwise we won't find
	// it anyways.
	slen = strlen(name);
	if (slen > sizeof(arh->ar_name)) {
		ERROR("Member name is too long");
		return -1;
	}

	ptr = arch->data;
	curlen = arch->len;

	if (curlen < SARMAG) {
		ERROR("Archive is waaay too short");
		return -1;
	}

	// an ar archive has to start with the magic ARMAG
	if (memcmp(ptr, ARMAG, SARMAG)) {
		ERROR("Wrong AR magic : %.*s", SARMAG, ptr);
		return -1;
	}

	ptr += SARMAG;
	curlen -= SARMAG;

	// since this magic is the only header, the following
	// stuff are the concatenation of file headers + data
	// which we parse sequentially to try and find the name
	// in a file header.
	for (;;) {
		// try to parse next AR file header
		if (!curlen)
			break;                   /* end of file */
		if (curlen < sizeof(*arh)) { /* not enough data to even be a header */
			ERROR("Trailing bytes at end of archive");
			break;
		}
		// we have a header candidate
		arh = (const struct ar_hdr *)ptr;
		ptr += sizeof(*arh);
		curlen -= sizeof(*arh);
		// check that it is a valid header (namely, that it ends with
		// file header magic ARFMAG)
		if (memcmp(arh->ar_fmag, ARFMAG, sizeof(arh->ar_fmag))) {
			ERROR("Incorrect fmag at offset %td: %.*s", ptr - arch->data,
			      sizeof(arh->ar_fmag), arh->ar_fmag);
			return -1;
		}
		if (get_len(arh->ar_size, sizeof(arh->ar_size), &mlen) < 0) {
			ERROR("Failed to read next member length");
			return -1;
		}
		// safe cast once and for all to obtain
		// the offset to be applied to get the next member
		// ar files are aligned on even bytes (padding is done with
		// newlines), but the size which
		// the header features does not take into
		// account the possible padding.
		// Hence, the raw data that we have if the archive
		// is well-formed is of the following size.
		uint32_t shift = mlen + (mlen & 1U);
		if (curlen < shift) {
			ERROR("Archive member overflow");
			return -1;
		}
		// checking whether the current file is the one we are looking for
		if (!memcmp(arh->ar_name, name, slen) &&
		    (slen == sizeof(arh->ar_name) || arh->ar_name[slen] == '/' ||
		     arh->ar_name[slen] == ' ')) {
			/* Found */
			// cast is OK here since ptr is necessarily greater than arch->data
			*off = (uint32_t)(ptr - arch->data);
			*len = mlen;
			return 0;
		}
		// otherwise, go to next header by shifting
		// ptr and decreasing remaining length to treat
		ptr += shift;
		curlen -= shift;
	}

	return -1;
}

// searches for a file named name in ar archive, and checks that
// is it the last in the archive
// @ arch : pointer to archive
// @ name : name of the file searched for in the archive
// @ off : offset of the archive where the named file is when successful
// (n.b. offset of the real start of the file, no the ar header offset)
// @ len : length of file referenced at offset.
int
ar_find_member_last(string_t *arch, const char *name, uint32_t *off,
                    uint32_t *len)
{
	uint32_t _off;
	uint32_t _len;

	if (ar_find_member(arch, name, &_off, &_len))
		return -1;

	// check that total length of archive equals
	// offset where the file starts + its length + the eventual padding
	// to ensure that it is the last file in the archive
	if (_off + _len + (_off + _len) % 2 != arch->len) {
		if (_off + _len > arch->len) {
			ERROR("Invalid member offset / length (%u + %u > %u", _off, _len,
			      arch->len);
		} else {
			ERROR("Member %s is not the last in the archive "
			      "(%u + %u < %u)",
			      name, _off, _len, arch->len);
		}
		return -1;
	}
	*off = _off;
	*len = _len;
	return 0;
}

// substracts the header size from argument
// returns > 0 value when successful
// 0 when negative value would have ensued
uint32_t
ar_header_offset(uint32_t off)
{
	if (off <= sizeof(struct ar_hdr)) {
		return 0;
	}
	return ((uint32_t)off - sizeof(struct ar_hdr));
}

int
ar_member_first_p(uint32_t off)
{
	if (off - sizeof(struct ar_hdr) - SARMAG)
		return 0;
	return 1;
}

// Computes the right length to be put in a ar file header.
// Namely, adds ar header size to len (taking padding into account),
// and if prefix_p is 1, size of SIG_HEADER_LEN too.
static inline size_t
member_length(size_t len, int prefix_p)
{
	size_t ret;

	ret = sizeof(struct ar_hdr) + len;
	if (len & 1)
		ret++;
	if (prefix_p)
		ret += SIG_HEADER_LEN;
	return ret;
}

// Generates an ar file header for a file of length len
// It applies the constraints propre to ar format :
// length is encoded on 10 digits in base 10, name on 16.
static inline int
write_header(struct ar_hdr *hdr, const char *name, size_t len)
{
	time_t curtime;

	char *ptr;
	char date[13];
	char size[11];

	curtime = time(0);

	if (16 != snprintf(hdr->ar_name, 16, "%-16s", name)) {
		ERROR("Truncated member name (%s)", name);
		return -1;
	}
	memcpy(hdr->ar_uid, "0     ", 6);
	memcpy(hdr->ar_gid, "0     ", 6);
	memcpy(hdr->ar_mode, "100644  ", 8);
	memcpy(hdr->ar_fmag, ARFMAG, 2);
	/* Note: snprintf always writes a trailing 0, even if that implies
	 * overriding the 'width' parameter. Hence, we write 13 chars to
	 * make sure we get 12 significant ones, then drop the 13th char.
	 * Same goes for size...
	 */
	snprintf(date, 13, "%-12lu", (unsigned long)curtime);
	memcpy(hdr->ar_date, date, 12);
	if (10 != snprintf(size, 11, "%-10ld", (long)len)) {
		ERROR("Truncated size of archive");
		return -1;
	};
	memcpy(hdr->ar_size, size, 10);

	ptr = memchr(hdr->ar_size, 0, 10);
	if (ptr) {
		ERROR("0 in ar_size at offset %u", ptr - hdr->ar_size);
		*ptr = ' ';
	}

	return 0;
}

// Generates the tag to be concatenated to packages signed
// by our tool. It is 'proprietary', and consists in
// adding two ar files to concatenate to the ar archive.
// @ out : where the resulting string to be concatenated is returned
// @ sig : signature string to use in the tag
// @ cert : certificate to use in the tag
int
ar_gen_tag(string_t *out, string_t *sig, string_t *cert)
{
	char *ptr;
	uint32_t siglen = htonl(sig->len);

	uint32_t len =
	    SARMAG + member_length(sig->len, 1) + member_length(cert->len, 0);
	char *tag;

	// Length of tag should not overflow
	if (len <= sig->len + cert->len) {
		ERROR("Problems with size of arguments, too large to fit in 32 bits.");
		return -1;
	}
	tag = malloc(len);
	if (!tag) {
		ERROR("Out of memory");
		return -1;
	}
	memset(tag, 0, len);
	ptr = tag;

	/* File header */
	memcpy(ptr, ARMAG, SARMAG);
	ptr += SARMAG;

	/* Certificate member */
	if (write_header((struct ar_hdr *)ptr, CERT_MEMBER_NAME, cert->len))
		goto err;
	ptr += sizeof(struct ar_hdr);
	memcpy(ptr, cert->data, cert->len);
	ptr += cert->len;
	if (cert->len & 1)
		*(ptr++) = '\n';

	/* Signature member */
	if (write_header((struct ar_hdr *)ptr, SIG_MEMBER_NAME,
	                 sig->len + SIG_HEADER_LEN))
		goto err;
	ptr += sizeof(struct ar_hdr);
	sprintf(ptr, "00000000%.8x", siglen);
	ptr += SIG_HEADER_LEN;
	memcpy(ptr, sig->data, sig->len);
	ptr += sig->len;
	if (sig->len & 1)
		*(ptr++) = '\n';

	out->data = tag;
	out->len = len;
	return 0;
err:
	free(tag);
	return -1;
}

/* fd must be opened in append mode */
int
ar_append_member(int fd, string_t *member, const char *name)
{
	struct ar_hdr hdr;
	size_t len = member->len;

	if (write_header(&hdr, name, len))
		return -1;

	if (write_fd(fd, (const char *)&hdr, sizeof(struct ar_hdr))) {
		ERROR("Failed to write header for member %s", name);
		return -1;
	}

	if (write_fd(fd, member->data, member->len)) {
		ERROR("Failed to write member %s", name);
		return -1;
	}

	if ((member->len & 1) && write_fd(fd, "\n", 1)) {
		ERROR("Failed to pad member %s", name);
		return -1;
	}
	return 0;
}

int
ar_parse_sigblock(string_t *tag, string_t *cert, string_t *sig)
{
	uint32_t cert_off, sig_off;
	uint32_t cert_len, sig_len;

	if (ar_find_member_last(tag, SIG_MEMBER_NAME, &sig_off, &sig_len)) {
		ERROR("Failed to find signature");
		return -1;
	}
	if (ar_find_member(tag, CERT_MEMBER_NAME, &cert_off, &cert_len)) {
		ERROR("Failed to find certificate");
		return -1;
	}

	if (!ar_member_first_p(cert_off)) {
		ERROR("Unexpected data before certificate");
		return -1;
	}

	uint32_t sig_hdr = ar_header_offset(sig_off);
	if (sig_hdr == 0) {
		ERROR("Unexpected behavior, possibly due to weird length of ar header");
		return -1;
	}
	// Checks that ar file containing the certificate (plus possible padding)
	// is followed immediately by ar file containing signature
	if (cert_off + cert_len + (cert_off + cert_len) % 2 != sig_hdr) {
		ERROR("Unexpected data between certificate and signature");
		return -1;
	}

	cert->data = tag->data + cert_off;
	cert->len = cert_len;
	sig->data = tag->data + sig_off + SIG_HEADER_LEN;
	if (sig_len < SIG_HEADER_LEN) {
		ERROR("Signature appended is too short");
		return -1;
	}
	sig->len = sig_len - SIG_HEADER_LEN;

	return 0;
}
