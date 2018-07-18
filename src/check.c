// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file check.c
 * check utility main
 *
 * Copyright (C) 2008 SGDN/DCSSI
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "gen_crypt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

int g_verbose = 0;
int g_daemonized = 0;

static void
print_help(const char *prog)
{
	printf("%s - Check a package signature\n", prog);
	printf("Usage: %s [opts] <arch>\n", prog);
	puts("With:");
	puts("  <arch> the ar archive to check");
	puts("Options:");
#ifdef CIVIL_GEN_CRYPT
	puts("  -k <path>  path to a folder containing a c_rehashed repository of");
	puts("             certificates to validate developer certificates");
	puts("  -r <re>    optional regular expression that the subject name in");
	puts("             verified developer certificates must match");
	puts("  -l <path>  path to a folder containing a c_rehashed repository of");
	puts("             CRL for the developer PKI");
	puts("  -t <path>  path to the certificate to trust as the issuer of");
	puts("             developer certificates");
	puts("");
	puts("  -K <path>  path to folder containing a c_rehashed repository of");
	puts("             certificates to validate controller certificates");
	puts("  -R <re>    optional regular expression that the subject name in");
	puts("             verified controller certificates must match");
	puts("  -L <path>  path to a folder containing a c_rehashed repository of");
	puts("             CRL for the controller PKI");
	puts("  -T <path>  path to the certificate to trust as the issuer of");
	puts("             controller certificates");
#else
#error "No underlying cryptography chosen !"
#endif
	puts("");
	puts("  -h         display this help and exit");
	puts("  -v         display version number and exit");
	puts("  -V         be more verbose: set once for log messages, twice for");
	puts("             debug");
}

static int
check_sigs(string_t *archive, gen_crypt_chk_ctx devctx,
           gen_crypt_chk_ctx ctrlctx, const char *devre, const char *ctrlre)
{
	string_t dev_tag, ctrl_tag, package;
	string_t sig, cert;
	uint32_t off;
	uint32_t len;
	int ret = -1;

	if (ar_find_member_last(archive, "ctrl_sign", &off, &len)) {
		ERROR("Failed to find ctrl_sign tag");
		goto out;
	}

	ctrl_tag.data = archive->data + off;
	ctrl_tag.len = len;

	/* 'Shorten' the archive to the next header */
	archive->len = ar_header_offset(off);
	if (archive->len == 0) {
		ERROR("Archive is way too short");
	}

	if (ar_find_member_last(archive, "dev_sign", &off, &len)) {
		ERROR("Failed to find dev_sign tag");
		goto out;
	}

	dev_tag.data = archive->data + off;
	dev_tag.len = len;

	package.data = archive->data;
	package.len = ar_header_offset(off);

	if (package.len == 0) {
		ERROR("Package in archive is way too short");
	}

	/* Parsing dev_tag to get the certificate (supposedly) matching the secret
	 * key
	 * used to create the signature and the signature value. */
	if (ar_parse_sigblock(&dev_tag, &cert, &sig)) {
		ERROR("Failed to parse dev_sign");
		goto out;
	}

	/* verification of the signature against devctx (which should have been
	 * initialized with the CA for developers).*/
	if (gen_crypt_verify(devctx, &package, &cert, &sig, devre, false) != C_OK) {
		ERROR("Signature check failed on dev_sign");
		goto out;
	}
	LOG("dev_sign signature OK");

	/* Same two steps for the controller tag*/
	if (ar_parse_sigblock(&ctrl_tag, &cert, &sig)) {
		ERROR("Failed to parse ctrl_sign");
		goto out;
	}

	/* /!\ signature is computed on hash over package | dev_tag, i.e. archive */
	if (gen_crypt_verify(ctrlctx, archive, &cert, &sig, ctrlre, false) != C_OK) {
		ERROR("Signature check failed on ctrl_sign");
		goto out;
	}
	LOG("ctrl_sign signature OK");

	ret = 0;
/* Fall through */
out:
	return ret;
}

int
main(int argc, char *argv[])
{
	int c;
	int ret = EXIT_FAILURE, fd = -1;
	const char *dregexp = NULL, *cregexp = NULL;
	const char *dca = NULL, *cca = NULL, *dcrl = NULL, *ccrl = NULL,
	           *dtrusted_ca = NULL, *ctrusted_ca = NULL, *dpwd = NULL,
	           *cpwd = NULL;
	char *map = NULL;
	uint32_t file_size = 0;
	string_t archive;
	struct stat st;
	gen_crypt_ca_info *dca_info = NULL, *cca_info = NULL;
	gen_crypt_chk_ctx dctx = -1, cctx = -1;
	const char *prog = basename(argv[0]);

	while ((c = getopt(argc, argv, "dhk:K:p:P:l:L:r:R:t:T:vV")) != -1) {
		switch (c) {
			case 'd':
				// Ignored for compatibility reasons
				break;
			case 'k':
				dca = optarg;
				break;
			case 'p':
				dpwd = optarg;
				break;
			case 'l':
				dcrl = optarg;
				break;
			case 't':
				dtrusted_ca = optarg;
				break;
			case 'K':
				cca = optarg;
				break;
			case 'P':
				cpwd = optarg;
				break;
			case 'L':
				ccrl = optarg;
				break;
			case 'T':
				ctrusted_ca = optarg;
				break;
			case 'r':
				dregexp = optarg;
				break;
			case 'R':
				cregexp = optarg;
				break;
			case 'v':
				print_version(prog);
				return EXIT_SUCCESS;
			case 'V':
				g_verbose++;
				break;
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option %c", c);
				print_help(prog);
				return EXIT_FAILURE_BAD_ARGS;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		ERROR("Error while parsing arguments : missing argument or bad option");
		return EXIT_FAILURE_BAD_ARGS;
	}

	if (!dca) {
		ERROR("Missing developer CA argument");
		return EXIT_FAILURE_BAD_ARGS;
	}

	if (!cca) {
		ERROR("Missing controller CA argument");
		return EXIT_FAILURE_BAD_ARGS;
	}

	if (gen_crypt_init_ca_info(dca, dcrl, dtrusted_ca, dpwd, &dca_info) != C_OK) {
		ERROR("Error initializing developer structure");
		return EXIT_FAILURE;
	}

	if (gen_crypt_init_ca_info(cca, ccrl, ctrusted_ca, cpwd, &cca_info) != C_OK) {
		ERROR("Error initializing developer structure");
		return EXIT_FAILURE;
	}

	if (gen_crypt_init()) {
		ERROR("Initialization problem");
		return EXIT_FAILURE;
	}

	if (gen_crypt_init_check(&dctx, dca_info)) {
		ERROR("Failed to initialize developer checking context");
		goto err;
	}
	if (gen_crypt_init_check(&cctx, cca_info)) {
		ERROR("Failed to initialize controller checking context");
		goto err;
	}
	LOG("Connected");

	fd = open(argv[0], O_RDONLY);
	if (fd == -1) {
		ERROR_ERRNO("could not open %s", argv[0]);
		goto err;
	}

	if (fstat(fd, &st)) {
		ERROR_ERRNO("fstat %s", argv[0]);
		goto err;
	}

	// Probably too careful, but it's not written
	// anywhere that it never is the case :)
	if (st.st_size <= 0) {
		ERROR("Error in stat, empty archive");
		goto err;
	}

	// Type string_t has an uint32_t field for the size.
	// It is historical, but is not a real limitation
	// in practise since we deal with debian packages here,
	// which should not be that large, and ar archives,
	// which have lengths of 10 digits in base 10 at most.
	// As a result, we choose to not handle archives
	// whose length cannot be encoded on 32 bits

	if (((uint64_t)st.st_size) >= UINT32_MAX) {
		ERROR("Archive is too big to be an ar archive");
		goto err;
	}

	// st.st_size is an off_t, which could be 64 bits
	// when compiling with 'large file systems' option.
	// It can now be cast safely to uint32_t
	file_size = (uint32_t)st.st_size;

	map = mmap(0, file_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		ERROR("Failed to mmap %s", argv[0]);
		goto err;
	}
	if (madvise(map, file_size, MADV_WILLNEED | MADV_SEQUENTIAL)) {
		ERROR_ERRNO("Failed madvise");
		/* Don't bug out here */
	}
	archive.data = map;
	archive.len = file_size;

	if (check_sigs(&archive, dctx, cctx, dregexp, cregexp))
		goto err;
	LOG("Successful signature verification!");
	ret = EXIT_SUCCESS;
/* Fall through */
err:
	gen_crypt_end_check(dctx);
	gen_crypt_end_check(cctx);
	gen_crypt_free_ca_info(dca_info);
	gen_crypt_free_ca_info(cca_info);
	gen_crypt_end();
	if (map) {
		int ret = munmap(map, file_size);
		if (ret != 0) {
			ERROR_ERRNO("munmap");
		}
	}
	if (fd > -1)
		close(fd);

	return ret;
}
