// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file sign.c
 * sign main: utility to sign packages.
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
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

int g_verbose = 0;
int g_daemonized = 0;

static void
print_help(const char *prog)
{
	printf("%s - Add a signature to an AR archive\n", prog);
	printf("Usage: %s [opts] <archive> \n", prog);
	puts("With:");
	puts("  <archive> name of the archive to sign");
	puts("Options:");
	puts("  -C         create a controller signature (ctrl_sign)");
	puts("  -D         create a developer signature (dev_sign)");
	puts("");
	puts("  -k <key>   controller or developer private key");
	puts("  -p <pass>  file containing the password for <key>");
	puts("  -c <cert>  signer's public key (certificate)");
	puts("  -r <re>    optional regular expression that the subject name in");
	puts("             <cert> must match");
	puts("");
	puts("  -h         display this help and exit");
	puts("  -v         display version number and exit");
	puts("  -V         be more verbose: set once for log messages, twice for");
	puts("             debug");
}

static int
write_sig(const char *fname, const char *name, string_t *sig, string_t *cert)
{
	int fd;
	string_t tag;
	tag.data = NULL;
	int ret = -1;

	if (ar_gen_tag(&tag, sig, cert)) {
		ERROR("Failed to generate tag");
		return -1;
	}

	fd = open(fname, O_WRONLY | O_APPEND);
	if (fd == -1) {
		ERROR_ERRNO("open %s for writing failed", fname);
		goto err;
	}

	if (ar_append_member(fd, &tag, name)) {
		ERROR("Failed to append signature");
		goto err;
	}

	ret = 0;
/* Fall through */
err:
	string_free(&tag);
	close(fd);
	return ret;
}

int
main(int argc, char *argv[])
{
	int c;
	int ret = EXIT_FAILURE;
	const char *privkey = NULL;
	const char *pubf = NULL;
	const char *re = NULL; //, *checkkey = NULL;
	const char *pwd = NULL;
	string_t pubkey, msg, signature;
	pubkey.data = msg.data = signature.data = NULL;
	pubkey.len = msg.len = 0;

	const char *prog = basename(argv[0]);
	const char *member_name = NULL;
	gen_crypt_ctx ctx = NULL;
	gen_crypt_sig_id sid = 0;
	gen_crypt_priv_info *priv_info = NULL;

	while ((c = getopt(argc, argv, "c:CDk:p:r:vVh")) != -1) {
		switch (c) {
			case 'C':
				if (member_name) {
					ERROR("Multiple types of signatures requested");
					return EXIT_FAILURE_BAD_ARGS;
				}
				member_name = "ctrl_sign";
				break;
			case 'D':
				if (member_name) {
					ERROR("Multiple types of signatures requested");
					return EXIT_FAILURE_BAD_ARGS;
				}
				member_name = "dev_sign";
				break;
			case 'c':
				pubf = optarg;
				break;
			case 'k':
				privkey = optarg;
				break;
			case 'p':
				pwd = optarg;
				break;
			case 'r':
				re = optarg;
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
	if (!privkey) {
		ERROR("Missing argument : no private key");
		return EXIT_FAILURE_BAD_ARGS;
	}
	if (!pubf) {
		ERROR("Missing argument : no certificate / public key");
		return EXIT_FAILURE_BAD_ARGS;
	}
	if (!member_name) {
		ERROR("Missing argument : select option -D or -C");
		return EXIT_FAILURE_BAD_ARGS;
	}

	// initialization of the cryptographic library
	if (gen_crypt_init() != C_OK)
		goto err;

	if (gen_crypt_init_priv_info(privkey, pwd, &priv_info) != C_OK) {
		goto err;
	}

	// getting the certificate matching the file name provided
	// by the caller
	if (gen_crypt_get_certificate(pubf, &pubkey, &sid, re) != C_OK)
		goto err;

	// getting the archive to be signed in string_t msg
	if (read_file(argv[0], &msg))
		goto err;

	if (gen_crypt_init_sign(&ctx, priv_info) != C_OK) {
		ERROR("Failed to connect");
		goto err;
	}

	if (gen_crypt_sign(ctx, &msg, sid, &signature) != C_OK) {
		ERROR("Signature failed");
		goto err;
	}

	if (write_sig(argv[0], member_name, &signature, &pubkey)) {
		ERROR("Failed to write signature");
		goto err;
	}

	LOG("[%s] %s signature added", basename(argv[0]), member_name);
	ret = EXIT_SUCCESS;
	gen_crypt_end_sign(ctx);
	gen_crypt_end();
/* Fall through */
err:
	string_free(&pubkey);
	string_free(&msg);
	string_free(&signature);
	gen_crypt_free_priv_info(priv_info);
	return ret;
}
