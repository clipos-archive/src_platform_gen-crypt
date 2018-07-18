// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file check_daemon.c
 * Package signature checking daemon
 *
 * Copyright (C) 2011 SGDSN/ANSSI
 * Copyright (C) 2015 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "gen_crypt.h"

#include <clip/clip.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

// Cache and CRL inherent race-conditions :
// 	* CRLs are supposed to be downloaded before the
// 	this daemaon is spawned. They remain constant
// 	for one verification cycle. As a result, of course,
// 	we can only be sure that a CRL is taken into account
// 	if it was emitted /before/ the last successful download occured.
// 	This is not considered to be a 'real' limitation, it is
// 	inherent to the use of CRLs...
//
// 	These facts entail that as long as the daemon is alive
// 	and a certificate is cached, it can be used after one
// 	of the member of the chain becomes invalid
// 	(be it because of expiration or revocation...)
//
// /!\ These limitations are considered as acceptable ASSUMING
// /!\ THE DAEMON IS REGULARLY RESPAWNED.
// /!\ Otherwise, a cache flush policy has to be implemented.
//
// /!\ CRLs ARE NOT UPDATED BY THIS CODE, IT SHOULD BE TAKEN CARE OF
// /!\ BY THE SOFTWARE DOWNLOADING PACKAGES TO UPDATE.

int g_verbose = 0;
int g_daemonized = 0;
static int g_chroot = 0;

// Default directory to chroot to if enabled
#define CHROOT_DIR "/var/empty/gen-crypt"

// Ensure that g_do_revoke_privs is optimized away if we are not compiling for
// testing. g_do_revoke_privs could have been defined locally to 'main' but
// defining it globally simplifies the #ifdef logic.
#ifdef TEST_GEN_CRYPT
static int g_do_revoke_privs = 1;
#else /* TEST_GEN_CRYPT */
#define g_do_revoke_privs 1
#endif /* TEST_GEN_CRYPT */

gen_crypt_chk_ctx g_dev_ctx;
gen_crypt_chk_ctx g_ctrl_ctx;
const char *g_dev_regexp;
const char *g_ctrl_regexp;

static void
print_help(const char *prog)
{
	printf("%s - Daemon to check package signatures\n", prog);
	printf("Usage: %s [opts]\n", prog);
	puts("With options:");
	puts("  -S <sock>  listen on socket <sock> for client connexions");
	puts("");
#ifdef CIVIL_GEN_CRYPT
	puts("  -k <path>  path to a folder containing a c_rehashed repository of");
	puts("             certificates to validate developers certificates");
	puts("  -r <re>    optional regular expression that the subject name in");
	puts("             verified developer certificates must match");
	puts("  -l <path>  path to a folder containing a c_rehashed repository of");
	puts("             CRL for the developer PKI");
	puts("  -t <path>  path to the certificate to trust as the issuer of");
	puts("             developer certificates");
	puts("");
	puts("  -K <path>  path to a folder containing a c_rehashed repository of");
	puts("             certificates to validate controllers certificates");
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
	puts("  -c         chroot into " CHROOT_DIR " after startup");
	puts("  -F         do not daemonize, stay in foreground");
	puts("  -h         display this help and exit");
#ifdef TEST_GEN_CRYPT
	puts("  -U         do not try to drop privileges. Should only be used for");
	puts("             testing");
#endif /* TEST_GEN_CRYPT */
	puts("  -v         display version number and exit");
	puts("  -V         be more verbose: set once for log messages, twice for");
	puts("             debug");
}

static int
check_sigs(string_t *archive, gen_crypt_chk_ctx devctx,
           gen_crypt_chk_ctx ctrlctx, const char *devre, const char *ctrlre)
{
	string_t dev_tag, ctrl_tag, package, hash;
	string_t sig, cert;
	uint32_t off;
	uint32_t len;
	int ret = -1;

	hash.data = NULL;
	hash.len = 0;

	/* The archive should be a tagged controller signature, try to parse it as
	 * such */
	if (ar_find_member_last(archive, "ctrl_sign", &off, &len)) {
		ERROR("Failed to find ctrl_sign tag");
		goto out;
	}

	ctrl_tag.data = archive->data + off;
	ctrl_tag.len = len;

	/* 'Shorten' the archive to the next header */
	/* then archive should be a tagged developer signature, i.e.
	 * of the form package + dev_tag, try to parse it as such */
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

	/* Parse the developer signature block */
	if (ar_parse_sigblock(&dev_tag, &cert, &sig)) {
		ERROR("Failed to parse dev_sign");
		goto out;
	}

	/* Check the developer signature, i.e. check that the signature sig
	 * found in dev_tag is a valid one for package.
	 */
	if (gen_crypt_verify_with_cache(devctx, &package, &cert, &sig, devre, false) != C_OK) {
		ERROR("Signature check failed on dev_sign");
		goto out;
	}
	DEBUG("dev_sign signature OK");

	/* Perform the same verifications for the ctrl signature */
	if (ar_parse_sigblock(&ctrl_tag, &cert, &sig)) {
		ERROR("Failed to parse ctrl_sign");
		goto out;
	}

	/* Check the controller signature, i.e. check that the signature sig
	 * found in ctrl_tag is a valid one for archive.
	 */
	if (gen_crypt_verify_with_cache(ctrlctx, archive, &cert, &sig, ctrlre, false) != C_OK) {
		ERROR("Signature check failed on ctrl_sign");
		goto out;
	}
	DEBUG("ctrl_sign signature OK");
	ret = 0;
/* Fall through */
out:
	if (hash.data)
		free(hash.data);

	return ret;
}

static void
handle_filecheck(int s)
{
	int fd;
	char c;
	string_t archive;
	struct stat st;
	char *map = NULL;

	if (clip_recv_fd(s, &fd)) {
		ERROR_ERRNO("Failed to receive fd");
		goto out;
	}

	if (fstat(fd, &st)) {
		ERROR_ERRNO("Failed to stat fd");
		goto out;
	}

	// Probably too careful, but it's not written
	// anywhere that it never is the case :)
	if (st.st_size <= 0) {
		ERROR("Error in stat, empty archive");
		goto out;
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
		goto out;
	}

	// st.st_size is an off_t, which could be 64 bits
	// when compiling with 'large file systems' option.
	// It can now be cast safely to size_t
	uint32_t file_size = (uint32_t)st.st_size;
	map = mmap(0, file_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		ERROR_ERRNO("Failed to mmap file");
		goto out;
	}

	if (madvise(map, file_size, MADV_WILLNEED | MADV_SEQUENTIAL)) {
		ERROR_ERRNO("Failed madvise");
		/* Don't bug out here */
	}
	archive.data = map;
	archive.len = file_size;
	close(fd);

	if (check_sigs(&archive, g_dev_ctx, g_ctrl_ctx, g_dev_regexp, g_ctrl_regexp)) {
		ERROR("Signature check failed");
		c = 'N';
	} else {
		LOG("Signature check OK");
		c = 'Y';
	}

	if (write_fd(s, &c, 1)) {
		ERROR("Failed to write answer");
		goto out;
	}

out:
	if (map) {
		int ret = munmap(map, file_size);
		if (ret != 0) {
			ERROR_ERRNO("munmap");
		}
	}
	close(s);
}

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

static void
handle_connexion(int s)
{
	char c;

	if (read_fd(s, &c, 1)) {
		ERROR("Failed to read command");
		close(s);
		return;
	}

	switch (c) {
		case 'Q':
			LOG("Received quit command, exiting");
			close(s);
			exit(0);
		case 'C':
			DEBUG("Received check command");
			handle_filecheck(s);
			return;
		default:
			ERROR("Received unsupported command: %c", c);
			close(s);
			return;
	}
}

static int
revoke_privs(void)
{
	uid_t uid = 65534;
	gid_t gid = 65534;
	struct group *grp = getgrnam("nobody");
	struct passwd *pwd = getpwnam("nobody");
	gid_t grps[1];

	if (grp)
		gid = grp->gr_gid;
	else
		ERROR("Group nobody not found, defaulting to gid 65534");
	grps[0] = gid;

	if (pwd)
		uid = pwd->pw_uid;
	else
		ERROR("User nobody not found, defaulting to uid 65534");

	if (g_chroot && clip_chroot(".")) {
		ERROR("Could not chroot to current directory");
		return -1;
	}

	if (clip_revokeprivs(uid, gid, grps, 1, 0)) {
		ERROR("Failed to revoke privileges");
		return -1;
	}

	DEBUG("Privileges dropped");
	return 0;
}

/**
 * Perform socket handling, privilege dropping and chroot.
 *
 * Privilege dropping and chroot features may be disabled if compiled in test
 * mode. In production (non-test mode), the g_do_revoke_privs variable will be
 * defined to 1 and should be optimized away by the compiler.
**/
static int
do_daemon(const char *sockpath)
{
	struct sockaddr_un addr;
	int sock;

	sock = clip_sock_listen(sockpath, &addr, 0066);
	if (sock == -1) {
		ERROR("Failed to create socket on %s", sockpath);
		return EXIT_FAILURE;
	}

	if (g_do_revoke_privs && revoke_privs()) {
		close(sock);
		return EXIT_FAILURE;
	}

	for (;;) {
		int s;
		struct sockaddr_un caddr;
		socklen_t clen = sizeof(caddr);

		s = accept(sock, (struct sockaddr *)&caddr, &clen);
		if (s < 0) {
			ERROR_ERRNO("Failed to accept connexion");
			continue;
		}

		handle_connexion(s);
	}

	/* Never reached */
	return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
	int c;
	const char *sockpath = NULL;
	const char *prog = basename(argv[0]);
	int daemonize = 1;
	const char *dca = NULL, *cca = NULL, *dcrl = NULL, *ccrl = NULL,
	           *dtrusted_ca = NULL, *ctrusted_ca = NULL, *dpwd = NULL,
	           *cpwd = NULL;
	gen_crypt_ca_info *dca_info = NULL, *cca_info = NULL;

#ifdef TEST_GEN_CRYPT
	while ((c = getopt(argc, argv, "cdFhl:L:k:K:p:P:r:R:S:t:T:UvV")) != -1) {
#else  /* TEST_GEN_CRYPT */
	while ((c = getopt(argc, argv, "cdFhl:L:k:K:p:P:r:R:S:t:T:vV")) != -1) {
#endif /* TEST_GEN_CRYPT */
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
			case 'K':
				cca = optarg;
				break;
			case 'P':
				cpwd = optarg;
				break;
			case 'L':
				ccrl = optarg;
				break;
			case 'r':
				g_dev_regexp = optarg;
				break;
			case 'R':
				g_ctrl_regexp = optarg;
				break;
			case 'S':
				sockpath = optarg;
				break;
			case 't':
				dtrusted_ca = optarg;
				break;
			case 'T':
				ctrusted_ca = optarg;
				break;
			case 'c':
				g_chroot = 1;
				break;
			case 'F':
				daemonize = 0;
				break;
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
#ifdef TEST_GEN_CRYPT
			case 'U':
				g_do_revoke_privs = 0;
				break;
#endif /* TEST_GEN_CRYPT */
			case 'V':
				g_verbose++;
				break;
			case 'v':
				print_version(prog);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option %c", c);
				print_help(prog);
				return EXIT_FAILURE_BAD_ARGS;
		}
	}

	if (!sockpath) {
		ERROR("Missing socket path");
		print_help(prog);
		return EXIT_FAILURE_BAD_ARGS;
	}

	if (!dca) {
		ERROR("Missing developer key argument");
		print_help(prog);
		return EXIT_FAILURE_BAD_ARGS;
	}

	if (!cca) {
		ERROR("Missing controller key argument");
		print_help(prog);
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

	if (daemonize) {
		if (clip_daemonize()) {
			ERROR("Failed to daemonize process");
			return EXIT_FAILURE;
		}

		openlog("pkg-check-daemon", LOG_NDELAY | LOG_PID, LOG_DAEMON);
		g_daemonized = 1;
	}

	if (g_chroot) {
		if (chdir(CHROOT_DIR) == -1) {
			ERROR_ERRNO("Failed to change directory to " CHROOT_DIR);
			return EXIT_FAILURE;
		}
		DEBUG("Changed directory to " CHROOT_DIR);
	}

	if (gen_crypt_init() != C_OK) {
		ERROR("Failed to initialize cryptographic library");
		return EXIT_FAILURE;
	}

	if (gen_crypt_init_check(&g_dev_ctx, dca_info) != C_OK) {
		ERROR("Failed to connect developer session");
		goto err;
	}

	if (gen_crypt_init_check(&g_ctrl_ctx, cca_info) != C_OK) {
		ERROR("Failed to connect controller session");
		goto err;
	}

	DEBUG("Connected");

	return do_daemon(sockpath);

err:
	gen_crypt_end_check(g_dev_ctx);
	gen_crypt_end_check(g_ctrl_ctx);
	return EXIT_FAILURE;
}
