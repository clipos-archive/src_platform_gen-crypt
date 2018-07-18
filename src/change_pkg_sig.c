// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file change_pkg_sig.c
 * TODO: Describe me
 *
 * Copyright (C) 2016 SGDSN/ANSSI
 *
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
	printf("%s - Change a package signature\n", prog);
	printf("Usage: %s [opts] <arch>\n", prog);
	puts("With:");
	puts("  <arch> the ar archive to check");
	puts("Options:");
	puts("  -d : changes the developer signature");
	puts("  -c : changes the controller signature");
	puts("  -v : verbose");
}

static int
modify_tag(string_t *tag)
{
	string_t sig, cert;

	if (ar_parse_sigblock(tag, &cert, &sig)) {
		ERROR("Failed to parse tag");
		return -1;
	}
	printf("signature %s\n", sig.data);
	if (sig.len >= 1) {
		sig.data[sig.len - 1]++;
		printf("signature %s\n", sig.data);
		return 0;
	}

	ERROR("Only 1 character in signature???");
	return -1;
}

static int
change_sig(string_t *archive, int ctrl, int dev)
{
	string_t tag;
	uint32_t off;
	uint32_t len;

	if (ar_find_member_last(archive, "ctrl_sign", &off, &len)) {
		ERROR("Failed to find ctrl_sign tag");
		return -1;
	}

	tag.data = archive->data + off;
	tag.len = len;

	if (ctrl) { /* Tweak signature */
		if (modify_tag(&tag)) {
			ERROR("Failed to parse ctrl_sign");
			return -1;
		}
		LOG("Modification of controller signature");
	}
	if (!dev) {
		LOG("Invalid archive was created successfully");
		return 0;
	}

	/* Continue parsing to modify developer signature */
	/* 'Shorten' the archive to the next header */
	archive->len = ar_header_offset(off);

	if (ar_find_member_last(archive, "dev_sign", &off, &len)) {
		ERROR("Failed to find dev_sign tag");
		return -1;
	}

	tag.data = archive->data + off;
	tag.len = len;

	if (modify_tag(&tag)) {
		ERROR("Failed to parse dev_sign");
		return -1;
	}
	LOG("Modification of controller signature");
	return 0;
}

int
main(int argc, char **argv)
{
	int ctrl = 0, dev = 0;
	int fd = -1;
	char *map = NULL;
	string_t archive;
	struct stat st;
	int c;
	int ret = EXIT_FAILURE;

	// get file name of archive and option
	const char *prog = basename(argv[0]);

	while ((c = getopt(argc, argv, "cdvh")) != -1) {
		switch (c) {
			case 'c':
				ctrl = 1;
				break;
			case 'd':
				dev = 1;
				break;
			case 'v':
				g_verbose = 2;
				break;
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
			default:
				ERROR("Unsupported option %c", c);
				print_help(prog);
				return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1) {
		ERROR("Error while parsing arguments : missing argument or bad option");
		return EXIT_FAILURE;
	}

	LOG("Tweaking archive file %s", argv[0]);

	fd = open(argv[0], O_RDWR);
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
	uint32_t file_size = (uint32_t)st.st_size;

	map = mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
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

	if (change_sig(&archive, ctrl, dev) < 0) {
		ERROR("Signature change was not performed successfully");
		goto err;
	}

	ret = EXIT_SUCCESS;

err:
	if (map)
		munmap(map, file_size);
	if (fd > -1)
		close(fd);
	return ret;
}
