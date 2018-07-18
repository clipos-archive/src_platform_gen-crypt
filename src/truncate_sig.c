// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
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

int g_verbose = 1;
int g_daemonized = 0;

int
main(__attribute__((unused)) int argc, char **argv)
{
	int fd = -1;
	char *map = NULL;
	string_t archive;
	struct stat st;
	int ret = EXIT_FAILURE;

	uint32_t off, len;
	// get file name of archive and option

	LOG("Unsigning archive file %s", argv[1]);

	fd = open(argv[1], O_RDWR);
	if (fd == -1) {
		ERROR_ERRNO("could not open %s", argv[1]);
		goto err;
	}

	if (fstat(fd, &st)) {
		ERROR_ERRNO("fstat %s", argv[1]);
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

	if (ar_find_member_last(&archive, "ctrl_sign", &off, &len)) {
		ERROR("Failed to find ctrl_sign tag");
		goto err;
	}

	/* Continue parsing to modify developper signature */
	/* 'Shorten' the archive to the next header */
	archive.len = ar_header_offset(off);

	if (ar_find_member_last(&archive, "dev_sign", &off, &len)) {
		ERROR("Failed to find dev_sign tag");
		goto err;
	}

	if (ftruncate(fd, (off_t) ar_header_offset(off))<0) {
		ERROR("Arhive could not be truncated");
		goto err;
	}

	LOG("Archive was truncated succesfully");

	ret = EXIT_SUCCESS;

err:
	if (map)
		munmap(map, file_size);
	if (fd > -1)
		close(fd);
	return ret;
}
