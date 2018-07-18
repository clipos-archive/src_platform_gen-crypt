// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file file.c
 * File I/O functions
 *
 * Copyright (C) 2008 SGDN
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
*/

#include "common-protos.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

int
read_fd(int fd, char *buf, size_t len)
{
	ssize_t rlen;
	char *ptr = buf;

	while (len) {
		rlen = read(fd, ptr, len);

		if (rlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("read");
			return -1;
		}
		if (!rlen) {
			return -1;
		}

		// cast from ssize_t to size_t OK here:
		// rlen is > 0
		len -= (size_t)rlen;
		ptr += rlen;
	}

	return 0;
}

int
read_fd_alloc(int fd, string_t *out)
{
	struct stat st;
	char *str;

	if (fstat(fd, &st)) {
		ERROR_ERRNO("fstat");
		return -1;
	}

	if (st.st_size < 0) {
		ERROR("Negative size found for file");
		return -1;
	}

	if (!st.st_size) {
		ERROR("empty file");
		return -1;
	}

	// cast st.st_size_t from her on is OK since st.st_size > 0
	str = malloc((size_t)st.st_size);

	if (!str) {
		ERROR("Out of memory reading file (%lu)", st.st_size);
		return -1;
	}

	if (read_fd(fd, str, (size_t)st.st_size)) {
		ERROR("Failed to read file");
		goto err;
	}

	out->data = str;
	out->len = (uint32_t)st.st_size;

	return 0;

err:
	free(str);
	return -1;
}

/* Function allocating one byte more than the file contentand adding
 * a null character to a raw string contained in a file*/
static int
read_fd_alloc_null_term(int fd, string_t *out)
{
	struct stat st;
	char *str;

	if (fstat(fd, &st)) {
		ERROR_ERRNO("fstat");
		return -1;
	}

	if (st.st_size < 0) {
		ERROR("Negative size found for file");
		return -1;
	}

	if (!st.st_size) {
		ERROR("empty file");
		return -1;
	}

	// st.size_t can be cast from here on since >0
	str = malloc((size_t)st.st_size + 1);

	if (!str) {
		ERROR("Out of memory reading file (%lu)", st.st_size);
		return -1;
	}

	if (read_fd(fd, str, (size_t)st.st_size)) {
		ERROR("Failed to read file");
		goto err;
	}

	/* Adding the NULL character in the end */
	str[st.st_size] = '\0';

	out->data = str;
	out->len = (size_t)st.st_size + 1;

	return 0;

err:
	free(str);
	return -1;
}

int
read_file(const char *fname, string_t *out)
{
	int fd, ret;

	fd = open(fname, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		ERROR_ERRNO("open %s", fname);
		return -1;
	}

	ret = read_fd_alloc(fd, out);
	close(fd);

	return ret;
}

int
get_string_from_file(const char *fname, string_t *out)
{
	int fd, ret;

	fd = open(fname, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		ERROR_ERRNO("open %s", fname);
		return -1;
	}

	ret = read_fd_alloc_null_term(fd, out);
	close(fd);

	return ret;
}

int
write_fd(int fd, const char *buf, size_t len)
{
	ssize_t wlen;
	const char *ptr = buf;

	while (len) {
		wlen = write(fd, ptr, len);

		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			ERROR_ERRNO("write");
			return -1;
		}
		if (!wlen) {
			return -1;
		}
		// wlen >0 here, cast is OK
		len -= (size_t)wlen;
		ptr += wlen;
	}

	return 0;
}

int
write_file(const char *fname, string_t *in)
{
	int fd, ret;
	size_t len = in->len;
	char *ptr = in->data;

	fd = open(fname, O_WRONLY | O_NOFOLLOW | O_CREAT | O_TRUNC,
	          S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd == -1) {
		ERROR_ERRNO("open %s", fname);
		return -1;
	}

	ret = write_fd(fd, ptr, len);
	close(fd);
	return ret;
}
