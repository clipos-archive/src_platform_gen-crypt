// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file common-protos.h
 * CLIP common definitions, macros and generic functions
 * prototypes.
 *
 * Copyright (C) 2008 SGDN/DCSSI
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#ifndef _COMMON_PROTOS_H_
#define _COMMON_PROTOS_H_

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#define SIG_MEMBER_NAME "signature"
#define CERT_MEMBER_NAME "certificate"
#define VERS_MEMBER_NAME "version"
/* Length of signature header (containing the signature length) */
#define SIG_HEADER_LEN 16
#define VERSION_LEN 8

// Specific exit failure return code used when command line arguments are
// invalid. This makes it easier to distinguish this case in tests.
#define EXIT_FAILURE_BAD_ARGS 10

/* Minimum validity period left, in seconds - error out if < 3 months */
#define MIN_VALIDITY (3 * 30 * 84600)
/* Minimum validity period left, in seconds - warn if < 6 months */
#define WARN_VALIDITY (6 * 30 * 84600)

extern size_t g_hash_size;
extern int g_verbose;

typedef struct {
	char *data;
	uint32_t len;
} string_t;

static inline void
string_free(string_t *str)
{
	if (str->data) {
		memset(str->data, 0, str->len);
		free(str->data);
	}
}

extern int read_fd(int, char *, size_t);
extern int read_fd_alloc(int fd, string_t *out);
extern int read_file(const char *fname, string_t *out);
extern int write_fd(int, const char *, size_t);
extern int write_file(const char *fname, string_t *in);
extern int get_string_from_file(const char *fname, string_t *out);

extern int
ar_find_member(string_t *arch, const char *name, uint32_t *off, uint32_t *len);
extern int ar_find_member_last(string_t *arch, const char *name, uint32_t *off,
                               uint32_t *len);
extern uint32_t ar_header_offset(uint32_t);
extern int ar_member_first_p(uint32_t);

extern int ar_append_member(int fd, string_t *member, const char *name);
extern int ar_gen_tag(string_t *out, string_t *sig, string_t *cert);
extern int ar_parse_sigblock(string_t *tag, string_t *cert, string_t *sig);

#define __U __attribute__((unused))

extern int g_daemonized;

#define ERROR(fmt, ...)                                                        \
	do {                                                                       \
		if (g_daemonized)                                                      \
			syslog(LOG_ERR, "%s(%s:%d): " fmt "\n", __FUNCTION__, __FILE__,    \
			       __LINE__, ##__VA_ARGS__);                                   \
		else                                                                   \
			fprintf(stderr, "%s(%s:%d): " fmt "\n", __FUNCTION__, __FILE__,    \
			        __LINE__, ##__VA_ARGS__);                                  \
	} while (0)

#define ERROR_ERRNO(fmt, ...) ERROR(fmt ": %s", ##__VA_ARGS__, strerror(errno))

#define _LOG(lev, fmt, ...)                                                    \
	do {                                                                       \
		if (g_verbose > lev) {                                                 \
			if (g_daemonized)                                                  \
				syslog((lev) > 0 ? LOG_DEBUG : LOG_INFO,                       \
				       "%s(%s:%d): " fmt "\n", __FUNCTION__, __FILE__,         \
				       __LINE__, ##__VA_ARGS__);                               \
			else                                                               \
				fprintf(stdout, "%s(%s:%d): " fmt "\n", __FUNCTION__,          \
				        __FILE__, __LINE__, ##__VA_ARGS__);                    \
		}                                                                      \
	} while (0)

#define LOG(fmt, ...) _LOG(0, fmt, ##__VA_ARGS__)

#define DEBUG(fmt, ...) _LOG(1, fmt, ##__VA_ARGS__)

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

static inline void
print_version(const char *prog)
{
	printf("%s - Version %s\n", prog, TO_STR(VERSION));
}

static inline void
dump(const char *msg, const char *data, size_t len)
{
	size_t curlen = 0;
	const char *ptr = data;
	char *curr;
	char *buff = malloc(2 * len + len / 4 + len / 32 + 2);
	if (!buff)
		return;
	curr = buff;

	while (curlen < len) {
		sprintf(curr, "%02x", *(ptr++) & 0xff);
		curr += 2;
		curlen++;
		if (!(curlen % 32)) {
			*(curr++) = '\n';
		} else if (!(curlen % 4)) {
			*(curr++) = ' ';
		}
	}
	*curr = '\0';

	if (msg)
		fprintf(stderr, "%s%s\n", msg, buff);
	else
		fprintf(stderr, "%s\n", buff);
	free(buff);
}

#endif /* _COMMON_PROTOS_H_ */
