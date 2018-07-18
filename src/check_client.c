// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file check_client.c
 * Client for the clip signature checking daemon
 *
 * Copyright (C) 2011 SGDSN/ANSSI
 *
 * @author Vincent Strubel <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "common-protos.h"

#include <clip/clip.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

int g_verbose = 0;
int g_daemonized = 0;

static void
print_help(const char *prog)
{
	printf("%s - Client to send packages to check-daemon\n", prog);
	printf("Usage: %s [options]\n", prog);
	puts("With options:");
	puts("  -S <sock>  connect to the checker daemon through socket <sock>");
	puts("");
	puts("  -c <pkg>   send package <pkg> to the daemon for checking");
	puts("  -q         send the quit command to the daemon");
	puts("");
	puts("  -h         display this help and exit");
	puts("  -v         display version number and exit");
	puts("  -V         be more verbose: set once for log messages, twice for");
	puts("             debug");
}

static int
send_file(int sock, const char *fpath)
{
	int fd;
	char c;
	int ret = -1;

	fd = open(fpath, O_RDONLY, 0);
	if (fd < 0) {
		ERROR_ERRNO("Failed to open %s", fpath);
		return ret;
	}

	c = 'C';
	if (write_fd(sock, &c, 1)) {
		ERROR("Failed to send check command");
		goto out;
	}

	if (clip_send_fd(sock, fd)) {
		ERROR_ERRNO("Failed to send file descriptor");
		goto out;
	}

	if (read_fd(sock, &c, 1)) {
		ERROR("Failed to read daemon answer");
		goto out;
	}

	if (c == 'Y') {
		LOG("Signature check OK for %s", fpath);
		ret = 0;
	} else {
		ERROR("Signature check failed for %s", fpath);
	}

/* Fall through */
out:
	close(fd);
	return ret;
}

static int
do_connect(const char *sockpath)
{
	int sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		ERROR("Failed to create socket");
		return EXIT_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	int ret = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
	// snprintf will never return a negative value as we are not writting
	// to a terminal.
	if (ret < 0 ) {
		ERROR("Unexpected error: %s\n", sockpath);
		return -1;
	} else if ((size_t)ret >= sizeof(addr.sun_path)) {
		ERROR("Path too long: %s\n", sockpath);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		ERROR_ERRNO("Failed to connect to %s", sockpath);
		return -1;
	}

	return sock;
}

int
main(int argc, char *argv[])
{
	int sock;
	const char *sockpath = NULL, *fpath = NULL;
	const char *prog = basename(argv[0]);
	int do_check = 0, do_quit = 0;
	int c;

	while ((c = getopt(argc, argv, "hS:vVc:q")) != -1) {
		switch (c) {
			case 'S':
				sockpath = optarg;
				break;
			case 'c':
				fpath = optarg;
				do_check++;
				break;
			case 'q':
				do_quit++;
				break;
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
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

	if (do_check + do_quit == 0) {
		ERROR("Missing command, either check or quit");
		print_help(prog);
		return EXIT_FAILURE_BAD_ARGS;
	}
	if (do_check + do_quit > 1) {
		ERROR("Too many commands in the arguments, only one can be sent");
		print_help(prog);
		return EXIT_FAILURE_BAD_ARGS;
	}

	sock = do_connect(sockpath);
	if (sock == -1) {
		ERROR("Failed to create socket");
		return EXIT_FAILURE;
	}

	if (do_check) {
		if (send_file(sock, fpath) != 0) {
			close(sock);
			return EXIT_FAILURE;
		}
	} else if (do_quit) {
		/* Send quit command */
		char c = 'Q';
		if (write_fd(sock, &c, 1) != 0) {
			close(sock);
			return EXIT_FAILURE;
		}
	}
	close(sock);

	return EXIT_SUCCESS;
}
