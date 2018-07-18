#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

# Safe shell defaults
LANG="C"
LC_ALL="C"

# Fail systematically on non zero return code by default. This is disabled
# later for tests that are expected to fail.
set -eu
# Fail if any command fails when using pipes
set -o pipefail

# Set debug only if DEBUG is set to 'y'
if [ ! -z "${DEBUG+x}" ]; then
	export DEBUG
	if [ "${DEBUG}" == "y" ]; then
		set -x
	else
		set +x
	fi
fi

# Scripts sourcing those files were designed to run in the 'test' folder and
# work in the 'test/workdir' folder.
if [ "$(basename "${PWD}")" != "test" ]; then
	printf "This script must be run in the gencrypt/test/ directory.\n"
	exit 1
fi

# Enable file globing
shopt -s nullglob

# Setup base working directory. All paths should be relative to this and all
# commands should be launched from this directory
WORKDIR="workdir"

# Make sure we have selected which cryto to use
if [ -z "${CRYPTO+x}" ]; then
	echo "Environment variable \$CRYPTO not set. Use 'civil'.\n"
	exit 1
else
	export CRYPTO
	if [ "${CRYPTO}" != "civil" ] ; then
		printf "Invalid CRYPTO chosen: %s\n" "${CRYPTO}"
		exit 1
	fi
fi

# Make sure we have selected a date as a reference for this test run
if [ -z "${DATE+x}" ]; then
	export DATE
	DATE=$(date --iso=seconds)
else
	export DATE
fi

# Setup variables for directories in WORKDIR
# Unsigned packages directory. Files here should not be modified
UNSIGNED_PACKAGE_DIR="packages"
# Temporary directory used to keep package signed only by a developer
if [ "${CRYPTO}" == "civil" ]; then
	TMP_PACKAGE_DIR="mirror_${CRYPTO}_devonly-${KIND}"
fi
# Final mirror used for testing
if [ "${CRYPTO}" == "civil" ]; then
	SIGNED_PACKAGE_DIR="mirror_${CRYPTO}-${KIND}"
fi
# Execution logs from all commands for this test run
LOG_DIR="logs/${DATE}"
export LOG_DIR
# Logs from Valgrind for this test run
VALGRIND_LOG_DIR="logs/${DATE}_valgrind"
mkdir -p "${WORKDIR}/${LOG_DIR}" "${WORKDIR}/${VALGRIND_LOG_DIR}"

export VALGRIND
export VALGRIND_CMD
export VALGRIND_PROG
VALGRIND_CMD=""
# Setup Valgrind variables if VALGRIND is set to 'y'
if [ ! -z "${VALGRIND+x}" ]; then
	if [ "${VALGRIND}" == "y" ]; then
		VALGRIND_CMD="valgrind --trace-children=yes --log-file=${VALGRIND_LOG_DIR}/%q{CRYPTO}_%q{VALGRIND_PROG}_PID:%p.log --"
		# VALGRIND_CMD="valgrind --trace-children=yes --log-file=${VALGRIND_LOG_DIR}/%q{PROG}_%q{DATE}_PID:%p.log --"
	fi
fi

# Path to binaries used for testing. BIN is relative to CWD which is WORKDIR
BIN=../../build_"${CRYPTO}"/
SIGN=${BIN}/sign
CHECK=${BIN}/check
CHECK_CLIENT=${BIN}/check-client
CHECK_DAEMON=${BIN}/check-daemon

DAEMON_SOCKET=./tmp_daemon_socket

# Where to find the program to falsify signature of well-formed packages (i.e.
# with a dev_sign tag and a ctrl_sign tag). This is called in falsify, which
# creates bad archives suffixed by .badsig. This suffix is used by function
# should_fail to tell that verification should not succeed.
BAD_SIGN=${BIN}/change_pkg_sig

# Set default verbosity for all gencrypt commands.
# Use "-V" for info and "-V -V" for debug
VERBOSITY="-V -V"

# Name of an invalid Debian package
BAD_PKG_NAME="random.deb"
# Name of a valid Debian package
GOOD_PKG_NAME="foo_0.1-1_all.deb"

# Source crypto specific environment files
if [ "${CRYPTO}" == "civil" ]; then
	source "./environment.civil.sh"
else
	printf "Invalid CRYPTO chosen: %s\n" "${CRYPTO}"
	exit 1
fi
