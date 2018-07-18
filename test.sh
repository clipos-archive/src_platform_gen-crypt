#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

# This script is documented in the Doxygen generated HTML documentation. See
# README for more information.

# Safe shell defaults
LANG="C"
LC_ALL="C"
set -eu
set -o pipefail
# Force debug ouput
#set -x

###############################################################################

compile() {
	# Set code coverage only if COVERAGE is set to 'y'
	local enable_coverage=""
	if [ ! -z "${COVERAGE+x}" ]; then
		if [ "${COVERAGE}" == "y" ]; then
			enable_coverage="--enable-coverage"
		fi
	fi

	printf "Compiling %s binaries...\n" "${CRYPTO}"
	{
		rm -rf "./build_${CRYPTO}"
		mkdir -p "build_${CRYPTO}"
		pushd "build_${CRYPTO}"
		autoreconf -fiv ..
		../configure --enable-sign --with-crypto="${CRYPTO}" --enable-testing "${enable_coverage}"
		make -j8 build
		make -j8 build_test
		popd
	} &> "${_LOG_DIR}/${CRYPTO}-00_compile.log"
	printf "Compiling %s binaries: OK\n" "${CRYPTO}"
}

prepare_mirror() {
	printf "Preparing %s package mirror...\n" "${CRYPTO}${SUFFIX}"
	{
		pushd test
		./01_prepare_mirror.sh
		popd
	} &> "${_LOG_DIR}/${CRYPTO}${SUFFIX}-01_prepare_mirror.log"
	printf "Preparing %s package mirror: OK\n" "${CRYPTO}${SUFFIX}"
}

prepare_test_ca() {
	printf "Preparing %s test CA...\n" "${CRYPTO}"
	{
		pushd test/CA
		./create_test_ca.sh
		./create_bad_pki.sh
		popd
	} &> "${_LOG_DIR}/${CRYPTO}-00_prepare_test_CA.log"
	printf "Preparing %s test CA: OK\n" "${CRYPTO}"
}

mirror_check() {
	printf "Checking %s mirror using 'check'...\n" "${CRYPTO}${SUFFIX}"
	{
		pushd test
		./02_check_mirror.sh
		popd
	} &> "${_LOG_DIR}/${CRYPTO}${SUFFIX}-02_check_mirror.log"
	printf "Checking %s mirror using 'check': OK\n" "${CRYPTO}${SUFFIX}"
}

mirror_check-daemon() {
	printf "Checking %s mirror using 'check-daemon'...\n" "${CRYPTO}${SUFFIX}"
	{
		pushd test
		./03_check_daemon_mirror.sh
		popd
	} &> "${_LOG_DIR}/${CRYPTO}${SUFFIX}-03_check_client_mirror.log"
	printf "Checking %s mirror using 'check-daemon': OK\n" "${CRYPTO}${SUFFIX}"
}

cli_args_checks() {
	printf "Checking %s binaries with various arguments...\n" "${CRYPTO}${SUFFIX}"
	{
		# Output redirection partially done by the python script
		pushd test
		./04_cli_args_checks.sh
		popd
	} &> "${_LOG_DIR}/${CRYPTO}${SUFFIX}-04_cli_args_checks.log"
	printf "Checking %s binaries with various arguments: OK\n" "${CRYPTO}${SUFFIX}"
}

code_coverage() {
	if [ ! -z "${COVERAGE+x}" ]; then
		if [ "${COVERAGE}" == "y" ]; then
			local output="../${_LOG_DIR}/${CRYPTO}${SUFFIX}_coverage.gcov"

			printf "Code covered by tests for %s crypto:\n" "${CRYPTO}${SUFFIX}"
			pushd "build_${CRYPTO}" > /dev/null
			gcov --branch-probabilities --no-output --function-summaries \
				$(ls ./*.o | grep -vE "change_pkg_sig.o") \
				> "${output}"
			tail -n1 "${output}"
			popd > /dev/null
		fi
	fi
}

###############################################################################

test_civil() {
	# Make sure some variables are set properly
	CRYPTO="civil"

	compile
	if [ ! -z "${COMPILE_ONLY+x}" ]; then
		if [ "${COMPILE_ONLY}" == "y" ]; then
			return 0
		fi
	fi
	prepare_test_ca
	if [ ! -z "${PREPARE_ONLY+x}" ]; then
		if [ "${PREPARE_ONLY}" == "y" ]; then
			return 0
		fi
	fi

	# We have to create a mirror for each PKI created
	KIND="1CA_2SubCA"
	SUFFIX="-${KIND}"

	prepare_mirror
	mirror_check
	mirror_check-daemon
	cli_args_checks
	code_coverage

	# We have to create a mirror for each PKI created
	KIND="2CA_NoSubCA"
	SUFFIX="-${KIND}"

	prepare_mirror
	mirror_check
	mirror_check-daemon
	cli_args_checks
	code_coverage
}

###############################################################################

# Set a date as a reference for this test run
export DATE
DATE=$(date --iso=seconds)

# Variables prefixed by '_' to avoid conflicts with other variables in scripts
# in the test folder. They are specific to this script.
_WORKDIR="workdir"
_LOG_DIR="test/${_WORKDIR}/logs/${DATE}"
mkdir -p "${_LOG_DIR}"

printf "Test run '%s', log dir '%s'\n" "${DATE}" "${_LOG_DIR}"

export CRYPTO
export KIND

# If a specific crypto is selected then run only those tests. Run everything if
# nothing is specified.
if [ -z "${CRYPTO+x}" ]; then
	printf "Running civil tests...\n"
	test_civil
else
	if [ "${CRYPTO}" == "civil" ] ; then
		printf "Running civil tests...\n"
		test_civil
	else
		printf "Invalid CRYPTO chosen: '%s'\n" "${CRYPTO}"
		exit 1
	fi
fi

echo "Done"
