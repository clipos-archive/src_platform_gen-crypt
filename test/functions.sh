#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

if [ "${CRYPTO}" == "civil" ]; then
	printf "Using crypto: %s\n" "${CRYPTO}"
else
	printf "Invalid CRYPTO chosen: %s\n" "${CRYPTO}"
	exit 1
fi

# Sign a package inplace. Does not use Valgrind when CRYPTO == civil
# sign_pkg_inplace (dev|cont) <package> <private_key> <certificate>
sign_pkg_inplace() {
	local sign_type="${1}"
	local pkg="${2}"
	local key="${3}"
	local cert="${4}"

	local pkg_name="$(basename "${pkg}")"
	local sign_arg=""
	local cert_name=""
	local key_name=""

	if [ "${CRYPTO}" == "civil" ]; then
		cert_name="$(basename "${cert}" ".pem")"
		key_name="$(basename "${key}" ".pem")"
	fi

	printf "Signing package '%s' with %s key '%s'\n" "${pkg_name}" \
		"${sign_type}" "${key_name}"

	if [ "${sign_type}" == "dev" ]; then
		sign_arg="-D"
	elif [ "${sign_type}" == "cont" ]; then
		sign_arg="-C"
	else
		printf "Invalid sign_type: '%s'. Using 'dev' as default\n" \
			"${sign_type}"
		sign_arg="-D"
	fi

	# Running civil tests with Valgrind is too slow as we have thousands of
	# packages to sign. As a memory leaks and errors in sign are less
	# critical, we skip this check in the general case.
	if [ "${CRYPTO}" == "civil" ]; then
		${SIGN} ${VERBOSITY} "${sign_arg}" \
			-k "${key}" -c "${cert}" "${pkg}"
	fi
}

# Copy and then sign a package. Does not use Valgrind when CRYPTO == civil
# sign_pkg (dev|cont) <package> <private_key> <certificate>
sign_pkg() {
	local sign_type="${1}"
	local pkg="${2}"
	local key="${3}"
	local cert="${4}"

	local pkg_name="$(basename "${pkg}")"
	local cert_name=""
	local key_name=""

	if [ "${CRYPTO}" == "civil" ]; then
		cert_name="$(basename "${cert}" ".pem")"
		key_name="$(basename "${key}" ".pem")"
	fi

	if [ "${sign_type}" == "dev" ]; then
		local dest="${TMP_PACKAGE_DIR}/${key_name}-${cert_name}__${pkg_name}"
	elif [ "${sign_type}" == "cont" ]; then
		local dest="${SIGNED_PACKAGE_DIR}/${key_name}-${cert_name}__${pkg_name}"
	fi

	cp "${pkg}" "${dest}"

	sign_pkg_inplace "${sign_type}" "${dest}" "${key}" "${cert}"
}

# TODO
# Creates all possible dev_tags with all possible pair (private key,
# certificate).
# NB : they DO NOT have to match for the signing program to work. Fills in
# TMP_MIRROR
packages_sign_developer() {
	local packages=(${UNSIGNED_PACKAGE_DIR}/*.deb)

	for p in "${packages[@]}"; do
		for k in "${PRIV_KEYS[@]}"; do
			for c in "${CERTS[@]}"; do
				sign_pkg 'dev' "${p}" "${k}" "${c}"
			done
		done
	done
}

# TODO
# Fills in MIRROR
packages_sign_controller() {
	local packages=(${TMP_PACKAGE_DIR}/*.deb)

	for p in "${packages[@]}"; do
		for k in "${PRIV_KEYS[@]}"; do
			for c in "${CERTS[@]}"; do
				sign_pkg 'cont' "${p}" "${k}" "${c}"
			done
		done
	done
}

# Check if the package name matches the signed package regular expression.
# Returns 0 if the package signature is supposed to be valid.
# Returns 1 otherwise.
is_signed_package() {
	local pkg_name="${1}"

	for exp in "${GOOD_PKG_REGEXP[@]}"; do
		if [[ "${pkg_name}" = ${exp} ]]; then
			return 0
		fi
	done
	return 1
}

# Check if the package is corresponding to a valid signed package.
# Returns 0 if a package is signed and supposed valid.
# Returns 1 otherwise.
is_valid_package() {
	local pkg="${1}"

	local bad_pkg_names="*${BAD_PKG_NAME}"
	local badsig="*.bad*sig"

	if is_signed_package "$(basename ${pkg})" ; then
		if [[ "$(basename ${pkg})" = ${bad_pkg_names} ]] ||
			[[ "$(basename ${pkg})" = ${badsig} ]]; then
			# printf "${pkg} is not a valid package\n"
			return 1
		fi
		# printf "valid package\n"
		return 0
	else
		# printf "%s is an invalid package\n" "${pkg}"
		return 1
	fi
}

# TODO
falsify_ctrl_sign() {
	local pkg="${1}"

	local target="${pkg}.badctrlsig"

	if is_valid_package "${pkg}"; then
		printf "Falsifying '%s'\n" "${pkg}"
		cp "${pkg}" "${target}"
		${BAD_SIGN} -c "${target}"
	# else
	# 	printf "Invalid package '%s': will not be create false sig\n" "${pkg}"
	fi
}

# TODO
falsify_dev_sign() {
	local pkg="${1}"
	local target="${pkg}.baddevsig"

	if is_valid_package "${pkg}"; then
		cp "${pkg}" "${target}"
		${BAD_SIGN} -d "${target}"
	# else
	# 	printf "Invalid package %s': will not be create false sig\n" "${pkg}"
	fi
}

# TODO
packages_sign_falsify() {
	local packages=(${SIGNED_PACKAGE_DIR}/*.deb)

	for p in "${packages[@]}"; do
		falsify_ctrl_sign "${p}"
		falsify_dev_sign "${p}"
	done
}

# Generate an invalid unsigned package from random content
generate_fake_package() {
	dd if=/dev/urandom of="${UNSIGNED_PACKAGE_DIR}/${BAD_PKG_NAME}" bs=512 count=10
}

# Generate an invalid "signed" package from random content
generate_fake_signed_package() {
	dd if=/dev/urandom of="${SIGNED_PACKAGE_DIR}/signed_${BAD_PKG_NAME}" bs=512 count=10
}

check_package() {
	local pkg="${1}"

	printf "Checking package: %s\n" "$(basename "${pkg}")"

	VALGRIND_PROG="check"

	if [ "${CRYPTO}" == "civil" ]; then
		${VALGRIND_CMD} ${CHECK} ${VERBOSITY} \
			-k "${DEV_ROOT_CA}" -K "${CONT_ROOT_CA}" \
			-l "${DEV_CRL}" -L "${CONT_CRL}" \
			-t "${DEV_TRUSTED_CA}" -T "${CONT_TRUSTED_CA}" \
			"${pkg}"
	fi
}

daemon_start() {
	printf "Starting check_daemon in background\n"

	VALGRIND_PROG="check-daemon"

	if [ "${CRYPTO}" == "civil" ]; then
		${VALGRIND_CMD} "${CHECK_DAEMON}" ${VERBOSITY} -S "${DAEMON_SOCKET}" \
			-k "${DEV_ROOT_CA}" -K "${CONT_ROOT_CA}" \
			-l "${DEV_CRL}" -L "${CONT_CRL}" \
			-t "${DEV_TRUSTED_CA}" -T "${CONT_TRUSTED_CA}" \
			-F -U &> "${LOG_DIR}/${CRYPTO}-03_check_daemon_mirror.log" &
	fi

	# Wait for daemon readiness: arbitrary value (may be set to 1 if not
	# running with Valgrind)
	sleep 5
}

daemon_stop() {
	printf "Stopping the check_daemon\n"

	VALGRIND_PROG="check-client"
	${VALGRIND_CMD} "${CHECK_CLIENT}" ${VERBOSITY} -S "${DAEMON_SOCKET}" -q
}

daemon_check_package() {
	local pkg="${1}"

	printf "Sending package '%s' to the daemon\n" "${pkg}"

	VALGRIND_PROG="check-client"
	${VALGRIND_CMD} "${CHECK_CLIENT}" ${VERBOSITY} -S "${DAEMON_SOCKET}" -c "${pkg}"
}

should_fail() {
	local pkg="${1}"
	local ret="${2}"

	if is_valid_package "${pkg}"; then
		printf "'%s' verification should be OK\n" "${pkg}"

		if [[ "${ret}" -ne 0 ]]; then
			printf "/!\\ Warning: package '%s' should be OK but verification failed!\n" \
				"$(basename "${pkg}")"
			printf "Return code was: %s\n" "${ret}"
			exit 1
		else
			printf "'%s' check was OK\n" "${pkg}"
		fi
	else
		printf "'%s' verification should fail\n" "${pkg}"

		if [[ "${ret}" -ne 1 ]]; then
			printf "/!\\ Warning: package '%s' is invalid but verification did not fail!\n" \
				"$(basename "${pkg}")"
			printf "Return code was: %s\n" "${ret}"
			exit 1
		else
			printf "'%s' check failed as expected\n" "${pkg}"
		fi
	fi
}
