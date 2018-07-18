#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

# Find the name of a good package for interleaving purposes
if [ "${CRYPTO}" == "civil" ]; then
	GOOD_PREFIX="cont_1-cont_1__dev_1-dev_1"
fi
GOOD_PKG="${SIGNED_PACKAGE_DIR}/${GOOD_PREFIX}__${GOOD_PKG_NAME}"

###############################################################################

printf "Checking %s mirror using daemon...\n\n" "${CRYPTO}"

packages=("${SIGNED_PACKAGE_DIR}"/*)
frequency=4
# printf "frequency is %s\n" "${frequency}"
counter=0

daemon_start

echo ""

# As somme commands will fail here, we need to disable 'set -e'
set +e

for p in "${packages[@]}"; do
	if [ $((counter % 5)) -eq ${frequency} ]; then
		daemon_check_package "${GOOD_PKG}"
		should_fail "${GOOD_PKG}" "${?}"
		echo ""
	fi
	daemon_check_package "${p}"
	should_fail "${p}" "${?}"
	echo ""
done

# Go back to safety
set -e

echo ""

daemon_stop

printf "Checking %s mirror using daemon: OK\n\n" "${CRYPTO}"

popd

printf "Done\n"
