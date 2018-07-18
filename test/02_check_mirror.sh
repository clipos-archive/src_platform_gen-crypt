#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

###############################################################################

printf "Checking %s mirror...\n\n" "${CRYPTO}"

# As somme commands will fail here, we need to disable 'set -e'
set +e

packages=(${SIGNED_PACKAGE_DIR}/*)
for p in "${packages[@]}"; do
	check_package "${p}"
	should_fail "${p}" ${?}
	echo ""
done

# Go back to safety
set -e

printf "Checking %s mirror: OK\n\n" "${CRYPTO}"

popd

printf "Done\n"
