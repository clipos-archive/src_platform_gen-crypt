#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

###############################################################################

printf "Preparing %s mirror...\n\n" "${CRYPTO}"

# Clear mirror directories
rm -rf ./"${TMP_PACKAGE_DIR}"/
rm -rf ./"${SIGNED_PACKAGE_DIR}"/
mkdir -p "${TMP_PACKAGE_DIR}" "${SIGNED_PACKAGE_DIR}"

generate_fake_package

echo ""

packages_sign_developer
echo ""
packages_sign_controller
echo ""
packages_sign_falsify

echo ""

generate_fake_signed_package

printf "Preparing %s mirror: OK\n\n" "${CRYPTO}"

popd

printf "Done\n"
