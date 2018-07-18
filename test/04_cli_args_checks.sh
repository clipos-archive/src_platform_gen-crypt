#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

# Temporarily copy a package for testing
TMP_SIGN_PACKAGE="./tmp_sign_package.deb"
cp "${UNSIGNED_PACKAGE_DIR}/${GOOD_PKG_NAME}" "${TMP_SIGN_PACKAGE}"
export TMP_SIGN_PACKAGE

# Find a good package
if [ "${CRYPTO}" == "civil" ]; then
	GOOD_PREFIX="cont_1-cont_1__dev_1-dev_1"
fi
GOOD_PACKAGE="${SIGNED_PACKAGE_DIR}/${GOOD_PREFIX}__${GOOD_PKG_NAME}"
export GOOD_PACKAGE

###############################################################################

printf "Checking %s binaries argument handling...\n\n" "${CRYPTO}"

../04_cli_args_checks.py

rm ./"${TMP_SIGN_PACKAGE}"

printf "Checking %s binaries argument handling: OK\n\n" "${CRYPTO}"

popd

printf "Done\n"
