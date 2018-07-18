#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

###############################################################################

# CRYPTO=civil KIND=1CA_2SubCA ./sign_package.sh \
# 	/opt/mirrors/remote/branches/stable-4.4.2/civil/rm/ \
# 	/home/user/git/gencrypt/test/CA/test_CA/${KIND}/dev/private/dev_1.pem \
# 	/home/user/git/gencrypt/test/CA/test_CA/${KIND}/dev/certs/dev_1.pem

PKG="${1}"

if [ "${CRYPTO}" == "civil" ]; then
	DEV_KEY="/home/user/git/gen-crypt/test/CA/test_ca/${KIND}/dev/private/dev_1.pem"
	DEV_CERT="/home/user/git/gen-crypt/test/CA/test_ca/${KIND}/dev/certs/dev_1.pem"
	CONT_KEY="/home/user/git/gen-crypt/test/CA/test_ca/${KIND}/cont/private/cont_1.pem"
	CONT_CERT="/home/user/git/gen-crypt/test/CA/test_ca/${KIND}/cont/certs/cont_1.pem"
else
	printf "Invalid CRYPTO chosen: %s\n" "${CRYPTO}"
	exit 1
fi

if [ -d "${PKG}" ]; then
	for f in "${PKG}"/*.deb ; do
		sign_pkg_inplace 'dev' "${f}" "${DEV_KEY}" "${DEV_CERT}"
		sign_pkg_inplace 'cont' "${f}" "${CONT_KEY}" "${CONT_CERT}"
		echo ""
	done
elif [ -f "${PKG}" ]; then
	sign_pkg_inplace 'dev' "${PKG}" "${DEV_KEY}" "${DEV_CERT}"
	sign_pkg_inplace 'cont' "${PKG}" "${CONT_KEY}" "${CONT_CERT}"
else
	echo "Nothing to do here"
fi
