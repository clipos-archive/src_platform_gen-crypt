#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./functions.sh"

pushd "${WORKDIR}"

###############################################################################

# CRYPTO=civil KIND=1CA_2SubCA ./check_package.sh /opt/mirrors/remote/branches/stable-4.4.2/civil/rm/

if [ -d "${1}" ]; then
	for f in "${1}"/*.deb ; do
		check_package ${f}
		echo ""
	done
elif [ -f "${1}" ]; then
	check_package ${1}
else
	echo "Nothing to do here"
fi
