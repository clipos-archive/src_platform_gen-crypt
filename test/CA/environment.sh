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

# Simple check to avoid unfortunate mistakes
if [ "$(basename "${PWD}")" != "CA" ]; then
	echo "This must be run inside the gencrypt/test/CA directory. Aborting."
	exit 1
fi
