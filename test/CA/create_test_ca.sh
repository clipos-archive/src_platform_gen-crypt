#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./create_test_ca.functions.bash"

###############################################################################

BASEDIR="${PWD}"
BUILD="test_ca"
CONFIG_DIR="config"
BAD_CERT_SCRIPT="${BASEDIR}/bad_cert.py"

mkdir -p "${BUILD}"

###############################################################################
# Create two CAs, one for developpers and one for controllers.
# Create 3 dev/cont keys/certs and revoke the third one for each CA.
# Generate CRLs.

KIND="2CA_NoSubCA"
OUTPUT="${BASEDIR}/${BUILD}/${KIND}"
LOG_FILE="${BASEDIR}/${BUILD}/${KIND}.log"

printf "Creating %s...\n" "${KIND}"
{
echo "Cleaning previously generated CA..."
rm -rf "${OUTPUT}"
mkdir -p "${OUTPUT}"

echo "Generating CA..."

TYPE_FULL="developer"
TYPE="dev"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Arborting."
	exit 1
fi

pushd "${OUTPUT}"
prepare_ca
create_ca
create_cert 1
create_cert 2
encrypt_privkey 2
create_cert 3
create_cert 4 "-startdate 20180101120000 -enddate 20190101120000"
tag_as_notyetvalid 4
create_cert 5 "-enddate 20150101120000"
tag_as_perempted 5
create_crl
revoke_cert 3
tag_as_revoked 3
create_bad_cert 1
create_bad_crl
create_expired_crl "default"
create_hashed_dir
popd

TYPE_FULL="controller"
TYPE="cont"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Arborting."
	exit 1
fi

pushd "${OUTPUT}"
prepare_ca
create_ca
create_cert 1
create_cert 2
encrypt_privkey 2
create_cert 3
create_cert 4 "-startdate 20180101120000 -enddate 20190101120000"
tag_as_notyetvalid 4
create_cert 5 "-enddate   20150101120000"
tag_as_perempted 5
create_crl
revoke_cert 3
tag_as_revoked 3
create_bad_cert 1
create_bad_crl
create_expired_crl "default"
create_hashed_dir
popd

echo "Generating CA: OK"
} &> "${LOG_FILE}"
printf "Creating %s: Done\n" "${KIND}"

###############################################################################
# Create one CA and two sub CA, one for developpers and one for controllers.
# Create 3 dev/cont keys/certs and revoke the third one for each sub CA.
# Generate CRLs.

KIND="1CA_2SubCA"
OUTPUT="${BASEDIR}/${BUILD}/${KIND}"
LOG_FILE="${BASEDIR}/${BUILD}/${KIND}.log"

printf "Creating %s...\n" "${KIND}"
{
echo "Cleaning previously generated CA..."
rm -rf "${OUTPUT}"
mkdir -p "${OUTPUT}"

echo "Generating CA..."

TYPE_FULL="developer"
TYPE="root"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"

pushd "${OUTPUT}"
prepare_ca
create_ca
create_crl
popd

TYPE_FULL="developer"
TYPE="dev"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_SUBCA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_SubCA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Arborting."
	exit 1
fi

pushd "${OUTPUT}"
prepare_ca
create_subca
create_cert_subca 1
create_cert_subca 2
encrypt_privkey 2
create_cert_subca 3
create_cert_subca 4 "-startdate 20180101120000 -enddate 20190101120000"
tag_as_notyetvalid 4
create_cert_subca 5 "-enddate   20150101120000"
tag_as_perempted 5
create_crl_subca
revoke_cert_subca 3
tag_as_revoked 3
create_bad_cert 1
create_bad_crl
create_expired_crl "sub"
create_hashed_dir
popd

TYPE_FULL="controller"
TYPE="cont"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_SUBCA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_SubCA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Arborting."
	exit 1
fi

pushd "${OUTPUT}"
prepare_ca
create_subca
create_cert_subca 1
create_cert_subca 2
encrypt_privkey 2
create_cert_subca 3
create_cert_subca 4 "-startdate 20180101120000 -enddate 20190101120000"
tag_as_notyetvalid 4
create_cert_subca 5 "-enddate   20150101120000"
tag_as_perempted 5
create_crl_subca
revoke_cert_subca 3
tag_as_revoked 3
create_bad_cert 1
create_bad_crl
create_expired_crl "sub"
create_hashed_dir
popd

echo "Generating CA: OK"
} &> "${LOG_FILE}"
printf "Creating %s: Done\n" "${KIND}"

###############################################################################
# Create two CA and two sub CA, one for developpers and one for controllers.
# Create 3 dev/cont keys/certs and revoke the third one for each sub CA.
# Generate CRLs.

# KIND="2CA_2SubCA"

# TODO

###############################################################################

echo "Done"
