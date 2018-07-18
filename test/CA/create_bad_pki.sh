#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

source "./environment.sh"
source "./create_test_ca.functions.bash"

###############################################################################

BASEDIR="${PWD}"
BUILD="bad_pki"
LOG_DIR="${BUILD}_logs"
CONFIG_DIR="config"

mkdir -p "${BUILD}"
mkdir -p "${LOG_DIR}"

###############################################################################
# Creation of minimal correct developper PKI + bad controller PKIs, using
# bad extensions for the CA certificate or for the end-user certificates
# Creates :
#  - a correct developper PKI in {BUILD}/2CA_NoSubCA/dev_pki
#  - a controller PKI with a root and a certificate
#  for each possible version of "bad" attributes.
#  Each PKI has only a default : either a root with bad attributes or a
#  collection of certificates with bad attributes.
#  PKIs with bad roots can be found in {BUILD}/2CA_NoSubCA/{bad} where bad
#  captures what is wrong with the attributes of the root certif.
#  PKI with good root and bad leaf certificates is stored in
#  {BUILD}/2CA_NoSubCA/certs_bad_attr/


KIND="2CA_NoSubCA"
printf "Creating %s...\n" "${KIND}"

echo "Generating PKI..."

TYPE_FULL="developer"
TYPE="dev"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Aborting."
	exit 1
fi

OUTPUT="${BASEDIR}/${BUILD}/${KIND}/dev_pki"
LOG_FILE="${BASEDIR}/${LOG_DIR}/${KIND}_dev.log"
{
	echo "Cleaning previously generated PKI..."
	rm -rf "${OUTPUT}"
	mkdir -p "${OUTPUT}"

	pushd "${OUTPUT}"
	prepare_ca
	create_ca
	create_cert 1
	create_crl
	create_hashed_dir
	popd

	echo "Generating PKI: OK"
} &> "${LOG_FILE}"


TYPE_FULL="controller"
TYPE="cont"
CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"
INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

# Config file must be there
if [ ! -f "${CONFIG}" ]; then
	echo "Need OpenSSL configuration files. Aborting."
	exit 1
fi

BAD_LIST=( "bad_v3_x509_ca_cafalse" "bad_v3_x509_ca_manyusage" "bad_v3_x509_ca_manyusage_2" "bad_v3_x509_ca_missingusage" "bad_v3_x509_ca_missingBC" "bad_v3_x509_ca_nousage")

for bad in "${BAD_LIST[@]}"; do
	OUTPUT="${BASEDIR}/${BUILD}/${KIND}/${bad}"
	LOG_FILE="${BASEDIR}/${LOG_DIR}/${KIND}_${bad}.log"
	{
		echo "Cleaning previously generated PKI..."
		rm -rf "${OUTPUT}"
		mkdir -p "${OUTPUT}"

		pushd "${OUTPUT}"
		prepare_ca
		create_bad_ca "${bad}"
		create_cert 1
		create_crl
		create_hashed_dir
		popd

		echo "Generating PKI: OK"
	} &> "${LOG_FILE}"
done

BAD_LIST=( "bad_v3_x509_sign_ctrl_manyusage" "bad_v3_x509_sign_ctrl_missingusage" "bad_v3_x509_sign_ctrl_nousage")

OUTPUT="${BASEDIR}/${BUILD}/${KIND}/certs_bad_attrs/"
LOG_FILE="${BASEDIR}/${LOG_DIR}/${KIND}_certs_bad_attrs.log"

{
	echo "Cleaning previously generated PKI with certs with bad attributes..."

	rm -rf "${OUTPUT}"
	mkdir -p "${OUTPUT}"

	pushd "${OUTPUT}"
	prepare_ca
	create_ca
	i=0
	for bad in "${BAD_LIST[@]}"; do
		create_cert_bad_attr ${bad} $i
		((i +=1))
	done
	create_crl
	create_hashed_dir
	popd

	echo "Generating PKI: OK"
} &> "${LOG_FILE}"

printf "Creating bad %s controller PKIs: Done\n" "${KIND}"

##############################################################################
# Create one root CA and two sub CA, one for developpers and one for controllers,
# plus one leaf certificate for each subCA.
# Creation of :
#  - bad root CA and sound subCAs.
#  - sound root CA and developper subCA, bad controller subCA
#  Resulting PKI are store in repos named {BUILD}/1CA_2SubCA/{bad}
#  where {bad} is named after what is wrong and is tagged with 'ca' or 'subca'
#  to distinguish between cases.
# nb : the case of bad leaf certificates is already treated by tests above
# it is omitted here.

KIND="1CA_2SubCA"
BAD_LIST=( "bad_v3_x509_ca_cafalse" "bad_v3_x509_ca_manyusage" "bad_v3_x509_ca_manyusage_2" "bad_v3_x509_ca_missingusage" "bad_v3_x509_ca_missingBC" "bad_v3_x509_ca_nousage")

for bad in "${BAD_LIST[@]}"; do
	TYPE_FULL="controller"
	TYPE="root"
	CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
	INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"

	OUTPUT="${BASEDIR}/${BUILD}/${KIND}/${bad}"
	LOG_FILE="${BASEDIR}/${LOG_DIR}/${KIND}_${bad}.log"
	printf "Creating %s...\n" "${KIND}_${bad}"
	{
		echo "Cleaning previously generated PKI..."
		rm -rf "${OUTPUT}"
		mkdir -p "${OUTPUT}"

		echo "Generating PKI..."

		pushd "${OUTPUT}"
		prepare_ca
		create_bad_ca ${bad}
		create_crl
		popd

		TYPE_FULL="developer"
		TYPE="dev"
		CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
		INPUTS_SUBCA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_SubCA_inputs.txt"
		INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

		# Config file must be there
		if [ ! -f "${CONFIG}" ]; then
			echo "Need OpenSSL configuration files. Aborting."
			exit 1
		fi

		pushd "${OUTPUT}"
		prepare_ca
		create_subca
		create_cert_subca 1
		create_crl_subca
		create_hashed_dir
		popd

		TYPE_FULL="controller"
		TYPE="cont"
		CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
		INPUTS_SUBCA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_SubCA_inputs.txt"
		INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

		# Config file must be there
		if [ ! -f "${CONFIG}" ]; then
			echo "Need OpenSSL configuration files. Aborting."
			exit 1
		fi

		pushd "${OUTPUT}"
		prepare_ca
		create_subca
		create_cert_subca 1
		create_crl_subca
		create_hashed_dir
		popd

		echo "Generating CA: OK"
	} &> "${LOG_FILE}"
done
printf "Creating %s: Done\n" "${KIND}"

BAD_LIST=( "bad_v3_x509_subca_cafalse" "bad_v3_x509_subca_manyusage" "bad_v3_x509_subca_manyusage_2" "bad_v3_x509_subca_missingusage" "bad_v3_x509_subca_missingBC" "bad_v3_x509_subca_nousage")

for bad in "${BAD_LIST[@]}"; do
	TYPE_FULL="controller"
	TYPE="root"
	CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
	INPUTS_CA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_CA_inputs.txt"

	OUTPUT="${BASEDIR}/${BUILD}/${KIND}/${bad}"
	LOG_FILE="${BASEDIR}/${LOG_DIR}/${KIND}_${bad}.log"
	printf "Creating %s...\n" "${KIND}_${bad}"
	{
		echo "Cleaning previously generated PKI..."
		rm -rf "${OUTPUT}"
		mkdir -p "${OUTPUT}"

		echo "Generating PKI..."

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
			echo "Need OpenSSL configuration files. Aborting."
			exit 1
		fi

		pushd "${OUTPUT}"
		prepare_ca
		create_subca
		create_cert_subca 1
		create_crl_subca
		create_hashed_dir
		popd

		TYPE_FULL="controller"
		TYPE="cont"
		CONFIG="${BASEDIR}/${CONFIG_DIR}/${KIND}/${TYPE_FULL}.cnf"
		INPUTS_SUBCA="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_SubCA_inputs.txt"
		INPUTS_CERT="${BASEDIR}/${CONFIG_DIR}/${TYPE_FULL}_cert_inputs.txt"

		# Config file must be there
		if [ ! -f "${CONFIG}" ]; then
			echo "Need OpenSSL configuration files. Aborting."
			exit 1
		fi

		pushd "${OUTPUT}"
		prepare_ca
		create_bad_subca ${bad}
		create_cert_subca 1
		create_crl_subca
		create_hashed_dir
		popd

		echo "Generating CA: OK"
	} &> "${LOG_FILE}"
done


################################################################################
## Create two CA and two sub CA, one for developpers and one for controllers.
## Create 3 dev/cont keys/certs and revoke the third one for each sub CA.
## Generate CRLs.
#
## KIND="2CA_2SubCA"
#
## TODO
#
################################################################################

echo "Done"
