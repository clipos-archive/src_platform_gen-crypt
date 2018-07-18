#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

function prepare_ca {
	mkdir -p "${TYPE}"/{certs,crl,csr,private}

	# Creation of file for openssl's database
	touch "${TYPE}"/index.txt
}

function create_ca {
	local privkey="${TYPE}/ca-privkey.pem"
	local cert="${TYPE}/cacert.pem"

	# Generating CA's secret key
	openssl ecparam -name brainpoolP256r1 -genkey  -param_enc explicit \
		-out "${privkey}"

	# Creation of the self-signed root certificate
	openssl req -config "${CONFIG}" -new -x509 -key "${privkey}" \
		-out "${cert}" -sha256 -extensions v3_x509_ca \
		< "${INPUTS_CA}"
}

function create_bad_ca {
   local exts="${1}"
   local privkey="${TYPE}/ca-privkey.pem"
	local cert="${TYPE}/cacert.pem"

	# Generating CA's secret key
	openssl ecparam -name brainpoolP256r1 -genkey  -param_enc explicit \
		-out "${privkey}"

	# Creation of the self-signed root certificate
	openssl req -config "${CONFIG}" -new -x509 -key "${privkey}" \
		-out "${cert}" -sha256 -extensions ${exts} \
		< "${INPUTS_CA}"
}


function generate_serial {
	# /!\ Serial initialization:
	# RGS-compliant serial numbers have to be random (and impredictible),
	# because serial numbers are the only revocation information used in CRL
	# creation!
	# THIS IS ONLY FOR TEST PURPOSES AND MUST NOT BE DONE IN PRODUCTION.
	printf "%s%s%s%s\n" "${num}" "${num}" "${num}" "${num}"
}

function create_cert {
	local num="${1}"
	local privkey="${TYPE}/private/${TYPE}_${num}.pem"
	local csr="${TYPE}/csr/${TYPE}_${num}.csr"
	local serial="${TYPE}/serial"
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"
	local args=""

	# Argument 2 is optional and used only for bad certificate tests
	if [ ! -z ${2+x} ]; then
		args="${2}"
	fi

	generate_serial > "${serial}"

	# Key pair: secret key generation
	openssl ecparam -name brainpoolP256r1 -genkey -param_enc explicit \
		-out "${privkey}"

	# Certificate signing request
	sed "s|Z|${num}|" "${INPUTS_CERT}" | \
	openssl req -new -key "${privkey}" -config "${CONFIG}" -out "${csr}"

	# Signature of the certificate by the CA
	printf 'y\ny\n' \
		| openssl ca -config "${CONFIG}" -md sha256 -policy policy_anything \
		-extensions v3_x509_sign_ctrl ${args} -out "${cert}" -infiles "${csr}"
}

tag_cert_as() {
	local num="${1}"
	local tag="${2}"
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"
	local new_cert="${TYPE}/certs/${tag}_${TYPE}_${num}.pem"

	printf "tag_cert_as %s" "${tag}"
	if [ ! -f "${cert}"]; then
		printf "Certificate %s could not be tagged, it does not exist\n" "${cert}"
	fi
	mv "${cert}" "${new_cert}"
}

create_cert_bad_attr() {
	local exts="${1}"
	local num="${2}"
	local privkey="${TYPE}/private/${TYPE}_${exts}.pem"
	local csr="${TYPE}/csr/${TYPE}_${exts}.csr"
	local serial="${TYPE}/serial"
	local cert="${TYPE}/certs/${TYPE}_${exts}.pem"

	generate_serial > "${serial}"

	# Key pair: secret key generation
	openssl ecparam -name brainpoolP256r1 -genkey -param_enc explicit \
		-out "${privkey}"

	# Certificate signing request
	sed "s|Z|${num}|" "${INPUTS_CERT}" | \
		openssl req -new -key "${privkey}" -config "${CONFIG}" -out "${csr}"

	# Signature of the certificate by the CA
	printf 'y\ny\n' \
		| openssl ca -config "${CONFIG}" -md sha256 -policy policy_anything \
		-extensions ${exts} -out "${cert}" -infiles "${csr}"
}

tag_as_perempted() {
	local num="${1}"
	tag_cert_as "${num}" "per"
}

tag_as_notyetvalid() {
	local num="${1}"
	tag_cert_as "${num}" "nyv"
}

tag_as_invalid() {
	local num="${1}"
	tag_cert_as "${num}" "inv"
}

tag_as_cut() {
	local num="${1}"
	tag_cert_as "${num}" "_cut"
}

tag_as_revoked() {
	local num="${1}"
	tag_cert_as "${num}" "rev"
}

function encrypt_privkey {
	local num="${1}"
	local privkey="${TYPE}/private/${TYPE}_${num}.pem"
	local privkey_enc="${privkey}.enc"

	openssl ec -in "${privkey}" -aes-256-cbc -out "${privkey_enc}" \
		-passout "pass:test"
}

function create_crl {
	local number="${TYPE}/crlnumber"
	local crl="${TYPE}/crl/crl.pem"

	# Creation of empty revocation list
	echo '01' > "${number}"
	openssl ca -config "${CONFIG}" -gencrl -out "${crl}" -crlexts crl_exts
}

function revoke_cert {
	if [[ "${#}" -ne 1 ]]; then
		printf "%s: need 1 argument.\n" "${FUNCNAME}"
		exit 1
	fi

	local num="${1}"
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"
	local crl="${TYPE}/crl/crl.pem"

	# Revocation of the signing key
	openssl ca -config "${CONFIG}" -revoke "${cert}" -crl_reason keyCompromise

	# Creation of a new CRL
	openssl ca -config "${CONFIG}" -gencrl -out "${crl}" -crlexts crl_exts
}

function create_subca {
	local privkey="${TYPE}/ca-privkey.pem"
	local cert="${TYPE}/cacert.pem"
	local csr="${TYPE}/csr/cacert.csr"
	local serial="${TYPE}/serial"
	local rootcert="./root/cacert.pem"
	local rootkey="./root/ca-privkey.pem"

	local num=""
	if [ "${TYPE}" == "dev" ]; then
		num="8"
	elif [ "${TYPE}" == "cont" ]; then
		num="9"
	else
		printf "create_subca: invalid SubCA TYPE: '%s'. Must be either 'dev' "
			   "or 'cont'!" "${TYPE}"
		exit 1
	fi

	generate_serial > "${serial}"

	# Key pair: secret key generation
	openssl ecparam -name brainpoolP256r1 -genkey -param_enc explicit \
		-out "${privkey}"

	# Certificate signing request
	openssl req -new -key "${privkey}" -config "${CONFIG}" -out "${csr}" \
		< "${INPUTS_SUBCA}"

	# Signature of the certificate by the CA
	printf 'y\ny\n' \
		| openssl ca -config "${CONFIG}" -md sha256 -policy policy_anything \
		-name CA_sub -extensions v3_x509_subca -cert "${rootcert}" \
		-keyfile "${rootkey}" -out "${cert}" -infiles "${csr}"

}

function create_bad_subca {
   local exts="${1}"
	local privkey="${TYPE}/ca-privkey.pem"
	local cert="${TYPE}/cacert.pem"
	local csr="${TYPE}/csr/cacert.csr"
	local serial="${TYPE}/serial"
	local rootcert="./root/cacert.pem"
	local rootkey="./root/ca-privkey.pem"

	local num=""
	if [ "${TYPE}" == "dev" ]; then
		num="8"
	elif [ "${TYPE}" == "cont" ]; then
		num="9"
	else
		printf "create_subca: invalid SubCA TYPE: '%s'. Must be either 'dev' "
			   "or 'cont'!" "${TYPE}"
		exit 1
	fi

	generate_serial > "${serial}"

	# Key pair: secret key generation
	openssl ecparam -name brainpoolP256r1 -genkey -param_enc explicit \
		-out "${privkey}"

	# Certificate signing request
	openssl req -new -key "${privkey}" -config "${CONFIG}" -out "${csr}" \
		< "${INPUTS_SUBCA}"

	# Signature of the certificate by the CA
	printf 'y\ny\n' \
		| openssl ca -config "${CONFIG}" -md sha256 -policy policy_anything \
		-name CA_sub -extensions "${exts}" -cert "${rootcert}" \
		-keyfile "${rootkey}" -out "${cert}" -infiles "${csr}"

}

function create_cert_subca {
	local num="${1}"
	local privkey="${TYPE}/private/${TYPE}_${num}.pem"
	local csr="${TYPE}/csr/${TYPE}_${num}.csr"
	local serial="${TYPE}/serial"
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"
	local args=""

	# Argument 2 is optionnal and used only for bad certificate tests
	if [ ! -z ${2+x} ]; then
		args="${2}"
	fi

	generate_serial > "${serial}"

	# Key pair: secret key generation
	openssl ecparam -name brainpoolP256r1 -genkey -param_enc explicit \
		-out "${privkey}"

	# Certificate signing request
	sed "s|Z|${num}|" "${INPUTS_CERT}" | \
	openssl req -new -key "${privkey}" -config "${CONFIG}" -out "${csr}"

	# Signature of the certificate by the CA
	printf 'y\ny\n' \
		| openssl ca -config "${CONFIG}" -md sha256 -policy policy_anything \
		-name CA_sub -extensions v3_x509_sign_ctrl ${args} -out "${cert}" \
		-infiles "${csr}"
}

function create_crl_subca {
	local number="${TYPE}/crlnumber"
	local crl="${TYPE}/crl/crl.pem"

	# Creation of empty revocation list
	echo '01' > "${number}"
	openssl ca -config "${CONFIG}" -gencrl -out "${crl}" -crlexts crl_exts \
		-name CA_sub
}

function revoke_cert_subca {
	if [[ "${#}" -ne 1 ]]; then
		printf "%s: need 1 argument.\n" "${FUNCNAME}"
		exit 1
	fi

	local num="${1}"
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"
	local crl="${TYPE}/crl/crl.pem"

	# Revocation of the signing key
	openssl ca -config "${CONFIG}" -revoke "${cert}" \
		-crl_reason keyCompromise -name CA_sub

	# Creation of a new CRL
	openssl ca -config "${CONFIG}" -gencrl -out "${crl}" -crlexts crl_exts \
		-name CA_sub
}

function create_bad_cert {
	if [[ "${#}" -ne 1 ]]; then
		printf "%s: need 1 argument.\n" "${FUNCNAME}"
		exit 1
	fi

	local num=${1}
	local cert="${TYPE}/certs/${TYPE}_${num}.pem"

	printf "Creating bad certificate for %s %s\n" "${TYPE_FULL}" "${num}"
	${BAD_CERT_SCRIPT} "${cert}"
}

function create_bad_crl {
	local crl="${TYPE}/crl/crl.pem"
	local bad_crl="${TYPE}/crl/crl_bad.pem"

	printf "Creating bad CRL for %s\n" "${TYPE}"
	openssl crl -in "${crl}" -badsig > "${bad_crl}"
}

function create_expired_crl {
	local name="${1}"
	local crl="${TYPE}/crl/crl.pem"
	local bad_crl="${TYPE}/crl/crl_exp.pem"

	printf "Creating expired CRL for %s\n" "${TYPE}"
	openssl ca -config "${CONFIG}" -gencrl -out "${bad_crl}" -crlexts crl_exts \
		-crldays 0 -crlhours 0 -crlsec 1 -name "CA_${name}"
}

function create_hashed_dir {
	local dir="hashed/${TYPE}"
	local dir_crl="hashed/${TYPE}_crl"

	mkdir -p "${dir}" "${dir_crl}"

	cp "${TYPE}/cacert.pem" "${dir}/${TYPE}.pem"
	cp "${TYPE}/crl/crl.pem" "${dir_crl}/crl.pem"

	local root_cert="root/cacert.pem"
	if [ -f "${root_cert}" ]; then
		cp "${root_cert}" "${dir}/root.pem"
	fi

	local root_crl="root/crl/crl.pem"
	if [ -f "${root_crl}" ]; then
		cp "${root_crl}" "${dir_crl}/crl_root.pem"
	fi

	local bad_crl="${TYPE}/crl/crl_bad.pem"
	if [ -f "${bad_crl}" ]; then
		local dir_bad_crl="hashed/${TYPE}_crl_bad"

		mkdir -p "${dir_bad_crl}"
		cp "${bad_crl}" "${dir_bad_crl}"

		if [ -f "${root_crl}" ]; then
			cp "${root_crl}" "${dir_bad_crl}/crl_root.pem"
		fi
	fi

	local expired_crl="${TYPE}/crl/crl_exp.pem"
	if [ -f "${expired_crl}" ]; then
		local dir_expired_crl="hashed/${TYPE}_crl_exp"

		mkdir -p "${dir_expired_crl}"
		cp "${expired_crl}" "${dir_expired_crl}"

		if [ -f "${root_crl}" ]; then
			cp "${root_crl}" "${dir_expired_crl}/crl_root.pem"
		fi
	fi

	# rehash all directories found under hashed
	shopt -s nullglob
	local dirs=(hashed/${TYPE}*)
	for d in "${dirs[@]}"; do
		pushd "${d}"
		c_rehash ./
		popd
	done
}
