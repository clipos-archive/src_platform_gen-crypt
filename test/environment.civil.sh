#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

if [ -z "${KIND+x}" ]; then
	printf "Civil crypto chosen but no CA kind selected.\n"
fi

pushd "${WORKDIR}"

CA_DIR="../CA/test_ca/${KIND}"
PRIV_KEYS=(${CA_DIR}/dev/private/dev_*.pem
           ${CA_DIR}/cont/private/cont_*.pem)
# Regexp matching all bad certificates excepted the ones that are cut and thus
# can not be used to sign package. Bad certificates are prefixed by a '_'
# (_cut_dev_*.pem...).
CERTS=(${CA_DIR}/dev/certs/dev_*.pem
       ${CA_DIR}/dev/certs/[a-z]+_dev_1.pem
       ${CA_DIR}/cont/certs/cont_*.pem
       ${CA_DIR}/cont/certs/[a-z]+_cont_1.pem)

DEV_ROOT_CA="${CA_DIR}/hashed/dev"
DEV_CRL="${CA_DIR}/hashed/dev_crl"
DEV_TRUSTED_CA="${CA_DIR}/hashed/dev/dev.pem"

CONT_ROOT_CA="${CA_DIR}/hashed/cont"
CONT_CRL="${CA_DIR}/hashed/cont_crl"
CONT_TRUSTED_CA="${CA_DIR}/hashed/cont/cont.pem"

DEV_REGEX=".*DEV.*"
CONT_REGEX=".*CONT.*"

popd

# All packages, when signed, are prepended with names of the key used to sign
# and the certificate appended to the archive (without extensions) This is in
# turn used to discriminate good from bad packages in function should_fail.
# Regexp to discriminate good packages
GOOD_PKG_REGEXP=("")
for i in $(seq 1 5); do
   for j in $(seq 1 5); do
   GOOD_PKG_REGEXP=("${GOOD_PKG_REGEXP[@]}" "cont_${i}-cont_${i}__dev_${j}-dev_${j}*")
   done
done
