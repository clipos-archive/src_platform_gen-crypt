#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

from cli_fuzzer import build_cmd_opt_list, exec_list
import sys
import os

# The following calls to get various environment variables will set some
# defaults used to test the script.

crypto = os.environ.get('CRYPTO', 'civil')

if crypto != "civil":
    print "Wrong crypto. Something strange is going on here!"
    sys.exit(1)

civil_kind = os.environ.get('KIND', "1CA_2SubCA")
civil_ca_dir = os.environ.get('CA_DIR', "../CA/test_ca/" + civil_kind + "/")

# Only used if no environment variables are set
default_bin_dir = "../../build_" + crypto + "/"

sign_package = os.environ.get('TMP_SIGN_PACKAGE', "foo_0.1-1_all.deb")
if crypto == "civil":
    good_package = os.environ.get('GOOD_PACKAGE', "mirror_civil-" + civil_kind + "/cont_1-cont_1__dev_1-dev_1__foo_0.1-1_all.deb")

# TODO: fix those
valid_arguments = {
    'civil': {
        'dev': {
            'key': civil_ca_dir + "dev/private/dev_1.pem",
            'cert': civil_ca_dir + "dev/certs/dev_1.pem",
            'pass': civil_ca_dir + "../../config/privkey_passphrase.txt",
            'root_ca': civil_ca_dir + "hashed/dev",
            'crl': civil_ca_dir + "hashed/dev_crl",
            'trusted_ca': civil_ca_dir + "hashed/dev/dev.pem",
            'regexp': "TEST-DEVELOPER*"
        },
        'cont': {
            'key': civil_ca_dir + "cont/private/cont_1.pem",
            'cert': civil_ca_dir + "cont/certs/cont_1.pem",
            'pass': civil_ca_dir + "../../config/privkey_passphrase.txt",
            'root_ca': civil_ca_dir + "hashed/cont",
            'crl': civil_ca_dir + "hashed/cont_crl",
            'trusted_ca': civil_ca_dir + "hashed/cont/cont.pem",
            'regexp': "TEST-CONTROLER"
        }
    }
}

binaries = {
    'sign': os.environ.get('SIGN', default_bin_dir + "sign"),
    'check': os.environ.get('CHECK', default_bin_dir + "check"),
    'check-client': os.environ.get('CHECK_CLIENT', default_bin_dir + "check-client"),
    'check-daemon': os.environ.get('CHECK_DAEMON', default_bin_dir + "check-daemon")
}

log_dir = os.environ.get('LOG_DIR', "logs/test")
if crypto == "civil":
    log_filename = log_dir + "/" + crypto + '-' + civil_kind  + "-04_cli_args_checks.py.log"
log_file = open(log_filename, 'a')

# Options are triples of:
#   - syntax of the option,
#   - "required" or "optional"
#   - list of values, which are pairs of "good" or "bad" and the actual value
#     to be concatenated to the option in the command line
# ("-h", "optional", [("good", "")])
options = {
    'sign': {
        'civil': [
            ( "", "required", [
                    ("good", sign_package),
                    ("bad", "."),
                    ("bad", "ro_package.deb")
            ]),
            ( "-k", "required", [
                    ("good", valid_arguments['civil']['dev']['key']),
                    ("bad", "keys/plop"),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad", valid_arguments['civil']['dev']['cert'])
            ]),
            ( "-a", "optional", [
                    ("bad", "")
            ]),
            ( "-c", "required", [
                    ("bad", ""),
                    ("good", valid_arguments['civil']['dev']['cert']),
                    ("bad", ".")
            ]),
            ( "", "required", [
                    ("good", "-C"),
                    ("good", "-D"),
                    ("bad", "")
            ]),
            ( "-p", "optional", [
                    ("bad", ""),
                    ("good", valid_arguments['civil']['dev']['pass']),
                    ("bad", "./plop")
            ]),
            ( "-r", "optional", [
                    ("bad", ""),
                    ("good", valid_arguments['civil']['dev']['regexp']),
                    ("bad", "lok*$"),
                    ("bad", "Marnan")
            ])
        ]
    },
    'check': {
        'civil': [
            ( "", "required", [
                    ("good", good_package),
                    ("bad", "."),
                    ("bad", "ro_package.deb")
            ]),
            ( "-k", "required", [
                    ("good", valid_arguments['civil']['dev']['root_ca']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['cert'])
            ]),
            ( "-K", "required", [
                    ("good", valid_arguments['civil']['cont']['root_ca']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['cert'])
            ]),
            ( "-l", "required", [
                    ("good", valid_arguments['civil']['dev']['crl']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['cert'])
            ]),
            ( "-L", "required", [
                    ("good", valid_arguments['civil']['cont']['crl']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['cert'])
            ]),
            ( "-t", "required", [
                    ("good", valid_arguments['civil']['dev']['trusted_ca']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['pass'])
            ]),
            ( "-T", "required", [
                    ("good", valid_arguments['civil']['cont']['trusted_ca']),
                    ("bad", "../../"),
                    ("bad", ""),
                    ("bad",valid_arguments['civil']['dev']['pass'])
            ]),
        ]
    },
}

# Specific test cases using valid arguments (and package) with an invalid PKI.
# Return codes should always be 1 (EXIT_FAILURE) and never 10 (BAD_ARGS). Those
# options are only available for check, using civil crypto.
invalid_pki_options = []
species = ['1CA_2SubCA', '2CA_NoSubCA']
kind = ['bad_v3_x509_ca_cafalse', 'bad_v3_x509_ca_manyusage',
        'bad_v3_x509_ca_manyusage_2', 'bad_v3_x509_ca_missingBC',
        'bad_v3_x509_ca_missingusage', 'bad_v3_x509_ca_nousage',
        'bad_v3_x509_subca_cafalse', 'bad_v3_x509_subca_manyusage',
        'bad_v3_x509_subca_manyusage_2', 'bad_v3_x509_subca_missingBC',
        'bad_v3_x509_subca_missingusage', 'bad_v3_x509_subca_nousage']

invalid_pki_dir = "../CA/bad_pki"

for s in species:
    for k in kind:
        base_dir = "{}/{}/{}/hashed/".format(invalid_pki_dir, s, k)
        invalid_pki_options.append(" -k {} -l {} -t {} -K {} -L {} -T {} -V {}".format(
            base_dir + 'dev',
            base_dir + 'dev_crl',
            base_dir + 'dev/dev.pem',
            base_dir + 'cont',
            base_dir + 'cont_crl',
            base_dir + 'cont/cont.pem',
            good_package))

# NOTE: We only check 'sign' and 'check' here. This should cover most of the
# code. The 'check-client' tests could be added here but they are not really
# useful as there is no critical operation being performed. However, adding the
# tests for 'check-daemon' is hard as we need timeouts if the checks fails and
# the daemon lives.
for b in ['sign', 'check']:
    binary = binaries[b]
    (ok, nok) = build_cmd_opt_list(binary, options[b][crypto])

    print "Checking {} with {} crypto...".format(b, crypto)

    print "Expecting {} successful calls...".format(len(ok))
    if not exec_list(binary, ok, 0, log_file):
        print "Expecting {} successful calls: FAIL".format(len(ok))
        print "See logs in {}".format(log_filename)
        sys.exit(1)
    print "Expecting {} successful calls: OK".format(len(ok))

    print "Expecting {} unsuccessful calls...".format(len(nok))
    if not exec_list(binary, nok, 10, log_file):
        print "Expecting {} unsuccessful calls: FAIL".format(len(nok))
        print "See logs in {}".format(log_filename)
        sys.exit(1)
    print "Expecting {} unsuccessful calls: OK".format(len(nok))

    # Invalid PKI checks are only relevant for check and civil crypto
    if b == 'check' and crypto == 'civil':
        # We do not need to check pki_ok calls, the previous tests do that. We
        # only check failure cases.
        print "Expecting {} unsuccessful calls (invalid CA)...".format(len(invalid_pki_options))
        if not exec_list(binary, invalid_pki_options, 1, log_file):
            print "Expecting {} unsuccessful calls (invalid CA): FAIL".format(len(invalid_pki_options))
            print "See logs in {}".format(log_filename)
            sys.exit(1)
        print "Expecting {} unsuccessful calls (invalid CA): OK".format(len(invalid_pki_options))

    print "Checking {} with {} crypto: OK".format(b, crypto)

log_file.close()
