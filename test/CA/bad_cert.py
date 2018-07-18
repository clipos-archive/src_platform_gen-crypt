#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.
#
# bad_cert.py:
# Takes as first argument the path to a '.pem' file containing a valid
# certificate.
# Creates two invalid certificates:
#   * file.pem.bad : by replacing a character
#   * file.pem.cut : by cutting out the end of the certificate

import sys
import os.path

if len(sys.argv) != 2:
    print "Need at least one argument."
    sys.exit(1)

path = sys.argv[1]

if not path.endswith('.pem'):
    print "File '{}' does not have a '.pem' extension.".format(path)
    sys.exit(1)

f = open(path, 'r')
content = f.read()
f.close()

# We're going to change the 35th char before the end. Make sure the file
# actually at least that many chars.
# We're using the 35th char before the end to make sure we're not altering the
# '-----END CERTIFICATE-----' part of the .pem file.
if len(content) < 37:
    print "File '{}' is too small. Is this a real certificate?".format(path)
    sys.exit(1)

# Figures out which char we're going to use to replace the one already here.
# The new char must be different from the current one and should be plausible.
if content[-35] == 'r':
    char = 'y'
else:
    char = 'r'

# Generate new filenames: remove '.pem' extension, append suffix and extension
last_slash = path.rfind("/")
if last_slash < 0:
    filename_bad = "ill_signed_" + path
    filename_cut = "_cut_" + path
else:
    filename_bad = path[:last_slash] + "/ill_signed_" + path[(last_slash + 1) : ]
    filename_cut = path[:last_slash] + "/_cut_" + path[(last_slash + 1) : ]

# Do not overwrite already existing files
for f in [filename_bad, filename_cut]:
    if os.path.isfile(f):
        print "File '{}' already exists.".format(f)
        sys.exit(1)

new_file = open(filename_bad, 'w')
new_file.write(content[0:-35] + char + content[-34:])
new_file.close()

new_file = open(filename_cut, 'w')
new_file.write(content[0:-35])
new_file.close()

sys.exit(0)
