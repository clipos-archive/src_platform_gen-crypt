# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.
.PHONY: all test clean

all:
	cat README

doc: Doxyfile src/gen-crypt.dox
	doxygen Doxyfile

test: test.sh
	./test.sh

clean:
	rm -f configure .clang-format
	rm -rf autom4te.cache build_civil doc \
		test/cli_fuzzer.pyc test/CA/test_ca/ test/CA/bad_pki/ \
		test/CA/bad_pki_logs/
	cd test/workdir/ && \
		rm -f ./*.deb tmp_daemon_socket packages/random.deb
	cd test/workdir/ && \
		rm -rf logs \
		mirror_civil-1CA_2SubCA mirror_civil-2CA_NoSubCA \
		mirror_civil_devonly-1CA_2SubCA mirror_civil_devonly-2CA_NoSubCA
