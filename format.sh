#!/usr/bin/env bash

if [ -x /usr/bin/clang-format-3.7 ]; then
	ln -sf .clang-format-3.7 .clang-format
	clang-format-3.7 -style=file -i src/*.c src/*.h
else
	echo "No supported version of clang-format found."
	echo "Currently supported version are: 3.7."
	echo "Please install one of those."
	exit 1
fi
