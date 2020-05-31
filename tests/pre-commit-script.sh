#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Avoid removing the "build" directory if the script does not run from the 
# package root directory 
basedir=`pwd`
if [[ ! -f "$basedir/tests/pre-commit-script.sh" ]]; then
  >&2 echo "Script does not run from the root directory"
  exit 0
fi

if [ $# -ne 0 ]; then
  # For speed testing when the first parameter is set we set the number
  # of monte carlo tests to 10. This should not be set before commiting a code.
  monte="-DMONTE_CARLO_NUM_OF_TESTS=10"
else
  # Use the default (100,000)
  monte=""
fi

# Clean previous build content
rm -rf build;

mkdir build;
cd build;

# Test clang-format
cmake ..; make format; 
rm -rf *

for method in "" "-DALTERNATIVE_AVX512_IMPL=1"; do
  # Test clang-tidy
  CC=clang-9 cmake $method -DCMAKE_C_CLANG_TIDY="clang-tidy-9;--fix-errors;--format-style=file" ..
  make -j20
  rm -rf *

  for flag in "" "-DTEST_SPEED=1" "-DASAN=1" "-DMSAN=1" "-DTSAN=1" "-DUBSAN=1" ; do
    CC=clang-9 cmake $method $flag $monte ..; 
    make -j20 
    ./sha-with-intrinsic
    rm -rf *
  done
done
