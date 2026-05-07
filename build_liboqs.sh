#! /bin/bash
rm -rf build
mkdir build
cd build
cmake -GNinja -DOQS_ENABLE_KEM_HQC=ON ..
ninja
