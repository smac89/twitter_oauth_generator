#!/bin/bash

mkdir build
pushd build

cmake ../
make oauth_sign

#find . -type f -not -path '*/\.*' | grep '.*\.[h|c]' | xargs clang-format -i -style=file

popd
