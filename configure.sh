#!/bin/bash

mkdir build
pushd build

cmake ../
make oauth_sign

popd
