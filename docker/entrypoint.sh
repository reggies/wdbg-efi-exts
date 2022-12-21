#!/usr/bin/env bash

export WORKSPACE=~/edk2
export EDK_TOOLS_PATH=~/edk2/BaseTools
export PACKAGES_PATH=~/edk2-libc:~/edk2:~/

source ~/edk2/edksetup.sh

build \
    -t GCC5 \
    -b DEBUG \
    -p MyDbgPkg/MyDbgPkg.dsc \
    -m MyDbgPkg/RuntimeSpyDxe/RuntimeSpyDxe.inf \
    -a X64 \
    -n 8
