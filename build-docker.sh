#!/usr/bin/env bash
# NB: paths in docker container are embedded into debug ELF
# make sure that they will match the original source code paths
IMG=edk2-wdbg-i
CID=edk2-wdbg-c
docker build -t $IMG ./docker
docker stop $CID
docker rm $CID
docker run --name $CID -v $(pwd)/MyDbgPkg:/root/MyDbgPkg/. -t $IMG
docker cp $CID:/root/edk2/Build/MyDbgPkg/DEBUG_GCC5/X64/RuntimeSpyDxe.efi RuntimeSpyDxe.efi
docker stop $CID
