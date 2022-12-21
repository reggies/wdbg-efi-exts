from ubuntu:focal

run apt-get update && \
    apt-get install -y \
        build-essential \
        git \
        gcc \
        uuid-dev \
        python \
        nasm && \
    apt-get clean

run mkdir /root/.ssh -m 0700
run ssh-keyscan -t rsa github.com >> /root/.ssh/known_hosts
run git clone https://github.com/tianocore/edk2 -b edk2-stable201808
run git clone https://github.com/tianocore/edk2-libc
workdir /root/edk2
run git submodule update --init
run make -C BaseTools/Source/C

copy entrypoint.sh /root/entrypoint.sh
entrypoint [ "bash", "/root/entrypoint.sh" ]
