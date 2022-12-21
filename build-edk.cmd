set WORKSPACE=D:\edk2
set NASM_PREFIX="C:\Program Files\NASM\"
set PYTHON_HOME=C:\Python34
set PACKAGES_PATH=D:\edk2;%cd%;D:\edk2-libc;D:\edk2-archive

call D:\edk2\edksetup.bat

build -p MyDbgPkg\MyDbgPkg.dsc ^
      -m MyDbgPkg\RuntimeSpyDxe\RuntimeSpyDxe.inf ^
      -a X64 ^
      -n 8 ^
      -t VS2017
