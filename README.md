# Build dependencies

* MSVC 2017
* WDK (I'm using 10.0.17763.1)
* EDK2, NASM, Python 2 or 3

# Build targets

## RuntimeSpyDxe.efi

An EFI runtime DXE executable. Maintain EFI variables cache
and EFI runtime modules list. These are stored in physical
memory so that they can later be accessed during memory
analysis.

To build, run build-docker.sh, build.sh or build.bat.

TBD: build process with build.sh or build.bat

## efihlp.sys

A helper WDM driver that must run on the debug target.

To build, run the following command from the Developer Command prompt.

```
msbuild win32/efihlp/sys/efihlp.sln
```

## efiexts.dll

A WinDbg extension library. To build, run the following command from Developer Command prompt.

```
msbuild win32/efihlp/dbgext/efiexts.sln
```

# Usage

- Reboot and launch EFI Shell
- Load RuntimeSpyDxe.efi
- Load bootmgfw.efi
- Install and run efihlp.sys
(there must appear EFIMemoryMap, EFIVariables, EFIVariables2 and EFIRuntimeDrivers keys under HKLM\Software)
- Use windbg to run extension commands

# WinDbg commands

At the moment only these commands are supported

`!efivars`        -- dump EFI variable cache

`!lsefi`          -- dump EFI runtime drivers list

`!findefivars`    -- scan physical memory for EFI variable cache structure (useful for crash dump analysis)

`!findruntime`    -- scan physical memory for EFI runtime driver list (useful for crash dump analysis)

## !efivars

`!efivars` or `!efivars efihlp!EfiVars` -- enumerate all variables that is accessible via gRT->GetNextVariableName() or set via calls to SetVariable()

`!efivars efihlp!EfiVars2` -- enumerate variables that is only accessible via gRT->GetNextVariableName()

`!efivars VirtualAddress` -- parse EFI variables cache at VirtualAddress

TBD: sample output

## !lsefi

`!lsefi`

TBD: sample output

`lm`

TBD: sample output

## !findefivars

`!findefivars PhysicalAddress`  -- scan memory starting at offset PhysicalAddress

TBD: sample output

## !findruntime

`!fundruntime PhysicalAddress`  -- scan memory starting at offset PhysicalAddress

TBD: sample output
