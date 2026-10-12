# ROCKEY ARM Linux ARM64 runtime

Imported on 2026-10-12 from the vendor SDK supplied by the project owner.

- Outer archive: `ROCKEY-ARM_SDK_LINUX.rar`
- ARM64 archive: `ARM64_Rockey-ARM_SDK_LINUX_V2.00_20260415.tar.gz`
- Original member: `Rockey-ARM_SDK_LINUX/base/api/api64/libRockeyARM.so.1.0`
- Installed member: `libRockeyARM.so.1.0` (original name and unmodified bytes)
- Architecture: ELF64, little-endian, AArch64 (`e_machine=183`)
- Dependencies: `libc.so.6`, `ld-linux-aarch64.so.1`; required symbol version `GLIBC_2.17`

SHA-256:

```text
Outer archive: b1c9522fc40ec26ba1d58874e782465afca561fa22253504d9d601a6df912dce
ARM64 archive: 5b9ae812eaaf89a40b32f91f205f4e2e96ace55b4957fa351713fcb1f5eb071a
Runtime:       3845bf34dbabd26caf34c067015da9d433de3dcdb3165d2ab854f2f4b57bcd4e
```

The six APIs used by DongleService are exported: `Dongle_Enum`, `Dongle_Open`,
`Dongle_ResetState`, `Dongle_Close`, `Dongle_ReadData`, `Dongle_WriteData`.
The supplied `base/include/Dongle_API.h` uses the same 40-byte DONGLE_INFO layout
and function signatures as this project's adapter (32-bit DWORD, pointer HANDLE).

No vendor installer, Java runtime, static library, sample program or sample key is
required by the Qt client. Deployment uses the existing project USB permission
rules in `scripts/70-rockey-arm.rules`.

This SDK is a vendor binary, not project-authored source. The vendor's terms apply.
The archive also contains X64, ARM32, LOONGARCH64 and SW64 packages; they were not
installed by this ARM64 integration. Existing x86/x64 runtimes remain unchanged.

Validation on the x86_64 development host covers the binary format, symbols,
interface declaration and build/package paths. It does not establish successful
ARM64 execution. Verify library loading and the physical USB dongle on the target
cloud laptop before release; see `docs/dongle-verification.md` at the project root.
