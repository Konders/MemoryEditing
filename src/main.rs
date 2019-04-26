use std::ffi::OsString;
use std::mem;
use std::os::windows::ffi::OsStringExt;

use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualProtectEx, VirtualQueryEx, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

fn find_process(name: &str) -> Option<DWORD> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() { return None; }
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;
        if Process32FirstW(snap, &mut entry) == FALSE {
            CloseHandle(snap);
            return None;
        }
        loop {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
            let exe = OsString::from_wide(&entry.szExeFile[..len]);
            if exe.to_string_lossy().eq_ignore_ascii_case(name) {
                let pid = entry.th32ProcessID;
                CloseHandle(snap);
                return Some(pid);
            }
            if Process32NextW(snap, &mut entry) == FALSE { break; }
        }
        CloseHandle(snap);
        None
    }
}

fn is_readable(protect: DWORD) -> bool {
    if protect & 0x100 != 0 { return false; }
    let base = protect & 0xFF;
    base == 0x02 || base == 0x04 || base == 0x08
        || base == 0x20 || base == 0x40 || base == 0x80
}

// Pattern: FF D7 83 F8 0D 75 24 8B 0D ?? ?? ?? ?? 83 EE 0A
//
// Disassembly of game.exe main loop:
//   call edi             ; _getch()
//   cmp eax, 0Dh         ; Enter key?
//   jne check
//   mov ecx, [cout]      ; ?? ?? ?? ?? (address varies)
//   sub esi, 0Ah         ; HP -= 10  <-- we NOP this
//
// We replace 83 EE 0A (sub esi, 10) with 90 90 90 (NOP NOP NOP)

const PATTERN_STR: &str = "FF D7 83 F8 0D 75 24 8B 0D ?? ?? ?? ?? 83 EE 0A";
const PATCH_STR: &str = "83 EE 0A"; // the bytes we want to NOP out

fn parse_pattern(pat: &str) -> Vec<Option<u8>> {
    pat.split_whitespace()
        .map(|t| if t == "??" { None } else { Some(u8::from_str_radix(t, 16).unwrap()) })
        .collect()
}

fn find_subpattern(full: &str, sub: &str) -> usize {
    let full_tokens: Vec<&str> = full.split_whitespace().collect();
    let sub_tokens: Vec<&str> = sub.split_whitespace().collect();
    full_tokens.windows(sub_tokens.len())
        .position(|w| w == sub_tokens.as_slice())
        .expect("PATCH_STR not found in PATTERN_STR")
}


fn main() {
    // --- Find & open game.exe ---
    let pid = match find_process("game.exe") {
        Some(p) => p,
        None => { eprintln!("game.exe not found!"); return; }
    };
    println!("[+] game.exe PID: {}", pid);

    let handle: HANDLE = unsafe {
        OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid,
        )
    };
    if handle.is_null() {
        eprintln!("[-] Failed to open process (run as admin)");
        return;
    }

    // --- Scan memory for the code pattern ---
    let pattern = parse_pattern(PATTERN_STR);
    let patch_offset = find_subpattern(PATTERN_STR, PATCH_STR);
    let patch_len = PATCH_STR.split_whitespace().count();
    println!("[*] Scanning for pattern: {}", PATTERN_STR);

    let mut patch_addr: Option<usize> = None;
    let mut address: usize = 0;

    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let ret = unsafe {
            VirtualQueryEx(handle, address as *const _, &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>())
        };
        if ret == 0 { break; }

        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let size = mbi.RegionSize;
            let mut buf = vec![0u8; size];
            let mut read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(handle, mbi.BaseAddress, buf.as_mut_ptr() as *mut _,
                    size, &mut read)
            };
            if ok != 0 && read >= pattern.len() {
                buf.truncate(read);
                for i in 0..=buf.len() - pattern.len() {
                    let matched = pattern.iter().enumerate().all(|(j, p)| match p {
                        None => true,
                        Some(b) => buf[i + j] == *b,
                    });
                    if matched {
                        patch_addr = Some(address + i + patch_offset);
                        println!("[+] Pattern found at 0x{:08X}", address + i);
                        println!("[+] Patch target at 0x{:08X}", address + i + patch_offset);
                        break;
                    }
                }
            }
            if patch_addr.is_some() { break; }
        }

        let next = mbi.BaseAddress as usize + mbi.RegionSize;
        if next <= address { break; }
        address = next;
    }

    let patch_addr = match patch_addr {
        Some(a) => a,
        None => {
            eprintln!("[-] Pattern not found!");
            unsafe { CloseHandle(handle); }
            return;
        }
    };

    // --- Patch: make .text writable, NOP out the sub ---
    let nops = vec![0x90u8; patch_len];

    let mut old_protect: DWORD = 0;
    let ok = unsafe {
        VirtualProtectEx(
            handle, patch_addr as *mut _, nops.len(),
            PAGE_EXECUTE_READWRITE, &mut old_protect,
        )
    };
    if ok == 0 {
        eprintln!("[-] VirtualProtectEx failed");
        unsafe { CloseHandle(handle); }
        return;
    }

    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            handle, patch_addr as *mut _,
            nops.as_ptr() as *const _, nops.len(), &mut written,
        )
    };

    // Restore original protection
    unsafe { VirtualProtectEx(handle, patch_addr as *mut _, nops.len(), old_protect, &mut old_protect); }

    if ok != 0 && written == nops.len() {
        println!("[+] Patched! {} -> {} (NOP)", PATCH_STR,
            std::iter::repeat("90").take(patch_len).collect::<Vec<_>>().join(" "));
        println!("[+] HP will no longer decrease. Press Enter in game to verify.");
    } else {
        eprintln!("[-] WriteProcessMemory failed");
    }

    unsafe { CloseHandle(handle); }
}
