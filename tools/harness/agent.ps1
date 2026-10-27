# specter-rs test agent (Windows side).
#
# ONE-TIME setup on the test VM, from the Defender-excluded Dev folder:
#   powershell -ExecutionPolicy Bypass -File .\agent.ps1
#
# Then it loops forever: every 5 s it fetches the job queue from the harness
# server, and when a new job arrives it downloads the payload, runs it,
# collects the diagnostics (specter.log, last WER crash event, exit code)
# and posts everything back as a JSON report. No other manual action.
#
# ASCII ONLY: PowerShell 5.1 reads a BOM-less file as ANSI, and any
# non-ASCII byte corrupts the parser.

param(
    [string]$Server = "http://100.126.19.5:8888",
    [int]$PollSeconds = 5
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
    } catch { Write-Host ("report failed: " + $_.Exception.Message) }
}

Write-Host ("[agent] polling " + $Server + " every " + $PollSeconds + "s")

while ($true) {
    $raw = ""
    try { $raw = curl.exe -s ($Server + "/job") } catch { }
    if ($raw -eq "") { Start-Sleep $PollSeconds; continue }

    $job = $null
    try { $job = $raw | ConvertFrom-Json } catch { }
    if ($null -eq $job) { Start-Sleep $PollSeconds; continue }

    if ($job.action -ne "run" -or $job.id -eq "" -or $job.id -eq $lastJob) {
        Start-Sleep $PollSeconds
        continue
    }
    $lastJob = $job.id
    Write-Host ("[agent] job " + $job.id + ": " + $job.name)

    # Fresh download of the payload.
    try { curl.exe -s -o $job.name $job.blob_url } catch { }
    if (-not (Test-Path $job.name)) {
        Post-Report @{ id = $job.id; name = $job.name; error = "download failed" }
        continue
    }

    # Fresh debug log for this run.
    Remove-Item (Join-Path $here "specter.log") -ErrorAction SilentlyContinue

    # Run it and wait: Start-Process + WaitForExit observes GUI-subsystem
    # exes properly (a direct console launch would return immediately).
    $alive = $false
    $code = $null
    try {
        $p = Start-Process -FilePath (Join-Path $here $job.name) -PassThru -WorkingDirectory $here
        if (-not ($p.WaitForExit([int]$job.timeout_ms))) {
            $alive = $true
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        } else {
            $code = $p.ExitCode
        }
    } catch {
        Post-Report @{ id = $job.id; name = $job.name; error = ("run failed: " + $_.Exception.Message) }
        continue
    }
    Start-Sleep 2

    $log = ""
    $logPath = Join-Path $here "specter.log"
    if (Test-Path $logPath) { $log = Get-Content $logPath -Raw }

    $wer = ""
    $werTime = ""
    try {
        $ev = Get-WinEvent -LogName Application -MaxEvents 30 -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -eq 1000 -and $_.Message -like ("*" + $job.name + "*") } |
            Select-Object -First 1
        if ($ev) { $wer = $ev.Message; $werTime = $ev.TimeCreated.ToString() }
    } catch { }

    Write-Host ("[agent] done: alive=" + $alive + " exit=" + $code + " log=" + $log.Length + "B wer=" + [bool]$wer)
    Post-Report @{
        id = $job.id
        name = $job.name
        alive = $alive
        exit_code = $code
        specter_log = $log
        wer = $wer
        wer_time = $werTime
    }
}
