<#
Measures redact-service startup: seconds from launch until /health reports
ready (what start-stack.ps1 waits for). Run it right after a reboot for a
true cold start (the ~425 MB spaCy model is read from disk, not the OS
cache).

    .\scripts\measure_cold_start.ps1
    .\scripts\measure_cold_start.ps1 -ModelOnly   # no store/token needed

The full measurement needs HANDOFF.md section 1 done (store, key, token
file). -ModelOnly times just the Python imports and the model load, which
is most of a cold start.

It starts the service on its own port (8799 by default, so it can't clash
with a running instance) and stops it again afterwards. Service logs go to
%TEMP%\redact-service-cold-start.log (they never contain text).
#>
param(
    [string]$Python = "H:\ai\engines\pii-redact\.venv\Scripts\python.exe",
    [string]$RedactionHome = "H:\ai\redaction",
    [int]$Port = 8799,
    [int]$TimeoutSeconds = 300,
    [switch]$ModelOnly
)

if ($ModelOnly) {
    & $Python -c "import time; t=time.perf_counter(); import pii_redact.service; from pii_redact.detect.analyzer import get_analyzer; get_analyzer().analyze('warm up', language='en'); print(f'imports + model load: {time.perf_counter()-t:.1f} s')"
    return
}

$log = Join-Path $env:TEMP "redact-service-cold-start.log"
$watch = [Diagnostics.Stopwatch]::StartNew()
$service = Start-Process -FilePath $Python -PassThru -WindowStyle Hidden -RedirectStandardError $log `
    -ArgumentList "-m", "pii_redact.service", "--port", $Port, "--home", "`"$RedactionHome`""
$ready = $false
while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds -and -not $service.HasExited) {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2
        if ($health.ready) { $ready = $true; break }
    } catch { }
    Start-Sleep -Milliseconds 250
}
$watch.Stop()
if ($ready) {
    "ready after {0:N1} s" -f $watch.Elapsed.TotalSeconds
} elseif ($service.HasExited) {
    "the service exited (code $($service.ExitCode)) - see $log"
} else {
    "not ready after $TimeoutSeconds s - see $log"
}
if (-not $service.HasExited) { Stop-Process -Id $service.Id }
