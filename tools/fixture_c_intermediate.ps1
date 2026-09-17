param(
    [Parameter(Mandatory = $true)]
    [string]$SessionDir,

    [Parameter(Mandatory = $true)]
    [string]$PythonExe,

    [Parameter(Mandatory = $true)]
    [string]$ChildScript,

    [int]$ChildSeconds = 60,

    [int]$ReleaseTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

if ($ChildSeconds -le 0) {
    throw 'ChildSeconds must be greater than zero.'
}
if ($ReleaseTimeoutSeconds -le 0) {
    throw 'ReleaseTimeoutSeconds must be greater than zero.'
}

$sessionPath = [System.IO.Path]::GetFullPath($SessionDir)
[System.IO.Directory]::CreateDirectory($sessionPath) | Out-Null

$readyPath = Join-Path $sessionPath 'ready.json'
$releasePath = Join-Path $sessionPath 'release.signal'
$stopPath = Join-Path $sessionPath 'child-stop.signal'

function Quote-Argument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

$childArgs = @(
    (Quote-Argument ([System.IO.Path]::GetFullPath($ChildScript))),
    '--stop-file',
    (Quote-Argument $stopPath),
    '--seconds',
    [string]$ChildSeconds
)

$child = Start-Process `
    -FilePath ([System.IO.Path]::GetFullPath($PythonExe)) `
    -ArgumentList $childArgs `
    -PassThru `
    -WindowStyle Hidden

[PSCustomObject]@{
    schema_version  = 1
    powershell_pid  = $PID
    child_pid       = $child.Id
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
} |
    ConvertTo-Json -Compress |
    Set-Content -LiteralPath $readyPath -Encoding utf8

$deadline = [DateTime]::UtcNow.AddSeconds($ReleaseTimeoutSeconds)
while (-not (Test-Path -LiteralPath $releasePath)) {
    if ([DateTime]::UtcNow -ge $deadline) {
        New-Item -ItemType File -Force -Path $stopPath | Out-Null
        exit 2
    }
    Start-Sleep -Milliseconds 50
}

# Deliberately exit while the harmless child remains alive. The observer will
# collect the after-snapshot and then signal the child to stop.
exit 0
