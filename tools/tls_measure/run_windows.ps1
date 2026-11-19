param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_:]+$')][string]$Test,
    [Parameter(Mandatory)][string]$OutputPrefix,
    [UInt64]$AffinityMask = 0
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This runner requires Windows and PowerShell 7.' }
$exe = (Resolve-Path -LiteralPath $Executable).Path
$prefix = [IO.Path]::GetFullPath($OutputPrefix)
if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($prefix))) {
    throw 'The output directory must already exist.'
}
foreach ($suffix in '.log', '.stderr.log', '.metadata.json') {
    if (Test-Path -LiteralPath ($prefix + $suffix)) { throw "Output already exists: $prefix$suffix" }
}

function Find-Builds {
    @(Get-Process cargo,rustc,clippy-driver -ErrorAction SilentlyContinue |
        ForEach-Object { [pscustomobject]@{ Id = $_.Id; Name = $_.ProcessName } })
}
if (@(Find-Builds).Count -ne 0) { throw 'A Cargo/rustc/Clippy process is running. No measurement started.' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TlsMeasureSystemTimes {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetSystemTimes(out long idle, out long kernel, out long user);
    public static long[] Read() {
        long idle, kernel, user;
        if (!GetSystemTimes(out idle, out kernel, out user))
            throw new System.ComponentModel.Win32Exception();
        return new long[] { idle, kernel, user };
    }
}
'@

$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$arguments = @($Test, '--exact', '--ignored', '--nocapture', '--test-threads=1')
if ($AffinityMask -eq 0) {
    $startInfo.FileName = $exe
    foreach ($argument in $arguments) { $startInfo.ArgumentList.Add($argument) }
} else {
    # START applies affinity before the executable begins its first sample.
    if ($exe -match '["%!^&|<>]') { throw 'Executable path cannot be safely passed to CMD START.' }
    $startInfo.FileName = $env:ComSpec
    $command = 'start "" /b /wait /affinity {0:X} "{1}" {2}' -f $AffinityMask, $exe, ($arguments -join ' ')
    # CMD consumes its own quoted command string, not CRT-escaped argv quotes.
    $startInfo.Arguments = '/d /s /c "' + $command + '"'
}
$settings = @{}
Get-ChildItem Env: | Where-Object { $_.Name -match '^TLS_(RECORD|CLIENT|CONFIG|VERIFICATION)_(TIMING|MEASURE)' } |
    ForEach-Object { $settings[$_.Name] = $_.Value }
$hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$started = [DateTimeOffset]::Now
$previous = [TlsMeasureSystemTimes]::Read()
$observations = [Collections.Generic.List[object]]::new()
$process = [Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) { throw 'Failed to start measurement.' }
$stdout = $process.StandardOutput.ReadToEndAsync()
$stderr = $process.StandardError.ReadToEndAsync()
do {
    $finished = $process.WaitForExit(1000)
    $current = [TlsMeasureSystemTimes]::Read()
    $total = $current[1] - $previous[1] + $current[2] - $previous[2]
    $idle = $current[0] - $previous[0]
    $observations.Add([pscustomobject]@{
        Time = [DateTimeOffset]::Now
        TotalCpuIncludingMeasurement = $(if ($total -gt 0) { 100 * (1 - $idle / $total) } else { $null })
        Builds = @(Find-Builds)
    })
    $previous = $current
} until ($finished)
$ended = [DateTimeOffset]::Now
$code = $process.ExitCode
$output = $stdout.GetAwaiter().GetResult()
$singleTestPassed = $output -match 'test result: ok\. 1 passed; 0 failed;'
[IO.File]::WriteAllText($prefix + '.log', $output)
[IO.File]::WriteAllText($prefix + '.stderr.log', $stderr.GetAwaiter().GetResult())
$overlap = @($observations | Where-Object { $_.Builds.Count -gt 0 }).Count -gt 0
$metadata = [ordered]@{
    Executable = $exe; SHA256 = $hash; Test = $Test
    Started = $started; Ended = $ended; ExitCode = $code
    AffinityMask = $AffinityMask; Environment = $settings
    BuildOverlapDetected = $overlap
    ExpectedSingleTestPassed = $singleTestPassed
    Monitoring = 'One-second Cargo/rustc/Clippy snapshots; short builds and other background work may be missed. Review CPU/noise separately.'
    Observations = $observations
}
[IO.File]::WriteAllText($prefix + '.metadata.json', ($metadata | ConvertTo-Json -Depth 8))
$process.Dispose()
Write-Output "$Test completed; exit=$code; build_overlap=$overlap; output=$prefix"
if ($code -ne 0) { exit $code }
if (-not $singleTestPassed) { exit 4 }
if ($overlap) { exit 3 }
