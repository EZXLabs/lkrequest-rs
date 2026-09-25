param(
    [int]$Rounds = 3,
    [string]$ResultsDirectory = "benchmark-results/h2-client",
    [int]$ClientRuntimeWorkers = 1,
    [int]$ServerRuntimeWorkers = 2
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "../../..")
$ResultsPath = Join-Path $RepositoryRoot $ResultsDirectory
$Executable = Join-Path $RepositoryRoot "target/release/http-client-bench.exe"
$ClientsForward = @("lkrequest", "hyper", "reqwest")
$ClientsReverse = @("reqwest", "hyper", "lkrequest")
$Scenarios = @(
    @{ Name = "sequential-reuse"; Body = 1024; Requests = 20000; Concurrency = 1 },
    @{ Name = "multiplex-c8"; Body = 1024; Requests = 30000; Concurrency = 8 },
    @{ Name = "multiplex-c32"; Body = 1024; Requests = 50000; Concurrency = 32 },
    @{ Name = "multiplex-c128"; Body = 1024; Requests = 50000; Concurrency = 128 },
    @{ Name = "download-1m-c32"; Body = 1048576; Requests = 1000; Concurrency = 32 }
)

New-Item -ItemType Directory -Force -Path $ResultsPath | Out-Null
Push-Location $RepositoryRoot
try {
    cargo build --release -p http-client-bench
    @(
        "timestamp=$(Get-Date -Format o)",
        "os=$([Environment]::OSVersion.VersionString)",
        "architecture=$([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)",
        "processor=$env:PROCESSOR_IDENTIFIER",
        "logical_processors=$([Environment]::ProcessorCount)",
        "client_runtime_workers=$ClientRuntimeWorkers",
        "server_runtime_workers=$ServerRuntimeWorkers",
        "rustc=$(& rustc --version)",
        "cargo=$(& cargo --version)"
    ) | Set-Content -Encoding utf8 (Join-Path $ResultsPath "environment.txt")

    foreach ($BodyGroup in ($Scenarios | Group-Object Body)) {
        $BodySize = [int]$BodyGroup.Name
        $Stdout = Join-Path $ResultsPath "server-$BodySize.out.log"
        $Stderr = Join-Path $ResultsPath "server-$BodySize.err.log"
        $Server = Start-Process -FilePath $Executable -ArgumentList @(
            "serve", "--listen", "127.0.0.1:18481", "--body-size", $BodySize,
            "--runtime-workers", $ServerRuntimeWorkers
        ) -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
          -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr

        try {
            $Ready = $false
            for ($Attempt = 0; $Attempt -lt 100; $Attempt++) {
                if ($Server.HasExited) {
                    throw "benchmark server exited during startup"
                }
                if ((Test-Path $Stdout) -and
                    (Select-String -Quiet -Path $Stdout -Pattern "benchmark server listening")) {
                    $Ready = $true
                    break
                }
                Start-Sleep -Milliseconds 100
            }
            if (-not $Ready) {
                throw "benchmark server did not become ready"
            }

            foreach ($Round in 1..$Rounds) {
                $Clients = if (($Round % 2) -eq 1) { $ClientsForward } else { $ClientsReverse }
                foreach ($Scenario in $BodyGroup.Group) {
                    foreach ($Client in $Clients) {
                        $Output = Join-Path $ResultsPath (
                            "{0}-round{1}-{2}.json" -f $Scenario.Name, $Round, $Client
                        )
                        & $Executable run --client $Client `
                            --url "http://127.0.0.1:18481/" `
                            --requests $Scenario.Requests `
                            --concurrency $Scenario.Concurrency `
                            --warmup-requests 200 `
                            --expected-bytes $Scenario.Body `
                            --runtime-workers $ClientRuntimeWorkers `
                            --output $Output
                        if ($LASTEXITCODE -ne 0) {
                            throw "$Client failed in $($Scenario.Name), round $Round"
                        }
                    }
                }
            }
        } finally {
            Stop-Process -Id $Server.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $Server.Id -ErrorAction SilentlyContinue
        }
    }
    python (Join-Path $PSScriptRoot "summarize.py") $ResultsPath
} finally {
    Pop-Location
}
