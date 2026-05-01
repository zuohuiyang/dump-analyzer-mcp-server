Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$runId = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$symbolsTempDir = Join-Path $env:TEMP "dump-analyzer-e2e-symbols-$runId"
$uploadTempDir = Join-Path $env:TEMP "dump-analyzer-e2e-uploads-$runId"
$defaultDumpPath = Join-Path $repoRoot "tests\dumps\DemoCrash1.exe.7088.dmp"
$timeoutSeconds = "1800"
$hostBind = "0.0.0.0"
$port = 8000

$serverProcess = $null
$venvPython = $null
$scriptExitCode = 0
$serverStdoutLog = Join-Path $env:TEMP "dump-analyzer-e2e-server.out.log"
$serverStderrLog = Join-Path $env:TEMP "dump-analyzer-e2e-server.err.log"
$pytestLog = Join-Path $env:TEMP "dump-analyzer-e2e-pytest.log"
$pytestErrLog = Join-Path $env:TEMP "dump-analyzer-e2e-pytest.err.log"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

function Write-Step([string]$message) {
    Write-Host "[E2E] $message"
}

function Print-LogTail([string]$title, [string]$path, [int]$lineCount = 120) {
    if (-not (Test-Path $path)) {
        Write-Host "[E2E] ${title}: <missing> $path"
        return
    }
    Write-Host "[E2E] $title (tail $lineCount): $path"
    Get-Content -Path $path -Tail $lineCount -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
}

function Print-FirewallHints([string]$pythonPath, [int]$portNumber) {
    Write-Host "[E2E] Firewall troubleshooting hints (manual, no automatic rule changes):"
    Write-Host ('[E2E]   New-NetFirewallRule -DisplayName "DumpAnalyzer-E2E-{0}" -Direction Inbound -Action Allow -Protocol TCP -LocalPort {0}' -f $portNumber)
    Write-Host ('[E2E]   New-NetFirewallRule -DisplayName "DumpAnalyzer-E2E-Python" -Direction Inbound -Action Allow -Program "{0}"' -f $pythonPath)
}

function Quote-Arg([string]$value) {
    return '"' + $value.Replace('"', '\"') + '"'
}

function Ensure-Command([string]$commandName) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Missing command: $commandName. Please install it and add it to PATH."
    }
}

function Test-CommandAvailable([string]$commandName) {
    return $null -ne (Get-Command $commandName -ErrorAction SilentlyContinue)
}

function Find-CdbPath {
    $candidates = @(
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        "C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
        "C:\Program Files\Debugging Tools for Windows (x86)\cdb.exe",
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\cdbX64.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\cdbX86.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\cdbARM64.exe")
    )
    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }
    return $null
}

function Reset-Directory([string]$path) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

function Ensure-Directory([string]$path) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

function Stop-StaleE2EProcesses {
    $stale = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "dump_analyzer_mcp_server --host|pytest tests/e2e"
    }
    if (-not $stale) {
        Write-Step "No stale E2E processes detected"
        return
    }
    foreach ($proc in $stale) {
        Write-Step "Stopping stale process: PID=$($proc.ProcessId), Name=$($proc.Name)"
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to stop stale process PID=$($proc.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Get-LocalIPv4 {
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
            Sort-Object -Property RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if ($route) {
            $routedIp = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
                Select-Object -First 1
            if ($routedIp) {
                return $routedIp.IPAddress
            }
        }
    } catch {
    }

    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.SkipAsSource -eq $false
    }
    if (-not $ips -or $ips.Count -eq 0) {
        throw "Unable to determine a usable local IPv4 address."
    }
    return $ips[0].IPAddress
}

function Wait-PortReady([string]$targetHost, [int]$portNumber, [int]$timeoutSec, [System.Diagnostics.Process]$process) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($process -and $process.HasExited) {
            throw "Server exited early with code $($process.ExitCode)."
        }
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect($targetHost, $portNumber, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(500)) {
                $client.EndConnect($async)
                $client.Close()
                return
            }
            $client.Close()
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "Service port is not ready within timeout: ${targetHost}:$portNumber"
}

try {
    Write-Step "Checking toolchain"
    $hasUv = Test-CommandAvailable "uv"

    if (-not (Test-Path $defaultDumpPath)) {
        throw "Default core dump not found: $defaultDumpPath"
    }
    $cdbPath = Find-CdbPath
    if (-not $cdbPath) {
        throw "cdb.exe not found. Please install WinDbg/Windows SDK first."
    }
    Write-Step "Using CDB: $cdbPath"

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if ($hasUv) {
        Write-Step "Installing dependencies with uv"
        & uv sync --dev
        if ($LASTEXITCODE -ne 0) {
            throw "uv sync --dev failed"
        }
    } elseif (Test-Path $venvPython) {
        Write-Step "uv not found in PATH, reusing existing virtual environment"
    } else {
        throw "Missing command: uv, and existing venv was not found: $venvPython"
    }
    $defaultSymbolHeavyDumpPath = Join-Path $repoRoot "tests\dumps\electron.dmp"
    $testBaseUrl = ""

    Write-Step "Resolved paths"
    Write-Step "repoRoot: $repoRoot"
    Write-Step "venvPython: $venvPython"
    Write-Step "cdbPath: $cdbPath"
    Write-Step "default dump: $defaultDumpPath"
    Write-Step "symbol-heavy default dump: $defaultSymbolHeavyDumpPath"
    Write-Step "log files: stdout=$serverStdoutLog, stderr=$serverStderrLog, pytest=$pytestLog, pytestErr=$pytestErrLog"

    Write-Step "Cleaning environment before execution"
    Write-Step "symbols temp dir: $symbolsTempDir"
    Write-Step "upload temp dir: $uploadTempDir"
    Stop-StaleE2EProcesses
    Ensure-Directory $symbolsTempDir
    Ensure-Directory $uploadTempDir

    $localIp = Get-LocalIPv4
    $publicBaseUrl = "http://${localIp}:$port"
    $testBaseUrl = $publicBaseUrl
    $symbolsPath = "srv*$symbolsTempDir*https://msdl.microsoft.com/download/symbols;srv*$symbolsTempDir*https://symbols.electronjs.org"
    Write-Step "Network and server settings"
    Write-Step "bind host/port: ${hostBind}:$port"
    Write-Step "public base URL (upload): $publicBaseUrl"
    Write-Step "E2E client base URL (MCP): $testBaseUrl"
    Write-Step "symbols path: $symbolsPath"

    Write-Step "Setting Python UTF-8 environment"
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    Write-Step "PYTHONUTF8=$($env:PYTHONUTF8)"
    Write-Step "PYTHONIOENCODING=$($env:PYTHONIOENCODING)"

    Write-Step "Starting server"
    $serverArgs = @(
        "-m dump_analyzer_mcp_server",
        "--host $hostBind",
        "--port $port",
        "--public-base-url $(Quote-Arg $publicBaseUrl)",
        "--cdb-path $(Quote-Arg $cdbPath)",
        "--symbols-path $(Quote-Arg $symbolsPath)",
        "--upload-dir $(Quote-Arg $uploadTempDir)"
    ) -join " "
    Write-Step "server command: $venvPython $serverArgs"
    Remove-Item -Path $serverStdoutLog, $serverStderrLog -ErrorAction SilentlyContinue
    Remove-Item -Path $pytestLog -ErrorAction SilentlyContinue
    Remove-Item -Path $pytestErrLog -ErrorAction SilentlyContinue
    $serverProcess = Start-Process -FilePath $venvPython -ArgumentList $serverArgs -WorkingDirectory $repoRoot -PassThru `
        -RedirectStandardOutput $serverStdoutLog -RedirectStandardError $serverStderrLog

    Wait-PortReady -targetHost $localIp -portNumber $port -timeoutSec 60 -process $serverProcess
    Start-Sleep -Seconds 2

    Write-Step "Setting fixed E2E environment variables"
    $env:DUMP_E2E_BASE_URL = $testBaseUrl
    $env:DUMP_E2E_DUMP_PATH = $defaultDumpPath
    $env:DUMP_E2E_TIMEOUT_SECONDS = $timeoutSeconds
    $env:DUMP_E2E_MCP_TRACE = "1"
    $env:DUMP_E2E_MCP_TRACE_MAX_CHARS = "12000"
    Write-Step "DUMP_E2E_BASE_URL=$($env:DUMP_E2E_BASE_URL)"
    Write-Step "DUMP_E2E_DUMP_PATH=$($env:DUMP_E2E_DUMP_PATH)"
    Write-Step "DUMP_E2E_TIMEOUT_SECONDS=$($env:DUMP_E2E_TIMEOUT_SECONDS)"
    Write-Step "DUMP_E2E_MCP_TRACE=$($env:DUMP_E2E_MCP_TRACE)"
    Write-Step "DUMP_E2E_MCP_TRACE_MAX_CHARS=$($env:DUMP_E2E_MCP_TRACE_MAX_CHARS)"

    Write-Step "Running all E2E tests (verbose + live stdout)"
    Write-Step "Command: $venvPython -m pytest tests/e2e -s -vv"
    Write-Step "pytest log file: $pytestLog"
    Write-Step "pytest stderr log file: $pytestErrLog"
    Remove-Item -Path $pytestErrLog -ErrorAction SilentlyContinue
    & $venvPython -m pytest tests/e2e -s -vv 2>&1 | Tee-Object -FilePath $pytestLog
    $pytestExitCode = $LASTEXITCODE
    if ($pytestExitCode -eq 0) {
        $scriptExitCode = 0
    } else {
        $scriptExitCode = if ($pytestExitCode) { $pytestExitCode } else { 1 }
    }

    if ($scriptExitCode -eq 0) {
        Write-Step "E2E completed successfully"
        Print-LogTail -title "Pytest log" -path $pytestLog -lineCount 60
    } else {
        Write-Step "E2E failed, pytest exit code: $scriptExitCode"
        Print-LogTail -title "Pytest log" -path $pytestLog -lineCount 120
        Print-LogTail -title "Server stdout log" -path $serverStdoutLog -lineCount 120
        Print-LogTail -title "Server stderr log" -path $serverStderrLog -lineCount 120
        Write-Host "[E2E] Port snapshot for :$port"
        Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
        Write-Host "[E2E] Process snapshot (dump_analyzer_mcp_server/python/uv)"
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "python|uv" -and $_.CommandLine -match "dump_analyzer_mcp_server|pytest|uv run"
        } | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
        Print-FirewallHints -pythonPath $venvPython -portNumber $port
    }
} catch {
    $scriptExitCode = 1
    Write-Host "[E2E] ERROR: $($_.Exception.Message)"
    Print-LogTail -title "Pytest log" -path $pytestLog -lineCount 120
    Print-LogTail -title "Server stdout log" -path $serverStdoutLog -lineCount 120
    Print-LogTail -title "Server stderr log" -path $serverStderrLog -lineCount 120
    if ($venvPython) {
        Print-FirewallHints -pythonPath $venvPython -portNumber $port
    }
} finally {
    Write-Step "Finalizing: stop server and clean environment"
    if ($serverProcess -and -not $serverProcess.HasExited) {
        try {
            Stop-Process -Id $serverProcess.Id -Force
        } catch {
        }
    }
    try {
        if (Test-Path $symbolsTempDir) {
            Remove-Item -Path $symbolsTempDir -Recurse -Force
        }
        if (Test-Path $uploadTempDir) {
            Remove-Item -Path $uploadTempDir -Recurse -Force
        }
    } catch {
        Write-Warning "Cleanup warning: $($_.Exception.Message)"
    }
    exit $scriptExitCode
}
