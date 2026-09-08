<#
.SYNOPSIS
    Cross-language round-trip check for RustCrypt.

.DESCRIPTION
    For every sibling CLI found on PATH (gocrypt-cli, pycrypt, nodecrypt) and
    every mode (default, --jasypt, --jasypt-strong) this script:
      1. encrypts with rustcrypt and decrypts with the sibling, and
      2. encrypts with the sibling and decrypts with rustcrypt,
    for several plaintexts (ASCII, punctuation, 200 chars, UTF-8 + emoji).
    Tools that are not installed are reported as SKIP.

.PARAMETER Password
    Shared password (default: rustcrypt-test-2026).

.PARAMETER RustCrypt
    Path to the rustcrypt binary. When omitted the script builds it with
    `cargo build --release` and uses target/release/rustcrypt.

.EXAMPLE
    pwsh scripts/cross-check.ps1
    powershell -ExecutionPolicy Bypass -File scripts\cross-check.ps1 -RustCrypt target\debug\rustcrypt.exe
#>
[CmdletBinding()]
param(
    [string]$Password = "rustcrypt-test-2026",
    [string]$RustCrypt = ""
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot

if (-not $RustCrypt) {
    Write-Host "Building rustcrypt (release)..."
    & cargo build --release --locked --manifest-path (Join-Path $root "Cargo.toml") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    $RustCrypt = Join-Path $root "target/release/rustcrypt"
    if (Test-Path "$RustCrypt.exe") { $RustCrypt = "$RustCrypt.exe" }
}
if (-not (Test-Path $RustCrypt)) { throw "rustcrypt binary not found: $RustCrypt" }

$plaintexts = @(
    "hello",
    "Password123!",
    ("0123456789" * 20),
    "Selamat pagi, Fariz 🦀"
)

$modes = @(
    @{ Name = "default";       Flag = $null },
    @{ Name = "jasypt";        Flag = "--jasypt" },
    @{ Name = "jasypt-strong"; Flag = "--jasypt-strong" }
)

# Every sibling CLI shares the gocrypt-cli argument layout:
#   <tool> encrypt -p <pw> -v <value> [--jasypt|--jasypt-strong]
#   <tool> decrypt -p <pw> -v <value> [--jasypt|--jasypt-strong]
$tools = @(
    @{ Name = "gocrypt-cli"; Cmd = "gocrypt-cli" },
    @{ Name = "pycrypt";     Cmd = "pycrypt" },
    @{ Name = "nodecrypt";   Cmd = "nodecrypt" }
)

function Invoke-Cli {
    param([string]$Exe, [string[]]$CliArgs)
    $out = & $Exe @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($CliArgs -join ' ') failed: $out" }
    return (($out | Out-String).TrimEnd("`r", "`n"))
}

function Get-Args {
    param([string]$Verb, [string]$Value, [string]$Flag)
    $a = @($Verb, "-p", $Password, "-v", $Value)
    if ($Flag) { $a += $Flag }
    return $a
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($tool in $tools) {
    $exe = Get-Command $tool.Cmd -ErrorAction SilentlyContinue
    if (-not $exe) {
        $results.Add([pscustomobject]@{ Tool = $tool.Name; Mode = "*"; Direction = "*"; Result = "SKIP (not on PATH)" })
        continue
    }
    foreach ($mode in $modes) {
        $toRust = "PASS"
        $fromRust = "PASS"
        foreach ($pt in $plaintexts) {
            try {
                # rustcrypt -> tool
                $enc = Invoke-Cli $RustCrypt (Get-Args "encrypt" $pt $mode.Flag)
                $dec = Invoke-Cli $exe.Source (Get-Args "decrypt" $enc $mode.Flag)
                if ($dec -ne $pt) { $fromRust = "FAIL ($pt)" }

                # tool -> rustcrypt
                $enc = Invoke-Cli $exe.Source (Get-Args "encrypt" $pt $mode.Flag)
                $dec = Invoke-Cli $RustCrypt (Get-Args "decrypt" $enc $mode.Flag)
                if ($dec -ne $pt) { $toRust = "FAIL ($pt)" }
            } catch {
                $fromRust = "ERROR: $($_.Exception.Message)"
                $toRust = $fromRust
            }
        }
        $results.Add([pscustomobject]@{ Tool = $tool.Name; Mode = $mode.Name; Direction = "rustcrypt -> $($tool.Name)"; Result = $fromRust })
        $results.Add([pscustomobject]@{ Tool = $tool.Name; Mode = $mode.Name; Direction = "$($tool.Name) -> rustcrypt"; Result = $toRust })
    }
}

$results | Format-Table -AutoSize | Out-String | Write-Host

$failed = @($results | Where-Object { $_.Result -notlike "PASS*" -and $_.Result -notlike "SKIP*" })
if ($failed.Count -gt 0) {
    Write-Host "Cross-check FAILED ($($failed.Count) failures)" -ForegroundColor Red
    exit 1
}
Write-Host "Cross-check OK" -ForegroundColor Green
