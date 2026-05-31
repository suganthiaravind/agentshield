#Requires -Version 5.1
<#
.SYNOPSIS
    AgentShield Tier 1 scan — VDI-safe wrapper.

.DESCRIPTION
    Handles VDI preflight (UTF-8 encoding, semgrep PATH relocation),
    optionally installs AgentShield, runs the Tier 1 static scan, then
    copies the Tier 2 Copilot Chat prompt to the clipboard so you can
    paste it straight into VS Code.

.PARAMETER RepoPath
    Absolute path to the agent repository you want to scan.
    Example: H:\repos\my-agent

.PARAMETER SkipInstall
    Skip the AgentShield install/check step (useful when already installed).

.EXAMPLE
    .\run_tier1.ps1 -RepoPath "H:\repos\my-agent"

.EXAMPLE
    .\run_tier1.ps1 -RepoPath "H:\repos\my-agent" -SkipInstall
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Absolute path to the agent repo to scan.")]
    [string]$RepoPath,

    [switch]$SkipInstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── VDI preflight ──────────────────────────────────────────────────────────────
# 1. Fix console encoding — prevents Unicode errors in semgrep output on VDI.
[Console]::OutputEncoding       = [System.Text.Encoding]::UTF8
[Console]::InputEncoding        = [System.Text.Encoding]::UTF8
$OutputEncoding                  = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING            = "utf-8"

# 2. semgrep installs to %APPDATA%\Python\Scripts which is blocked on many VDI
#    roaming profiles. Copy the binary to %LOCALAPPDATA%\agentshield-bin and
#    prepend that directory to PATH so every subsequent call finds it.
$roamingScripts = "$env:APPDATA\Python\Scripts"
$localBin       = "$env:LOCALAPPDATA\agentshield-bin"

foreach ($exe in @("semgrep.exe", "semgrep")) {
    $src = Join-Path $roamingScripts $exe
    $dst = Join-Path $localBin       $exe
    if ((Test-Path $src) -and -not (Test-Path $dst)) {
        Write-Host "[preflight] Relocating $exe to $localBin ..."
        New-Item -ItemType Directory -Force -Path $localBin | Out-Null
        Copy-Item $src $dst
    }
}

if (Test-Path $localBin) {
    if ($env:PATH -notlike "*$localBin*") {
        $env:PATH = "$localBin;$env:PATH"
    }
}

Write-Host ""
Write-Host "AgentShield Tier 1 — VDI runner"
Write-Host "================================"
Write-Host "Target repo : $RepoPath"
Write-Host ""

# ── Validate repo path ─────────────────────────────────────────────────────────
if (-not (Test-Path $RepoPath)) {
    Write-Error "RepoPath does not exist: $RepoPath"
    exit 1
}

# ── Install AgentShield ────────────────────────────────────────────────────────
if (-not $SkipInstall) {
    $ver = & agentshield --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $ver) {
        Write-Host "[install] AgentShield already installed: $ver  (use -SkipInstall to suppress this check)"
    } else {
        Write-Host "[install] Installing AgentShield (pip install -e .[semgrep,dev]) ..."
        pip install -e ".[semgrep,dev]"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "pip install failed — check the output above."
            exit $LASTEXITCODE
        }
        Write-Host "[install] Done."
    }
}

Write-Host ""

# ── Tier 1 scan ────────────────────────────────────────────────────────────────
Write-Host "[scan] Running Tier 1 static scan ..."
& agentshield scan $RepoPath --scan-all-files

if ($LASTEXITCODE -ne 0) {
    Write-Error "Tier 1 scan exited with code $LASTEXITCODE — check output above."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "[done] Tier 1 complete.  Skill files written to:"
Write-Host "       $RepoPath\.agentshield\"
Write-Host ""

# ── Copy Tier 2 prompt to clipboard ───────────────────────────────────────────
$promptScript = Join-Path $PSScriptRoot "generate_copilot_prompts.ps1"
if (Test-Path $promptScript) {
    Write-Host "[prompts] Generating Tier 2 prompt and copying to clipboard ..."
    & $promptScript -RepoPath $RepoPath -Mode Tier2 -CopyToClipboard
} else {
    Write-Host "[prompts] generate_copilot_prompts.ps1 not found — skipping."
    Write-Host "          Paste the Tier 2 prompt from QUICKSTART.md into Copilot Chat manually."
}

Write-Host ""
Write-Host "Next step:"
Write-Host "  Open $RepoPath in VS Code, open Copilot Chat, and paste the prompt."
