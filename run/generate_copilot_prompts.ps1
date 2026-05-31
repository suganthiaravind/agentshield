#Requires -Version 5.1
<#
.SYNOPSIS
    Generate AgentShield Copilot Chat prompts for Tier 2 and/or the behaviour emulator.

.DESCRIPTION
    Writes the ready-to-paste Copilot Chat prompt(s) to
    <RepoPath>\.agentshield\copilot-prompts.txt and optionally copies
    the first relevant prompt to the clipboard.

.PARAMETER RepoPath
    Absolute path to the agent repository that was already scanned by Tier 1.

.PARAMETER Mode
    Which prompt(s) to generate:
      Tier2    — Tier 2 LLM-as-judge prompt only (default for run_tier1.ps1)
      Emulator — Phase 2 behaviour-emulator prompt only
      Both     — Both prompts in one file; Tier 2 goes to clipboard

.PARAMETER CopyToClipboard
    Copy the primary prompt to the Windows clipboard.

.EXAMPLE
    .\generate_copilot_prompts.ps1 -RepoPath "H:\repos\my-agent" -Mode Both -CopyToClipboard

.EXAMPLE
    .\generate_copilot_prompts.ps1 -RepoPath "H:\repos\my-agent" -Mode Emulator -CopyToClipboard
#>

param(
    [Parameter(Mandatory = $true, HelpMessage = "Absolute path to the scanned agent repo.")]
    [string]$RepoPath,

    [ValidateSet("Tier2", "Emulator", "Both")]
    [string]$Mode = "Both",

    [switch]$CopyToClipboard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Prompt text ────────────────────────────────────────────────────────────────
$tier2Prompt = @'
@workspace Please run AgentShield Tier 2.

Read the checklist at .agentshield/tier2-checklist.md and the
output schema at .agentshield/tier2-output-schema.md. Walk every
source file in this workspace, apply each check that is in scope
for the file's language, and write your findings to
.agentshield/tier2-findings.json following the schema exactly.

Also read .agentshield/tier1-results.json and add a
tier1_fp_callouts section noting any Tier 1 finding you believe
is a false positive, with reasoning.

Important: copy the agentshield_tier1_fingerprint field from
tier1-results.json verbatim into your output. The merger uses it
to detect stale Tier 2 runs.
'@

$emulatorPrompt = @'
@workspace Please run the AgentShield agent behaviour emulator.

Read the instructions at
.agentshield/agent-emulator-instructions.md and the output
schema at .agentshield/agent-emulator-output-schema.md.

Step 0 — Enumerate entry points first (mandatory).
Before classifying the agent type, list every distinct entry
point in the codebase: all HTTP route handlers (@app.route,
FastAPI path ops), WebSocket handlers, Lambda handlers,
scheduled-job triggers, and inter-agent receivers. For each
entry point, note whether it has an input filter, whether it
calls chain.invoke, whether it has a system prompt, whether it
has tools, and whether it forwards to a downstream agent.
Group entry points that share an identical pipeline
configuration — entry points with ANY pipeline difference get
their own block.

If two or more distinct pipeline configurations exist, use the
entry_points[] schema (see output schema). Each entry point
block must contain all 17 attack-class traces evaluated
independently against that entry point's pipeline. An attack
blocked by a filter on one route may land on a sibling route
without a filter — do not share verdicts across entry points.

Then classify the agent type: interactive, batch, sub-agent,
or orchestrator. Walk each entry point's pipeline from source
code. For each applicable catalogued attack class, identify the
pipeline step(s) it targets, predict the pipeline behaviour
under that attack for each entry point, and cite the file:line
evidence for every prediction.

Use the GENERIC catalogue payloads exactly as shipped — do not
adapt the attacker-side text from source code. The intelligence
comes from what the agent reveals, not from what you read in
the repo.

Write your pipeline emulations to
.agentshield/agent-emulation.json following the schema exactly.
Mark inconclusive when the relevant pipeline step isn't present
— do not fabricate behaviour.
'@

# ── Validate repo path ─────────────────────────────────────────────────────────
if (-not (Test-Path $RepoPath)) {
    Write-Error "RepoPath does not exist: $RepoPath"
    exit 1
}

# ── Build file content ─────────────────────────────────────────────────────────
$separator = "`n" + ("=" * 72) + "`n"
$sections  = @()

if ($Mode -in @("Tier2", "Both")) {
    $sections += @(
        "# AgentShield — Tier 2 Copilot Chat Prompt",
        "# Paste the block below verbatim into Copilot Chat (@workspace must be first).",
        "",
        $tier2Prompt
    ) -join "`n"
}

if ($Mode -in @("Emulator", "Both")) {
    $sections += @(
        "# AgentShield — Phase 2 Behaviour Emulator Prompt",
        "# Run this AFTER tier2-findings.json exists in .agentshield/.",
        "# Paste the block below verbatim into Copilot Chat (@workspace must be first).",
        "",
        $emulatorPrompt
    ) -join "`n"
}

$fileContent = $sections -join $separator

# ── Write to .agentshield/copilot-prompts.txt ──────────────────────────────────
$agentshieldDir = Join-Path $RepoPath ".agentshield"
if (-not (Test-Path $agentshieldDir)) {
    New-Item -ItemType Directory -Force -Path $agentshieldDir | Out-Null
}
$outFile = Join-Path $agentshieldDir "copilot-prompts.txt"
[System.IO.File]::WriteAllText($outFile, $fileContent, [System.Text.Encoding]::UTF8)
Write-Host "[prompts] Saved  → $outFile"

# ── Clipboard ──────────────────────────────────────────────────────────────────
if ($CopyToClipboard) {
    $clipContent = switch ($Mode) {
        "Tier2"    { $tier2Prompt }
        "Emulator" { $emulatorPrompt }
        "Both"     { $tier2Prompt }
    }
    Set-Clipboard -Value $clipContent

    $label = if ($Mode -eq "Emulator") { "Emulator" } else { "Tier 2" }
    Write-Host "[prompts] $label prompt copied to clipboard."
    Write-Host "          Switch to VS Code → Copilot Chat → paste (Ctrl+V)."
}
