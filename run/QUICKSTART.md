# AgentShield — Quick Start

> **First time?** Follow [INSTALL.md](./INSTALL.md) before continuing here.

Run a complete scan in four steps, all from the **AgentShield repo**.
You never need to open the target repo in a separate VS Code window.

---

## 1 — Tier 1: static scan

```bash
agentshield scan /absolute/path/to/your-agent-repo --scan-all-files
```

> **Windows / VDI:** use the PowerShell wrapper instead — see [§ Windows / VDI](#windows--vdi) below.

What this does:

- Runs 19 Semgrep rules (Python & Java AST) + 12 Manifest scanner rules
- Writes contract files to `<target-repo>/.agentshield/`
- Generates **`<target-repo>/.agentshield/copilot-prompts.md`** — a
  ready-to-paste file containing the exact Tier 2 and emulator prompts
  with absolute paths to the target repo

**Done when you see** the Tier 2 prompt printed at the bottom of the terminal output.

---

## 2 — Tier 2: LLM scan *(Copilot Chat)*

1. Open **`<target-repo>/.agentshield/copilot-prompts.md`** in VS Code.
2. Copy the entire **`## Step 1 — Tier 2: LLM scan`** fenced block.
3. Paste it into **Copilot Chat** (the same VS Code window).

> The prompt already contains absolute paths to the target repo —
> no need to change anything before pasting.

Wait for Copilot to finish (single file ~30 s, 10 files ~2 min, 50 files ~10 min).

**Done when:** `<target-repo>/.agentshield/tier2-findings.json` exists.

If the file doesn't appear after Copilot says it's done:
> "You said you finished but `tier2-findings.json` doesn't exist at
> `<target-repo>/.agentshield/tier2-findings.json`. Please write the
> JSON output to that exact path."

---

## 3 — Behaviour emulator *(Copilot Chat)*

1. In the same **`copilot-prompts.md`** file, copy the entire
   **`## Step 2 — Behaviour emulator`** fenced block.
2. Paste it into **Copilot Chat**.

Wait for Copilot to finish (1 entry point ~5 min, 3–5 entry points ~15 min).

**Done when:** `<target-repo>/.agentshield/agent-emulation.json` exists.

If the file doesn't appear:
> "You said you finished but `agent-emulation.json` doesn't exist at
> `<target-repo>/.agentshield/agent-emulation.json`. Please write the
> JSON output to that exact path."

---

## 4 — Merge → unified report

```bash
agentshield merge /absolute/path/to/your-agent-repo
```

Combines Tier 1 + Tier 2 + behaviour emulator into a single report,
then automatically runs all 14 health checks. Output lands in the
**target repo's** `output/` folder:

```
<target-repo>/output/
├── 20260530-123456/
│   ├── agentshield-report.html            ← interactive (tabs, filter, search, Reference)
│   ├── agentshield-report-print.html      ← printable / stacked view
│   ├── agentshield-findings-fix.md        ← paste into Claude Code to fix all findings
│   └── agentshield-emulator-payloads.md   ← emulator attack walkthroughs per source × transition
└── agentshield-report.html                ← "latest" copy, always reflects the most recent run
```

Open the report:
```bash
open <target-repo>/output/agentshield-report.html          # macOS
# start <target-repo>\output\agentshield-report.html       # Windows
# xdg-open <target-repo>/output/agentshield-report.html   # Linux
```

**Done when you see:** `✓  Report health: 14/14  —  ALL CHECKS PASSED`

---

## Summary

| Step | What | Where |
|---|---|---|
| 1 | `agentshield scan <target-path> --scan-all-files` → generates `copilot-prompts.md` | Terminal |
| 2 | Copy **Step 1** from `copilot-prompts.md` → paste into Copilot Chat | VS Code |
| 3 | Copy **Step 2** from `copilot-prompts.md` → paste into Copilot Chat | VS Code |
| 4 | `agentshield merge <target-path>` → `✓ 14/14` → open `output/agentshield-report.html` | Terminal |

---

## Windows / VDI

Use this if you are on a **Windows VDI** (e.g. JPMC desktop) where
roaming-profile PATH restrictions or Unicode encoding issues block the
normal CLI flow. Open the **AgentShield repo** in VS Code / JetBrains,
then run from a PowerShell terminal:

```powershell
.\run\run_tier1.ps1 -RepoPath "H:\path\to\your-agent-repo"
```

What it does automatically:

| Step | Action |
|------|--------|
| Preflight | Sets console encoding to UTF-8; relocates `semgrep.exe` from the blocked roaming profile to `%LOCALAPPDATA%\agentshield-bin` |
| Install | `pip install -e ".[semgrep,dev]"` (skipped if already installed) |
| Scan | `agentshield scan <RepoPath> --scan-all-files` |
| Prompts | Generates `<RepoPath>\.agentshield\copilot-prompts.md` |

**Done when you see:** `[done] Tier 1 complete.`

Then open `<RepoPath>\.agentshield\copilot-prompts.md` in VS Code and
follow steps 2–4 above.

Flags for `run_tier1.ps1`:

| Flag | Effect |
|------|--------|
| `-SkipInstall` | Skip the `pip install` check |

---

For flags, troubleshooting, and CI integration (`--require-fresh`) see [EXECUTE_AGENTSHIELD.md](./EXECUTE_AGENTSHIELD.md).
