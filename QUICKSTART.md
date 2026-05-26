# AgentShield — Quick Start

Follow this file top to bottom. The only thing you set is your repo path.

---

## 0 — Set your target

```bash
export REPO=/absolute/path/to/your-agent-repo
```

> Replace `/absolute/path/to/your-agent-repo` with the real path.  
> Every command below uses `$REPO` — set it once, run everything.

---

## 1 — Install AgentShield

```bash
git clone https://github.com/your-org/agentshield.git
cd agentshield
pip install -e ".[semgrep,dev]"
agentshield --version
```

**What happens:** Downloads AgentShield and installs the CLI with Semgrep bundled.  
**Done when you see:** `agentshield 4.x.x`

---

## 2 — Run the Tier 1 scan

```bash
agentshield scan $REPO --scan-all-files
```

**What happens:** Semgrep runs 70+ security rules against your source code.  
Skill files are written to `$REPO/.agentshield/` for the next step.  
**Done when you see:** `[agentshield] ✓ Skill files → .agentshield/`

---

## 3 — Tier 2 + Behaviour Emulator  *(VS Code + Copilot — no CLI)*

1. Open `$REPO` in **VS Code** with the **GitHub Copilot Chat** extension active.
2. Open `$REPO/.agentshield/SKILL.md` → copy all contents → paste into Copilot Chat.
3. Wait for Copilot to finish. It writes `$REPO/.agentshield/tier2-findings.json`.
4. Open `$REPO/.agentshield/AGENT_EMULATOR_SKILL.md` → copy → paste into Copilot Chat.
5. Wait for Copilot to finish. It writes `$REPO/.agentshield/agent-emulation.json`.

**What happens:** Copilot walks every source file, validates Tier 1 findings (TP/FP),
discovers new issues, and simulates 14 adversary attack classes against your pipeline.

---

## 4 — Generate the unified report

```bash
agentshield merge $REPO --output-html report.html
open report.html
```

**What happens:** Merges Tier 1 + Tier 2 + Emulator results into a single HTML report
with D/D/R findings, fix guidance, and OWASP LLM / MITRE ATLAS / CWE mappings.  
**Done when you see:** `[agentshield] ✓ Wrote: report.html`

---

## That's it

| Step | Command | Output |
|---|---|---|
| 0 | `export REPO=...` | Target set |
| 1 | `pip install -e ".[semgrep,dev]"` | `agentshield` CLI |
| 2 | `agentshield scan $REPO --scan-all-files` | `tier1-results.json` + skill files |
| 3 | VS Code + Copilot Chat (×2 pastes) | `tier2-findings.json` + `agent-emulation.json` |
| 4 | `agentshield merge $REPO --output-html report.html` | `report.html` |

For flags, troubleshooting, and CI integration see [INSTALL.md](./INSTALL.md).
