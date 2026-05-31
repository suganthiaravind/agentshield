# AgentShield — Installation

One-time setup. Run this before your first scan.

---

## 1 — Clone the AgentShield repo

```bash
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield
git checkout v7
```

---

## 2 — Open in VS Code

Open the **AgentShield repo** in VS Code. Keep this window open for
every scan — all terminal commands and Copilot Chat prompts run here.

---

## 3 — Install

```bash
pip install -e ".[semgrep,dev]"
```

**Done when you see:** `agentshield 4.x.x` when you run:

```bash
agentshield --version
```

---

## Windows / VDI

If you are on a **Windows VDI** (e.g. JPMC desktop), open the
AgentShield repo in VS Code and run from a **PowerShell** terminal:

```powershell
pip install -e ".[semgrep,dev]"
```

If `pip` is blocked by roaming-profile PATH restrictions, the
`run_tier1.ps1` script handles the install automatically — see
[QUICKSTART.md](./QUICKSTART.md) step 2.

---

Once installed, go to [QUICKSTART.md](./QUICKSTART.md) to run your first scan.
