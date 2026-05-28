# AgentShield — Speaker Notes

---

## Slide 1 — AI Agent: Production Readiness Review

We've been shipping software for decades. We know how to review it, test it, and sign it off. But AI agents are different — they don't just execute instructions, they interpret them. And that changes the risk conversation entirely.

What I've found is that every team involved in shipping an agent is worried — but they're each worried about a different thing. Legal is thinking about the regulator call they don't want to receive. Engineering is thinking about what happens if the agent gets manipulated and starts acting on its own. The developer is confident in what they built — but they've never had to think like an attacker before. And security knows the tools they rely on were designed for a world that didn't have AI agents in it.

The thing is — none of them are wrong. They're all looking at the same risk from a different seat.

That's what this question is about. Not a checklist. Not a sign-off form. One question that forces every seat in the room to agree before we ship: *did we cover everything that matters?* If we can answer that with confidence — with evidence — the agent is ready. If we can't, it isn't.

---

## Slide 2 — The Problem

The honest answer to that question — "have we covered all the potential issues in this AI agent?" — is that most teams today don't know. Existing tools weren't designed for this, reviews are inconsistent, and problems surface too late.

Traditional security scanners were built for web applications and have no understanding of how AI agents behave or how they can be manipulated. They only check whether the doors are locked.

AgentShield does both. It checks whether the doors are locked — and it checks whether someone can knock, say they're from IT, and still get in. That's the difference between knowing your protections exist and knowing whether they actually hold against a real adversary.

---

## Slide 3 — AgentShield Solution Blueprint

We built AgentShield on a simple principle — if the industry has already agreed on what good looks like, our job is to make that enforceable. Every control, every check, every finding in AgentShield traces back to one of five frameworks the security community has established: OWASP LLM Top 10 v2 (Open Worldwide Application Security Project — Large Language Model), OWASP Agentic AI Top 10, OWASP AST10 (Agentic Skills Top 10), MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems), and CWE (Common Weakness Enumeration). This isn't our opinion of what matters. It's the industry's.

The pipeline runs in four steps — and each one builds on the last.

It starts with what you already have. Your agent's source code, skill manifests, and bundled configs. No deployed environment, no live endpoint, no test infrastructure to spin up. AgentShield meets you where the work happens — in the repository.

From there, the static scan takes everything it can find from code alone. Three layers — Semgrep (Semantic Grep) for precise, deterministic pattern matching across Python and Java; a manifest scanner that reads your SKILL.md and AGENT.md files for supply-chain and configuration risks; and Copilot as an interpretive reviewer for the checks that require judgment rather than pattern matching. More than a hundred checks, running consistently, with no variance between teams or reviewers.

Then the behaviour emulator does what static analysis cannot. It doesn't ask whether the protection is there — it asks whether the protection holds. Fourteen attack classes, each escalating through up to eight attempts — a hundred and twelve total — with Copilot simultaneously playing the role of planner, attacker, agent, and judge. The whole thing runs offline, from source, with no agent running anywhere.

And everything converges into one report. Every finding ranked by severity, tagged to its exact framework reference — whether that's OWASP, MITRE ATLAS, or CWE — deduplicated across all three scanning layers. Delivered in HTML, Markdown, JSON, or SARIF (Static Analysis Results Interchange Format) for direct integration into GitHub, Azure DevOps, and enterprise security dashboards. And for every finding type, a FIX.MD — a ready-made remediation guide you paste directly into Claude or Copilot. The distance between finding a problem and fixing it has never been shorter.

---

## Slide 4 — How AgentShield Works

One command. One repository. Everything else is automatic.

AgentShield takes your codebase — source code, manifests, configs — and fans it out into two analysis phases simultaneously. Static analysis interrogates the code for known vulnerabilities. Behaviour emulation thinks like an attacker and tests whether the defences actually hold. Both run from the same scan. Neither requires a live agent.

The two phases converge into a single merge step — findings deduplicated, ranked by severity, sorted into Detect, Defend, and Respond. Every finding tagged to the exact framework item it maps to. Every finding type paired with a FIX.MD — a remediation guide ready to hand to a developer or drop straight into Claude or Copilot.

The output is a report that's reproducible, framework-mapped, and ready before the agent ships. Not after. Before.

---

## Slide 5 — AgentShield Behavior Emulator

Imagine hiring a red team to attack your agent — but instead of waiting until it's deployed, they work entirely from the blueprints. No live system. No test environment. Just the code. That's exactly what the behaviour emulator does.

Before it fires a single attack, it reads the agent like a story. Eight steps — how user input enters, how documents are retrieved, how the system prompt is constructed, how the model plans, how tools are chosen and executed, how the agent re-plans, and finally how the answer leaves. Every step mapped to a file and a line number. This is the agent's architecture, laid bare.

Then the attacks begin. Fourteen classes — every major way an adversary tries to manipulate, deceive, or break an AI agent. From blunt prompt injection to memory poisoning, from tool argument manipulation to partial-defence bypass. Each one grounded in OWASP (Open Worldwide Application Security Project), MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems), and CWE (Common Weakness Enumeration).

But here's what makes it different. It doesn't just fire one payload and move on. For every attack class, it starts with three fixed seeds — a blunt override, a social engineering attempt, a fake authority claim. If all three are blocked, it doesn't give up. It reads the defence that blocked them, and generates mutations specifically designed to get around that exact defence. Up to five attempts, each one smarter than the last. This is how a real attacker thinks — observe, adapt, try again.

Copilot runs the entire process playing four roles at once: the planner designing the attack, the attacker delivering it, the agent receiving it, and the judge deciding whether it landed.

What comes out is a verdict for every attack class — lands, partial, blocked, or inconclusive — with the exact file and line that made the difference. Not a guess. A prediction grounded in code.

---

## Hackathon / Innovation Week Submission

### Session title
AgentShield — Your AI Agent's Preflight Safety Check

### Project description

As AI agents move into production, the manual effort required to assess security, prompt integrity, privacy boundaries, and behavioral compliance creates a critical scalability gap that no team can sustainably close by hand.

AgentShield is an automated risk-assessment engine that closes that gap before deployment. It discovers every entry point into your agent — HTTP routes, chat handlers, scheduled triggers, and sub-agent call sites — then runs three layers of analysis against each one: a rules-engine static scan for known-bad code patterns, an LLM-as-judge review that reads the full codebase as a senior security engineer would, and a behaviour emulator that fires 17 adversarial attack classes across 136 payloads per entry point — no live endpoint required.

Critically, AgentShield does not stop at source code. It also reviews your agent's skill and manifest files — `SKILL.md`, `AGENT.md`, `AGENTS.md`, `CLAUDE.md`, and bundled configuration — the documents that define what your agent is allowed to do, which tools it can invoke, and how it presents itself to the LLM. Risky permissions, missing safety markers, dangerous tool combinations, and jailbreak text hidden inside these files are surfaced alongside code findings, giving a complete picture of the agent's declared versus actual attack surface.

The result is a structured, reproducible report with categorised findings across Detect / Defend / Respond, severity ratings, remediation guidance, and a composite risk score — mapped to OWASP LLM Top 10, OWASP Agentic AI, MITRE ATLAS, and CWE.

This session demonstrates the end-to-end workflow: from a single CLI command to an interactive report with animated kill-chain walkthroughs, framework coverage matrices, and per-finding fix guidance — giving teams a consistent, confidence-building gate before every agent deployment.

### Key benefits

- **Shift security left.** Vulnerabilities are caught at development time, not after a breach — the same way unit tests catch bugs before they reach production.
- **No live agent required.** The behaviour emulator runs entirely offline using static analysis outputs, eliminating exposure risk during assessment.
- **Full attack surface visibility.** AgentShield automatically discovers every entry point — including sub-agent call sites — and tests each one independently, so a hardened public endpoint cannot mask an unguarded internal one.
- **Scales with your fleet.** A single CLI command assesses any agent codebase in minutes, making it practical to gate every pull request or deployment pipeline, not just quarterly audits.
- **Actionable, not just informational.** Every finding ships with severity context, a plain-English explanation, targeted remediation guidance, and framework-level mapping — so engineers know exactly what to fix and why.
- **Framework agnostic.** Works across LangChain, LlamaIndex, Google ADK, Spring AI, Bedrock Agents, and custom agent architectures without configuration changes.
- **Consistent, reproducible results.** The same fixed seed payloads fire on every run, making re-assessments after a fix directly comparable — no noise between runs.
- **Built for agentic-specific threats.** Goes beyond standard AppSec by testing multi-agent trust boundaries, memory poisoning, tool-argument injection, and sub-agent privilege escalation — attack classes that generic scanners were never designed to find.
