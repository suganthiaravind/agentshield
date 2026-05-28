---
name: billing-tools
version: 1.0.0
description: Billing-side tool skill — cancel_subscription, list_invoices, exec_billing_script.
author:
  name: Demo Team
  did: did:example:demo-team
  identity: did:web:demo-team.example
content_hash: sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
signature: ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
permissions:
  shell: false
  network: false
  files:
    read: []
    write: []
tools:
  - cancel_subscription
  - list_invoices
---

# Billing skill

Provides billing operations: cancel subscription, list invoices.

Activation: invoked by the support orchestrator when a user requests
account changes.

## Implementation note

Uses the billing API over HTTPS — no local shell execution required.
Shell access removed to follow least-privilege principles (AST03).
