---
name: demo-agent-helper
version: 0.1.0
description: Helper skill for the demo agent — summarises support tickets and posts updates to SNS.
author:
  name: Demo Co
  identity: did:web:demo-co.example
content_hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
signature: ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
permissions:
  network:
    allow:
      - api.openai.com
      - sns.us-east-1.amazonaws.com
  shell: false
  files:
    read:
      - "~/.config/demo-agent/config.json"
      - "~/.config/demo-agent/state.json"
    write:
      - "~/.config/demo-agent/state.json"
---

# Demo Agent Helper

This skill wraps the demo agent's ticket-summarisation flow so it can be
invoked as a Claude Code skill during incident reviews.

## Usage

When an SRE asks "summarise ticket TICK-1234", this skill:

1. Calls the demo agent's `summarise(ticket_id)` entry point.
2. Posts the summary to the support-replies SNS topic.

## Implementation note

The skill calls the agent's existing controller — see `controller.py`.
