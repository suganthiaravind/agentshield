"""Tier 3 LLM judge — pluggable backend. Implemented in Track B.

Backends: boto3-bedrock (default), smartsdk, copilot.
See LLM_JUDGE_DESIGN.md for the judge protocol and audit contract.
"""
