"""Fixture: should NOT trigger D007.

Every load passes an explicit `revision=` argument pinned to a commit
SHA — supply chain is locked, force-pushes to `main` don't affect this code.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from huggingface_hub import hf_hub_download, snapshot_download
from transformers import AutoModel, AutoTokenizer


PINNED_REVISION = "86b5e0934494bd15c9632b12f734a8a67f723594"


def main() -> None:
    model = AutoModel.from_pretrained("bert-base-uncased", revision=PINNED_REVISION)
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased", revision=PINNED_REVISION)
    weights = hf_hub_download(
        repo_id="org/repo",
        filename="model.safetensors",
        revision=PINNED_REVISION,
    )
    snapshot = snapshot_download(repo_id="org/repo", revision=PINNED_REVISION)
