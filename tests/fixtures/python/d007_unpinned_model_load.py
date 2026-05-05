"""Fixture: should trigger D007 (untrusted model loading).

Each load below pulls a HuggingFace model / file without pinning the
revision, leaving the supply chain exposed to a force-pushed `main`.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from huggingface_hub import hf_hub_download, snapshot_download
from sentence_transformers import SentenceTransformer
from transformers import AutoModel, AutoTokenizer


def main() -> None:
    # transformers — no revision pin
    model = AutoModel.from_pretrained("bert-base-uncased")  # D007
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")  # D007

    # sentence-transformers — no revision pin
    encoder = SentenceTransformer.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")  # D007

    # huggingface_hub direct downloads — no revision pin
    weights = hf_hub_download(repo_id="org/repo", filename="model.safetensors")  # D007
    snapshot = snapshot_download(repo_id="org/repo")  # D007
