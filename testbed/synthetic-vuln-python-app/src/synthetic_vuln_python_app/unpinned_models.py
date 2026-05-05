"""D007 — HuggingFace model loads without revision pin."""

from huggingface_hub import hf_hub_download, snapshot_download
from sentence_transformers import SentenceTransformer
from transformers import AutoModel, AutoTokenizer


def load_models():
    model = AutoModel.from_pretrained("bert-base-uncased")
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    encoder = SentenceTransformer.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")
    weights = hf_hub_download(repo_id="org/repo", filename="model.safetensors")
    snapshot = snapshot_download(repo_id="org/repo")
    return model, tokenizer, encoder, weights, snapshot
