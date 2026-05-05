"""D002 — URL document loader with no allowlist, output indexed."""

from langchain_community.document_loaders import WebBaseLoader, RecursiveUrlLoader


def load_attacker_url(url: str):
    loader = WebBaseLoader(url)
    return loader.load()


def load_recursive(url: str):
    return RecursiveUrlLoader(url=url, max_depth=3).load()
