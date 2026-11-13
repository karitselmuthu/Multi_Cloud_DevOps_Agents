"""Knowledge/RAG: keyword-overlap retrieval over knowledge/*.md paragraphs.
ponytail: no embeddings/vector DB; swap in pgvector/OpenSearch when the corpus outgrows a few hundred paragraphs."""
import pathlib
import re

KB = pathlib.Path(__file__).resolve().parent.parent / "knowledge"


def _tok(s):
    return set(re.findall(r"[a-z0-9]{3,}", s.lower()))


def search(query, k=3):
    q = _tok(query)
    scored = []
    for f in sorted(KB.glob("*.md")):
        for para in re.split(r"\n\s*\n", f.read_text()):
            if (n := len(q & _tok(para))):
                scored.append((n, f"{f.name}: {para.strip()}"))
    return [p for _, p in sorted(scored, key=lambda x: -x[0])[:k]]
