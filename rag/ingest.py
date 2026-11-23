"""Ingestion de la base de connaissances EVA-Guard dans ChromaDB.

- Front matter par fichier : doc_id, category, attack_type, surface, label, evidence_level.
- Découpage par titres `##` / `###`.
- Surcharge de métadonnées par section via un commentaire : <!-- meta: cle=valeur; cle=valeur -->
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REQUIRED_FILE_KEYS = {"doc_id", "title", "category", "attack_type", "surface", "label", "evidence_level",
                      "target_agent"}
AGENTS = {"interpretation", "correlation", "confirmation", "restitution"}
ALLOWED = {
    "category": {"attack_playbook", "false_positive", "scenario", "metrics_dictionary",
                 "normal_baseline", "decision_rules", "recommendations", "attack_variant"},
    "attack_type": {"ECLIPSE", "DOS_P2P", "BENIGN", "NORMAL", "GENERIC"},
    "label": {"attack", "benign", "normal", "neutral"},
    "evidence_level": {"theoretical", "illustrative", "simulated", "experimental"},
}
MIN_CHUNK_CHARS = 40
COLLECTION = "eva_guard_kb"

_FM = re.compile(r"\A---\n(.*?)\n---\n", re.S)
_META = re.compile(r"<!--\s*meta:\s*(.*?)\s*-->", re.S)
_HEAD = re.compile(r"^(#{2,3})\s+(.*)$")


@dataclass
class Chunk:
    id: str
    text: str
    metadata: dict


def parse_front_matter(text: str) -> tuple[dict, str]:
    m = _FM.match(text)
    if not m:
        raise ValueError("front matter absent")
    meta = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, text[m.end():]


_FENCE = re.compile(r"```.*?```", re.S)


def parse_meta_comment(block: str) -> tuple[dict, str]:
    """Extrait les commentaires meta HORS blocs de code (les gabarits en code restent du texte)."""
    meta = {}
    outside = _FENCE.sub("", block)
    for m in _META.finditer(outside):
        for part in m.group(1).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                meta[k.strip()] = v.strip()
    # on retire des commentaires uniquement ceux qui sont hors code
    pieces, last = [], 0
    for f in _FENCE.finditer(block):
        pieces.append(_META.sub("", block[last:f.start()]))
        pieces.append(f.group(0))
        last = f.end()
    pieces.append(_META.sub("", block[last:]))
    return meta, "".join(pieces)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:50]


def _sections(body: str):
    """Génère (h2, h3, texte) en respectant les blocs de code."""
    h2 = h3 = ""
    buf: list[str] = []
    in_code = False

    def flush():
        txt = "\n".join(buf).strip()
        buf.clear()
        return txt

    for line in body.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
        m = None if in_code else _HEAD.match(line)
        if m:
            txt = flush()
            if txt:
                yield h2, h3, txt
            if len(m.group(1)) == 2:
                h2, h3 = m.group(2).strip(), ""
            else:
                h3 = m.group(2).strip()
        else:
            buf.append(line)
    txt = flush()
    if txt:
        yield h2, h3, txt


def load_file_chunks(path: Path) -> list[Chunk]:
    fm, body = parse_front_matter(path.read_text(encoding="utf-8"))
    missing = REQUIRED_FILE_KEYS - fm.keys()
    if missing:
        raise ValueError(f"{path.name}: clés front matter manquantes {sorted(missing)}")
    chunks: list[Chunk] = []
    for i, (h2, h3, raw) in enumerate(_sections(body)):
        over, text = parse_meta_comment(raw)
        text = text.strip()
        if len(text) < MIN_CHUNK_CHARS:
            continue
        meta = {k: v for k, v in fm.items() if k != "title"}
        meta.update(over)
        # Chroma n'a pas de filtre « contient » sur les métadonnées : un drapeau booléen par agent
        for a in (x.strip() for x in meta["target_agent"].split(",")):
            meta[f"agent_{a}"] = True
        meta.update({"source": path.name, "heading": " > ".join(x for x in (h2, h3) if x)})
        ctx = " > ".join(x for x in (fm["title"], h2, h3) if x)
        cid = f"{fm['doc_id']}::{meta.get('scenario_id') or meta.get('metric') or _slug(h3 or h2)}::{i}"
        chunks.append(Chunk(id=cid, text=f"[{ctx}]\n{text}", metadata=meta))
    return chunks


def load_chunks(data_dir: str | Path) -> list[Chunk]:
    files = sorted(Path(data_dir).glob("[0-9][0-9]_*.md"))
    if not files:
        raise FileNotFoundError(f"aucun fichier NN_*.md dans {data_dir}")
    out: list[Chunk] = []
    for f in files:
        out.extend(load_file_chunks(f))
    return out


def build(data_dir, db_path, collection_name=COLLECTION, reset=False, ef=None):
    import chromadb
    from rag.embeddings import get_embedding_function

    ef = ef or get_embedding_function()
    client = chromadb.PersistentClient(path=str(db_path))
    if reset:
        try:
            client.delete_collection(collection_name)
        except Exception:
            pass
    col = client.get_or_create_collection(collection_name, embedding_function=ef,
                                          metadata={"hnsw:space": "cosine"})
    chunks = load_chunks(data_dir)
    col.upsert(ids=[c.id for c in chunks], documents=[c.text for c in chunks],
               metadatas=[c.metadata for c in chunks])
    return col


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--db", default="chroma_db")
    ap.add_argument("--collection", default=COLLECTION)
    ap.add_argument("--reset", action="store_true", help="supprime la collection avant ré-indexation")
    a = ap.parse_args(argv)
    col = build(a.data, a.db, a.collection, a.reset)
    print(f"{col.count()} chunks indexés dans '{a.collection}' ({a.db})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
