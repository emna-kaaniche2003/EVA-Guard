"""Récupération RAG sans renforcement du biais du ML.

Pour chaque anomalie, on récupère TOUJOURS :
  - open     : recherche sémantique non filtrée ;
  - support  : signature de l'hypothèse prédite par le ML (pour l'évaluer explicitement) ;
  - counter  : scénarios/playbooks d'un AUTRE type que celui prédit par le ML ;
  - benign   : faux positifs et comportement normal ;
  - rules    : règles de décision ;
  - metrics  : définitions des métriques citées (lookup exact par nom).
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass

from rag.ingest import COLLECTION

METRIC_RE = re.compile(r"\b((?:p2p|host|api)_[a-z0-9]+(?:_[a-z0-9]+)*)\b")


@dataclass
class Hit:
    id: str
    text: str
    metadata: dict
    distance: float | None
    role: str


def _query(col, text, k, where=None, role="open"):
    kwargs = {"query_texts": [text], "n_results": k}
    if where:
        kwargs["where"] = where
    r = col.query(**kwargs)
    return [Hit(i, d, m, dist, role) for i, d, m, dist in
            zip(r["ids"][0], r["documents"][0], r["metadatas"][0], r["distances"][0])]


def _and(where, extra):
    if not extra:
        return where
    return extra if not where else {"$and": [where, extra]}


def extract_metrics(text: str) -> list[str]:
    return sorted(set(METRIC_RE.findall(text)))


def retrieve(col, query: str, predicted_attack: str | None = None, metrics: list[str] | None = None,
             k_open=4, k_support=3, k_counter=3, k_benign=3, k_rules=2, agent: str | None = None) -> dict[str, list[Hit]]:
    ag = {f"agent_{agent}": True} if agent else None
    results: dict[str, list[Hit]] = {}
    seen: set[str] = set()

    def add(role, hits):
        kept = [h for h in hits if h.id not in seen]
        seen.update(h.id for h in kept)
        results[role] = kept

    add("open", _query(col, query, k_open, ag, "open"))

    if predicted_attack and predicted_attack != "BENIGN":
        # Hypothèse du ML : on récupère sa signature pour l'évaluer, SANS que ce soit le seul angle
        support_where = {"$and": [
            {"category": {"$in": ["scenario", "attack_playbook"]}},
            {"attack_type": predicted_attack},
        ]}
        add("support", _query(col, query, k_support, _and(support_where, ag), "support"))

    if predicted_attack:
        counter_where = {"$and": [
            {"category": {"$in": ["scenario", "attack_playbook"]}},
            {"attack_type": {"$nin": [predicted_attack, "GENERIC"]}},
        ]}
        add("counter", _query(col, query, k_counter, _and(counter_where, ag), "counter"))

    add("benign", _query(col, query, k_benign,
                         _and({"category": {"$in": ["false_positive", "normal_baseline"]}}, ag), "benign"))
    add("rules", _query(col, query, k_rules, _and({"category": "decision_rules"}, ag), "rules"))

    names = metrics if metrics is not None else extract_metrics(query)
    if names:
        got = col.get(where={"metric": {"$in": names}})
        add("metrics", [Hit(i, d, m, None, "metrics")
                        for i, d, m in zip(got["ids"], got["documents"], got["metadatas"])])
    return results


def format_context(results: dict[str, list[Hit]]) -> str:
    titles = {"open": "PREUVES PERTINENTES", "support": "SIGNATURE DE L'HYPOTHÈSE PRÉDITE PAR LE ML (à évaluer, pas à présumer)", "counter": "HYPOTHÈSES ALTERNATIVES (autre type d'attaque)",
              "benign": "DIAGNOSTICS BÉNINS / COMPORTEMENT NORMAL", "rules": "RÈGLES DE DÉCISION",
              "metrics": "DÉFINITIONS DES MÉTRIQUES"}
    parts = []
    for role in ("open", "support", "counter", "benign", "rules", "metrics"):
        for h in results.get(role, []):
            m = h.metadata
            tag = f"{m.get('source')} | {m.get('category')} | {m.get('attack_type')} | niveau={m.get('evidence_level')}"
            if m.get("scenario_id"):
                tag += f" | id={m['scenario_id']}"
            parts.append(f"### {titles[role]} — {tag}\n{h.text}")
    return "\n\n".join(parts)


def main(argv=None):
    import chromadb
    from rag.embeddings import get_embedding_function

    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--predicted", default=None, choices=["ECLIPSE", "DOS_P2P", "BENIGN"])
    ap.add_argument("--db", default="chroma_db")
    ap.add_argument("--collection", default=COLLECTION)
    a = ap.parse_args(argv)
    col = chromadb.PersistentClient(path=a.db).get_collection(a.collection,
                                                              embedding_function=get_embedding_function())
    print(format_context(retrieve(col, a.query, a.predicted)))


if __name__ == "__main__":
    main()
