"""Agent d'interprétation EVA-Guard : ML -> RAG -> LLM (Groq) -> hypothèse structurée (JSON).

Le LLM NE confirme PAS l'attaque : il propose une hypothèse, l'explique, et liste les
preuves que l'agent de corrélation/confirmation devra vérifier.

Placer ce fichier dans rag/interpreter.py
    pip install groq chromadb sentence-transformers
    export GROQ_API_KEY="gsk_..."
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict

from groq import Groq

from rag.embeddings import get_embedding_function
from rag.ingest import COLLECTION
from rag.retriever import retrieve, format_context

GROQ_MODEL = os.environ.get("EVA_LLM_MODEL", "llama-3.3-70b-versatile")
HYPOTHESES = {"ECLIPSE", "DOS_P2P", "BENIGN", "UNKNOWN"}
MAX_CONTEXT_CHARS = 9000   # évite de dépasser la fenêtre / les limites de tokens Groq
TOP_FEATURES = 8           # nb de features les plus "déviantes" injectées dans le prompt


# ----------------------------------------------------------------------------------
# 1) Entrée / sortie
# ----------------------------------------------------------------------------------
@dataclass
class MLAlert:
    """Ce que l'agent de détection (ML) transmet à l'agent d'interprétation."""
    predicted_attack: str                       # "ECLIPSE" | "DOS_P2P" | "BENIGN"
    anomaly_score: float                        # score IsolationForest ou proba XGB/RF
    probabilities: dict[str, float] = field(default_factory=dict)   # ex {"ECLIPSE":0.1,"DOS_P2P":0.8,"BENIGN":0.1}
    features: dict[str, float] = field(default_factory=dict)        # valeurs courantes (p2p_*, host_*, api_*)
    baseline: dict[str, float] = field(default_factory=dict)        # moyenne "normale" (optionnel mais recommandé)
    timestamp: str = ""
    node_id: str = "node-1"


@dataclass
class Interpretation:
    hypothesis: str                  # ECLIPSE | DOS_P2P | BENIGN | UNKNOWN
    confidence: float                # 0..1 (confiance du LLM dans son hypothèse, PAS une confirmation)
    agrees_with_ml: bool
    reasoning: str
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    alternatives: list[str]
    evidence_to_verify: list[dict]   # [{"metric":..., "condition":..., "source":"p2p|system|rpc"}]
    sources_used: list[str]


# ----------------------------------------------------------------------------------
# 2) Construction de la requête RAG et du résumé des features
# ----------------------------------------------------------------------------------
def top_deviating_features(alert: MLAlert, n: int = TOP_FEATURES) -> list[tuple[str, float, float | None]]:
    """Retourne les n features les plus écartées de la baseline (écart relatif)."""
    rows = []
    for k, v in alert.features.items():
        b = alert.baseline.get(k)
        if b is not None and abs(b) > 1e-9:
            dev = abs(v - b) / abs(b)
        else:
            dev = abs(v)  # pas de baseline : on trie par amplitude
        rows.append((k, v, b, dev))
    rows.sort(key=lambda r: r[3], reverse=True)
    return [(k, v, b) for k, v, b, _ in rows[:n]]


def features_summary(alert: MLAlert) -> str:
    lines = []
    for k, v, b in top_deviating_features(alert):
        lines.append(f"- {k} = {v:.4g}" + (f" (baseline normale ≈ {b:.4g})" if b is not None else ""))
    return "\n".join(lines) or "- (aucune feature fournie)"


def build_query(alert: MLAlert) -> tuple[str, list[str]]:
    """Requête sémantique + noms de métriques pour le lookup exact dans la KB."""
    top = top_deviating_features(alert)
    names = [k for k, _, _ in top]
    q = (f"Anomalie sur un noeud Ethereum. Prédiction ML : {alert.predicted_attack}. "
         f"Métriques anormales : {', '.join(names)}. "
         + " ".join(f"{k}={v:.3g}" for k, v, _ in top))
    return q, names


# ----------------------------------------------------------------------------------
# 3) Prompt
# ----------------------------------------------------------------------------------
SYSTEM_PROMPT = """Tu es l'agent d'INTERPRÉTATION du système EVA-Guard (sécurité des noeuds Ethereum).

Rôle : à partir d'une alerte ML et d'extraits d'une base de connaissances (RAG), formuler une HYPOTHÈSE
d'attaque et l'expliquer. Tu ne confirmes jamais une attaque : la confirmation est faite plus tard
par un autre agent à partir de preuves observables indépendantes.

Règles strictes :
1. La prédiction du ML est une hypothèse à ÉVALUER, pas une vérité. Compare-la aux alternatives
   (autre type d'attaque, faux positif bénin) présentes dans le contexte.
2. Appuie-toi UNIQUEMENT sur les valeurs fournies et sur le contexte RAG. N'invente aucune métrique,
   aucune valeur, aucun seuil. Si le contexte est insuffisant, réponds "UNKNOWN".
3. Les types possibles sont : ECLIPSE (isolement/pairs/churn/retard de sync), DOS_P2P (flooding P2P :
   débit, CPU, mémoire, latence, erreurs), BENIGN (faux positif / comportement normal), UNKNOWN.
4. Dans "evidence_to_verify", liste les preuves INDÉPENDANTES à vérifier (réseau, système, RPC) qui
   confirmeraient ou infirmeraient ton hypothèse. Utilise des noms de métriques existants.
5. Réponds UNIQUEMENT avec un objet JSON valide, en français, sans texte autour, au format :
{
  "hypothesis": "ECLIPSE|DOS_P2P|BENIGN|UNKNOWN",
  "confidence": 0.0-1.0,
  "agrees_with_ml": true|false,
  "reasoning": "explication concise (5-8 phrases max)",
  "supporting_evidence": ["..."],
  "contradicting_evidence": ["..."],
  "alternatives": ["autres hypothèses plausibles et pourquoi"],
  "evidence_to_verify": [{"metric": "nom", "condition": "ex: > 3x baseline", "source": "p2p|system|rpc"}],
  "sources_used": ["fichier.md | section"]
}"""


def build_user_prompt(alert: MLAlert, context: str) -> str:
    probs = ", ".join(f"{k}={v:.2f}" for k, v in alert.probabilities.items()) or "n/a"
    return f"""ALERTE ML
- noeud : {alert.node_id} | horodatage : {alert.timestamp or 'n/a'}
- prédiction ML : {alert.predicted_attack}
- score d'anomalie : {alert.anomaly_score:.3f}
- probabilités : {probs}

MÉTRIQUES LES PLUS ÉCARTÉES
{features_summary(alert)}

CONTEXTE RAG
{context[:MAX_CONTEXT_CHARS]}

Formule ton interprétation (JSON uniquement)."""


# ----------------------------------------------------------------------------------
# 4) Agent
# ----------------------------------------------------------------------------------
class InterpretationAgent:
    def __init__(self, collection, client: Groq | None = None, model: str = GROQ_MODEL):
        self.col = collection
        self.client = client or Groq(api_key=os.environ["GROQ_API_KEY"])
        self.model = model

    # -- appel LLM avec 1 retry si JSON invalide
    def _call_llm(self, user_prompt: str, retries: int = 1) -> dict:
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}]
        last_err = None
        for _ in range(retries + 1):
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0.1, max_tokens=4000,
                response_format={"type": "json_object"})
            raw = resp.choices[0].message.content
            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                last_err = e
                messages += [{"role": "assistant", "content": raw},
                             {"role": "user", "content": "JSON invalide. Renvoie uniquement l'objet JSON demandé."}]
        raise ValueError(f"Sortie LLM non JSON : {last_err}")

    @staticmethod
    def _validate(d: dict) -> Interpretation:
        hyp = str(d.get("hypothesis", "UNKNOWN")).upper()
        if hyp not in HYPOTHESES:
            hyp = "UNKNOWN"
        try:
            conf = min(1.0, max(0.0, float(d.get("confidence", 0.0))))
        except (TypeError, ValueError):
            conf = 0.0
        return Interpretation(
            hypothesis=hyp, confidence=conf,
            agrees_with_ml=bool(d.get("agrees_with_ml", False)),
            reasoning=str(d.get("reasoning", "")),
            supporting_evidence=list(d.get("supporting_evidence", [])),
            contradicting_evidence=list(d.get("contradicting_evidence", [])),
            alternatives=list(d.get("alternatives", [])),
            evidence_to_verify=[e for e in d.get("evidence_to_verify", []) if isinstance(e, dict) and e.get("metric")],
            sources_used=list(d.get("sources_used", [])),
        )

    def interpret(self, alert: MLAlert) -> dict:
        query, metric_names = build_query(alert)
        hits = retrieve(self.col, query, predicted_attack=alert.predicted_attack,
                        metrics=metric_names, agent="interpretation")
        context = format_context(hits)
        out = self._validate(self._call_llm(build_user_prompt(alert, context)))
        return {"interpretation": asdict(out),
                "rag_hits": {r: [h.id for h in hs] for r, hs in hits.items()}}   # traçabilité / explicabilité


# ----------------------------------------------------------------------------------
# 5) Test rapide : python -m rag.interpreter
# ----------------------------------------------------------------------------------
def load_collection(db_path: str = "chroma_db"):
    import chromadb
    return chromadb.PersistentClient(path=db_path).get_collection(
        COLLECTION, embedding_function=get_embedding_function())


if __name__ == "__main__":
    agent = InterpretationAgent(load_collection())
    demo = MLAlert(
        predicted_attack="DOS_P2P", anomaly_score=0.91,
        probabilities={"ECLIPSE": 0.05, "DOS_P2P": 0.90, "BENIGN": 0.05},
        features={"p2p_msg_rate": 5200, "host_cpu_pct": 94, "host_mem_pct": 81, "p2p_peer_count": 48},
        baseline={"p2p_msg_rate": 400, "host_cpu_pct": 30, "host_mem_pct": 45, "p2p_peer_count": 50},
        timestamp="2026-11-20T10:32:00Z")
    print(json.dumps(agent.interpret(demo), indent=2, ensure_ascii=False))
