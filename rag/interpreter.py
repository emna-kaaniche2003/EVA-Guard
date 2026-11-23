"""Agent d'interprétation EVA-Guard (v2) : détecteur -> RAG -> LLM (Groq) -> hypothèse structurée (JSON).

Le LLM NE confirme PAS l'attaque : il propose une hypothèse, l'explique, et liste les
preuves que l'agent de corrélation/confirmation devra vérifier.

Copier ce fichier vers rag/interpreter.py (remplace la v1).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict

from groq import Groq

from rag.embeddings import get_embedding_function
from rag.ingest import COLLECTION
from rag.retriever import retrieve, format_context

GROQ_MODEL = os.environ.get("EVA_LLM_MODEL", "openai/gpt-oss-120b")
HYPOTHESES = {"ECLIPSE", "DOS_P2P", "BENIGN", "UNKNOWN"}
MAX_CONTEXT_CHARS = 9000
TOP_FEATURES = 8           # utilisé uniquement pour construire la requête RAG
DEVIATION_FLAG = 0.5       # écart relatif à la baseline au-delà duquel une métrique est marquée ⚠
MAX_TOKENS = 4000          # les modèles à raisonnement consomment des tokens avant de répondre


# ----------------------------------------------------------------------------------
# 1) Entrée / sortie
# ----------------------------------------------------------------------------------
@dataclass
class MLAlert:
    """Ce que l'agent de détection transmet à l'agent d'interprétation."""
    predicted_attack: str                       # "ECLIPSE" | "DOS_P2P" | "BENIGN"
    anomaly_score: float
    probabilities: dict[str, float] = field(default_factory=dict)
    features: dict[str, float] = field(default_factory=dict)        # p2p_*, host_*, api_*
    baseline: dict[str, float] = field(default_factory=dict)
    timestamp: str = ""
    node_id: str = "node-1"
    method: str = ""                            # random_forest | regle_p2p_all_inbound


@dataclass
class Interpretation:
    hypothesis: str
    confidence: float
    agrees_with_ml: bool
    reasoning: str
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    alternatives: list[str]
    evidence_to_verify: list[dict]
    sources_used: list[str]          # rempli par le code à partir du RAG, jamais par le LLM


# ----------------------------------------------------------------------------------
# 2) Requête RAG et résumé des métriques
# ----------------------------------------------------------------------------------
def _deviation(v: float, b: float | None) -> float:
    if b is None:
        return 0.0
    return abs(v - b) / max(abs(b), 1.0)


def top_deviating_features(alert: MLAlert, n: int = TOP_FEATURES) -> list[tuple[str, float, float | None]]:
    rows = [(k, v, alert.baseline.get(k), _deviation(v, alert.baseline.get(k)) if k in alert.baseline else abs(v))
            for k, v in alert.features.items()]
    rows.sort(key=lambda r: r[3], reverse=True)
    return [(k, v, b) for k, v, b, _ in rows[:n]]


def features_summary(alert: MLAlert) -> str:
    """TOUTES les métriques, groupées par source, avec baseline ; ⚠ marque les écarts notables."""
    groups = {"p2p_": "RÉSEAU P2P", "host_": "SYSTÈME", "api_": "RPC"}
    out = []
    for prefix, title in groups.items():
        lines = []
        for k in sorted(alert.features):
            if not k.startswith(prefix):
                continue
            v, b = alert.features[k], alert.baseline.get(k)
            flag = " ⚠" if b is not None and _deviation(v, b) >= DEVIATION_FLAG else ""
            ratio = f", x{v / b:.1f}" if b not in (None, 0) else ""
            lines.append(f"- {k} = {v:.4g}" + (f" (baseline {b:.4g}{ratio})" if b is not None else "") + flag)
        if lines:
            out.append(f"[{title}]\n" + "\n".join(lines))
    return "\n".join(out) or "(aucune métrique fournie)"


def build_query(alert: MLAlert) -> tuple[str, list[str]]:
    top = top_deviating_features(alert)
    names = [k for k, _, _ in top]
    q = (f"Anomalie sur un noeud Ethereum. Prédiction du détecteur : {alert.predicted_attack}. "
         f"Métriques anormales : {', '.join(names)}. "
         + " ".join(f"{k}={v:.3g}" for k, v, _ in top))
    return q, names


# ----------------------------------------------------------------------------------
# 3) Prompt
# ----------------------------------------------------------------------------------
SYSTEM_PROMPT = """Tu es l'agent d'INTERPRÉTATION du système EVA-Guard (sécurité des noeuds Ethereum).

Rôle : à partir d'une alerte du détecteur et d'extraits d'une base de connaissances (RAG), formuler une
HYPOTHÈSE d'attaque et l'expliquer. Tu ne confirmes jamais une attaque : la confirmation est faite plus tard
par un autre agent à partir de preuves observables indépendantes.

Règles strictes :
1. La prédiction du détecteur est une hypothèse à ÉVALUER, pas une vérité. Compare-la aux alternatives
   (autre type d'attaque, faux positif bénin) présentes dans le contexte.
2. Appuie-toi UNIQUEMENT sur les métriques fournies et sur le contexte RAG. N'invente aucune métrique,
   valeur, seuil ou événement. Toutes les métriques disponibles te sont fournies : ne dis jamais qu'une
   métrique listée est « non disponible ». Cite les valeurs avec leur baseline.
3. Types possibles : ECLIPSE (isolement/pairs/churn/retard de sync), DOS_P2P (flooding P2P),
   BENIGN (faux positif / comportement normal), UNKNOWN si le contexte est insuffisant.
4. La méthode du détecteur t'est donnée. Ne la devine pas. Si c'est une règle heuristique
   (regle_p2p_all_inbound), c'est un simple indice qui peut produire des faux positifs.
5. Les seuils de la KB sont indicatifs (niveau de preuve « theoretical »/« illustrative ») : le noeud observé
   peut s'en écarter. Si tu contredis un détecteur très confiant (score > 0.9), justifie-le par des métriques
   précises ET indique dans evidence_to_verify ce qui trancherait entre ta thèse et la sienne.
5b. Quand une fiche de niveau « experimental » (mesurée sur le banc) contredit une fiche « theoretical »,
   la fiche expérimentale prévaut pour ce noeud.
6. Les valeurs proviennent d'UN SEUL échantillon : ne conclus pas sur une tendance. evidence_to_verify doit
   lister les preuves indépendantes à contrôler sur une FENÊTRE de temps (persistance, tendance, concomitance
   entre surfaces), avec des conditions relatives à la baseline (ex : « > 3x baseline sur >= 3 intervalles »),
   en utilisant uniquement des noms de métriques existants.
7. Réponds UNIQUEMENT avec un objet JSON valide, en français, sans texte autour :
{
  "hypothesis": "ECLIPSE|DOS_P2P|BENIGN|UNKNOWN",
  "confidence": 0.0-1.0,
  "agrees_with_ml": true|false,
  "reasoning": "explication concise (5-8 phrases max), cohérente avec les listes ci-dessous",
  "supporting_evidence": ["métrique = valeur (baseline x) : pourquoi elle soutient l'hypothèse"],
  "contradicting_evidence": ["métrique = valeur (baseline x) : pourquoi elle la contredit"],
  "alternatives": ["autres hypothèses plausibles et pourquoi"],
  "evidence_to_verify": [{"metric": "nom", "condition": "ex: > 3x baseline sur >= 3 intervalles", "source": "p2p|system|rpc"}]
}"""


def build_user_prompt(alert: MLAlert, context: str) -> str:
    probs = ", ".join(f"{k}={v:.2f}" for k, v in alert.probabilities.items()) or "n/a"
    return f"""ALERTE DU DÉTECTEUR
- noeud : {alert.node_id} | horodatage : {alert.timestamp or 'n/a'}
- prédiction : {alert.predicted_attack} | méthode : {alert.method or 'n/a'}
- score : {alert.anomaly_score:.3f} | probabilités : {probs}

MÉTRIQUES OBSERVÉES (⚠ = écart notable à la baseline normale)
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

    def _call_llm(self, user_prompt: str, retries: int = 1) -> dict:
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}]
        last_err = None
        for _ in range(retries + 1):
            resp = self.client.chat.completions.create(
                model=self.model, messages=messages, temperature=0.1, max_tokens=MAX_TOKENS,
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
    def _validate(d: dict, sources: list[str]) -> Interpretation:
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
            sources_used=sources,
        )

    def interpret(self, alert: MLAlert) -> dict:
        query, metric_names = build_query(alert)
        hits = retrieve(self.col, query, predicted_attack=alert.predicted_attack,
                        metrics=metric_names, agent="interpretation")
        context = format_context(hits)
        # sources = ce qui a réellement été récupéré (le LLM ne peut pas inventer d'identifiant)
        sources = []
        for role in ("open", "support", "counter", "benign", "rules", "metrics"):
            for h in hits.get(role, []):
                m = h.metadata
                label = m.get("scenario_id") or m.get("metric") or m.get("heading", "")
                sources.append(f"{role}: {m.get('source')} | {label}")
        out = self._validate(self._call_llm(build_user_prompt(alert, context)), sources)
        # on ne garde que des métriques réellement présentes dans l'échantillon (pas d'invention du LLM)
        out.evidence_to_verify = [e for e in out.evidence_to_verify if e["metric"] in alert.features]
        return {"interpretation": asdict(out),
                "rag_hits": {r: [h.id for h in hs] for r, hs in hits.items()}}


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
        predicted_attack="DOS_P2P", anomaly_score=0.91, method="random_forest",
        probabilities={"ECLIPSE": 0.05, "DOS_P2P": 0.90, "BENIGN": 0.05},
        features={"p2p_in_kbps": 5200, "host_cpu_geth": 94, "host_rss_geth_mb": 810, "p2p_n_peers": 48},
        baseline={"p2p_in_kbps": 400, "host_cpu_geth": 30, "host_rss_geth_mb": 300, "p2p_n_peers": 50},
        timestamp="2026-11-20T10:32:00Z")
    print(json.dumps(agent.interpret(demo), indent=2, ensure_ascii=False))
