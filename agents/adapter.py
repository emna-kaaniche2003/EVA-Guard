"""Adaptateur Détection -> Interprétation.

Transforme la sortie de detector.detect_one() (hypothese, score, methode, mesures) en MLAlert
pour l'agent d'interprétation. Placer dans agents/adapter.py.

Usage (depuis la racine du projet) :
    # 1) une seule fois : baseline normale à partir d'un CSV de données normales
    python -m agents.adapter --build-baseline data_ml/normal.csv
    # 2) test sur les exemples de détection
    python -m agents.adapter chemin/exemples_detection.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from rag.interpreter import InterpretationAgent, MLAlert, load_collection

BASELINE_PATH = Path("ml/models/baseline.json")

# Colonnes de l'expérimentation qui révèlent la vérité terrain : NE JAMAIS les donner au LLM
# (sinon l'évaluation est truquée : le LLM lirait "attack_name": "dos_p2p").
LEAKY_KEYS = {"label", "attack_name", "attack_intensity", "attack_active",
              "traffic_profile", "traffic_mult", "timestamp"}

LABEL_MAP = {"dos_p2p": "DOS_P2P", "eclipse": "ECLIPSE"}   # "normal" => pas d'alerte


def build_baseline(csv_path: str, out: Path = BASELINE_PATH) -> dict:
    """Médiane de chaque métrique sur les lignes normales."""
    import pandas as pd
    df = pd.read_csv(csv_path, encoding="utf-8-sig")
    df.columns = [c.strip() for c in df.columns]
    if "label" in df.columns:
        df = df[df["label"].astype(str).str.startswith("normal")]
    num = df.select_dtypes("number").drop(columns=[c for c in LEAKY_KEYS if c in df.columns], errors="ignore")
    base = {k: float(v) for k, v in num.median().dropna().items()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(base, indent=2), encoding="utf-8")
    print(f"baseline écrite : {out} ({len(base)} métriques, {len(df)} lignes normales)")
    return base


def load_baseline(path: Path = BASELINE_PATH) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    print(f"[avertissement] {path} absent : l'interprétation se fera sans baseline.", file=sys.stderr)
    return {}


def detection_to_alert(det: dict, baseline: dict | None = None, node_id: str = "node-1") -> MLAlert | None:
    """Sortie de detect_one -> MLAlert. Retourne None si 'normal' (aucun appel LLM)."""
    hyp = det.get("hypothese")
    if hyp not in LABEL_MAP:
        return None
    score = float(det.get("score") or 0.0)
    if hyp == "eclipse":
        probs = {"ECLIPSE": score, "DOS_P2P": 0.0, "BENIGN": 0.0}
    else:
        probs = {"DOS_P2P": score, "ECLIPSE": 0.0, "BENIGN": round(1 - score, 3)}
    feats = {k: float(v) for k, v in det.get("mesures", {}).items()
             if k not in LEAKY_KEYS and isinstance(v, (int, float)) and not isinstance(v, bool) and v == v}
    return MLAlert(predicted_attack=LABEL_MAP[hyp], anomaly_score=score, probabilities=probs,
                   features=feats, baseline=baseline or {},
                   timestamp=str(det.get("timestamp") or ""), node_id=node_id,
                   method=str(det.get("methode") or ""))


def interpret_detection(agent: InterpretationAgent, det: dict, baseline: dict | None = None) -> dict | None:
    alert = detection_to_alert(det, baseline)
    return agent.interpret(alert) if alert else None


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--build-baseline":
        build_baseline(sys.argv[2]); sys.exit(0)
    samples = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    base, agent = load_baseline(), InterpretationAgent(load_collection())
    for det in samples:
        print(f"\n=== {det['timestamp']} | détecteur : {det['hypothese']} ({det['methode']}, score {det['score']})")
        res = interpret_detection(agent, det, base)
        print("aucune alerte (normal), pas d'appel LLM" if res is None
              else json.dumps(res["interpretation"], indent=2, ensure_ascii=False))
