"""Évalue l'interprétation sur des échantillons étiquetés des CSV du banc.

Compare, pour chaque échantillon : vérité terrain / détecteur seul / détecteur + LLM-RAG.
Placer dans ml/evaluation/eval_interpreter.py, lancer depuis la racine du projet :
    PYTHONPATH=. python ml/evaluation/eval_interpreter.py --n 8
Sortie : matrices de confusion + ml/evaluation/interp_eval.csv (une ligne par échantillon).
"""
import argparse
import glob
import time

import pandas as pd

try:
    from agents.detector import detect_one
except ImportError:
    from ml.detector import detect_one
from agents.adapter import detection_to_alert, load_baseline
from rag.interpreter import InterpretationAgent, load_collection

LLM_TO_FINAL = {"DOS_P2P": "dos_p2p", "ECLIPSE": "eclipse", "BENIGN": "normal", "UNKNOWN": "normal"}


def truth_of(row) -> str:
    label = str(row["label"])
    if label.startswith("normal") or row.get("attack_active", 1) == 0:
        return "normal"
    return "dos_p2p" if label.startswith("dos") else "eclipse" if label.startswith("eclipse") else "normal"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=8, help="échantillons par classe")
    ap.add_argument("--data", default="data/raw/*.csv")
    ap.add_argument("--sleep", type=float, default=2.0, help="pause entre appels LLM (limites Groq)")
    a = ap.parse_args()

    df = pd.concat([pd.read_csv(f, encoding="utf-8-sig") for f in glob.glob(a.data)], ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    df["truth"] = df.apply(truth_of, axis=1)
    sample = pd.concat([g.sample(min(a.n, len(g)), random_state=0) for _, g in df.groupby("truth")])

    baseline, agent = load_baseline(), InterpretationAgent(load_collection())
    rows = []
    for _, r in sample.iterrows():
        det = detect_one(r.to_dict())
        alert = detection_to_alert(det, baseline)
        if alert is None:
            llm, conf = "normal", None            # pas d'alerte : pas d'appel LLM
        else:
            try:
                it = agent.interpret(alert)["interpretation"]
                llm, conf = LLM_TO_FINAL[it["hypothesis"]], it["confidence"]
            except Exception as e:                # limite de débit, JSON invalide...
                print("erreur LLM :", e)
                llm, conf = "erreur", None
            time.sleep(a.sleep)
        rows.append({"timestamp": r.get("timestamp"), "truth": r["truth"], "detector": det["hypothese"],
                     "detector_score": det["score"], "llm_final": llm, "llm_confidence": conf})
        print(f"{r['truth']:8} | détecteur {det['hypothese']:8} | + LLM {llm:8} | conf {conf}")

    out = pd.DataFrame(rows)
    out.to_csv("ml/evaluation/interp_eval.csv", index=False)
    print("\n== Détecteur seul ==")
    print(pd.crosstab(out["truth"], out["detector"]))
    print("\n== Détecteur + LLM/RAG ==")
    print(pd.crosstab(out["truth"], out["llm_final"]))
    for name in ("detector", "llm_final"):
        print(f"exactitude {name} : {(out['truth'] == out[name]).mean():.2%}")


if __name__ == "__main__":
    main()
