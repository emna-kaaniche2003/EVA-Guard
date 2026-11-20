#!/usr/bin/env python3
import pandas as pd, joblib, numpy as np
from sklearn.metrics import classification_report, confusion_matrix

features = joblib.load("ml/models/features_used.joblib")
test = pd.read_csv("ml/data/test.csv", parse_dates=["timestamp"])
X = test[features]
y = (test["y_bin"] == "attack").astype(int)

preds = {
    "rf":  joblib.load("ml/models/rf_bin.joblib").predict(X),
    "xgb": joblib.load("ml/models/xgb_bin.joblib").predict(X),
    "iso": (joblib.load("ml/models/iso_bin.joblib").predict(X) == -1).astype(int),
}

for name, p in preds.items():
    print(f"\n===== {name} =====")
    print(classification_report(y, p, target_names=["normal", "attack"], digits=3))
    print("Matrice de confusion :\n", confusion_matrix(y, p))
    test[f"pred_{name}"] = p

    # Recall par run d'attaque + faux positifs par run normal
    print("Par fichier :")
    for f, g in test.groupby("source_file"):
        if g["y_bin"].eq("attack").any():
            rec = g.loc[g.y_bin == "attack", f"pred_{name}"].mean()
            print(f"  {f}: recall attaque = {rec:.2f}")
        else:
            print(f"  {f}: taux de faux positifs = {g[f'pred_{name}'].mean():.3f}")

# --- Temps de détection (échantillonnage = 5 s) ---
print("\n===== Temps de détection =====")
for name in preds:
    for f, g in test.groupby("source_file"):
        g = g.sort_values("timestamp")
        act = g[g["attack_active"] == 1]
        if act.empty:
            continue
        t0 = act["timestamp"].iloc[0]
        hit = g[(g["timestamp"] >= t0) & (g[f"pred_{name}"] == 1)]
        if hit.empty:
            print(f"{name} | {f}: attaque jamais détectée")
        else:
            print(f"{name} | {f}: détectée après {(hit['timestamp'].iloc[0]-t0).total_seconds():.0f} s")

test.to_csv("ml/data/test_predictions.csv", index=False)
