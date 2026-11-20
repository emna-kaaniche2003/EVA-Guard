#!/usr/bin/env python3
import pandas as pd
import numpy as np

df = pd.read_csv("ml/data/all_raw.csv")
n0 = len(df)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values(["source_file", "timestamp"]).reset_index(drop=True)

# --- 1. Doublons exacts ---
df = df.drop_duplicates()

# --- 2. Débits P2P négatifs (reset de compteur Prometheus) -> manquant ---
neg_mask = (df["p2p_in_kbps"] < 0) | (df["p2p_out_kbps"] < 0)
print("Débits négatifs trouvés :", neg_mask.sum())
df.loc[neg_mask, ["p2p_in_kbps", "p2p_out_kbps"]] = np.nan

# --- 3. Détecter les lignes où le nœud est hors service (redémarrage) ---
# Signature vue dans eclipse_test : p2p_n_peers=0 ET api_ok_ratio=0 (ou NaN)
df["node_down"] = (
    (df["p2p_n_peers"] == 0) &
    ((df["api_ok_ratio"].fillna(0) == 0))
).astype(int)
print("Lignes 'node_down' (nœud hors service) :", df["node_down"].sum())

# --- 4. Saturation de l'hôte (bruit machine, pas réseau) ---
df["host_overload"] = (df["host_cpu_sys"] >= 95).astype(int)
print("Lignes host_overload :", df["host_overload"].sum())

# --- 5. Première ligne de chaque run (churn/joined faussés à l'amorçage) ---
df = df.groupby("source_file", group_keys=False).apply(lambda g: g.iloc[1:], include_groups=False)
print(f"Après suppression 1re ligne/run : {len(df)} lignes")

# --- 6. Valeurs manquantes numériques : imputation par médiane du run ---
num_cols = df.select_dtypes("number").columns.tolist()
for c in ["node_down", "host_overload"]:
    if c in num_cols: num_cols.remove(c)
df[num_cols] = df.groupby("source_file")[num_cols].transform(
    lambda s: s.fillna(s.median()))
df[num_cols] = df[num_cols].fillna(0)

# --- 7. Colonnes de contexte texte vides -> valeur explicite "none" ---
for c in ["traffic_profile", "attack_name", "attack_intensity"]:
    if c in df.columns:
        df[c] = df[c].fillna("none").replace("", "none")

# --- 8. api_is_syncing / api_block manquants pendant node_down -> -1 (valeur sentinelle) ---
for c in ["api_block", "api_is_syncing"]:
    if c in df.columns:
        df[c] = df[c].fillna(-1)

print(f"\n{n0} -> {len(df)} lignes après nettoyage")
df.to_csv("ml/data/all_clean.csv", index=False)
