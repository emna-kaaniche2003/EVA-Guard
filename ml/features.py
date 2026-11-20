#!/usr/bin/env python3
import pandas as pd
df = pd.read_csv("ml/data/all_target.csv")

# Signature Eclipse : tous les pairs sont entrants
df["p2p_all_inbound"] = ((df["p2p_n_outbound"] == 0) & (df["p2p_n_peers"] > 0)).astype(int)

# Lissage du bruit RPC (moyenne glissante sur 5 échantillons, par run)
for c in ["api_lat_blocknumber_ms", "api_lat_peers_ms"]:
    df[c + "_avg5"] = df.groupby("source_file")[c].transform(
        lambda s: s.rolling(5, min_periods=1).mean())

# Colonnes de contexte à exclure du modèle (vérité terrain / identifiants, pas des mesures)
CONTEXT = ["timestamp", "label", "source_file", "traffic_profile", "traffic_mult",
           "attack_name", "attack_intensity", "attack_active", "node_down", "y"]
FEATURES = [c for c in df.columns if c not in CONTEXT and df[c].dtype != object]

print(f"{len(FEATURES)} features :", FEATURES)
df.to_csv("ml/data/all_features.csv", index=False)
with open("ml/data/feature_list.txt", "w") as f:
    f.write("\n".join(FEATURES))
