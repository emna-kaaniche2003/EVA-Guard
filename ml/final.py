#!/usr/bin/env python3
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"].copy()
d["t"] = (d.y_bin == "attack").astype(int)
# Eclipse est gérée par la règle, pas par le ML : on la retire du train du modèle DoS
d = d[d.y != "eclipse"]
d = d[~d.source_file.str.contains("eclipse")]

rng = np.random.default_rng(42)
normal = d[d.t == 0][feats].reset_index(drop=True)
dos = d[d.y == "dos_p2p"][feats].reset_index(drop=True)
rows = []
for _ in range(300):
    a = rng.uniform(0.05, 0.6)
    rows.append(normal.iloc[rng.integers(len(normal))] * (1 - a) + dos.iloc[rng.integers(len(dos))] * a)
syn = pd.DataFrame(rows, columns=feats); syn["t"] = 1
tr = pd.concat([d[feats + ["t"]], syn], ignore_index=True)

rf = RandomForestClassifier(n_estimators=300, max_depth=8, class_weight="balanced", random_state=42)
rf.fit(tr[feats], tr.t)
joblib.dump(rf, "ml/models/rf_dos_final.joblib")
joblib.dump(feats, "ml/models/features_final.joblib")
print("Modèle final sauvegardé :", len(tr), "lignes dont", len(syn), "synthétiques")
