#!/usr/bin/env python3
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"].copy()
d["t"] = (d.y_bin == "attack").astype(int)
rng = np.random.default_rng(42)

def augment(tr, n=300):
    normal = tr[tr.t == 0][feats].reset_index(drop=True)
    dos = tr[tr.y == "dos_p2p"][feats].reset_index(drop=True)
    if len(dos) == 0:
        return tr
    rows = []
    for _ in range(n):
        a = rng.uniform(0.05, 0.6)   # 5 % à 60 % du chemin normal -> DoS
        r = normal.iloc[rng.integers(len(normal))] * (1 - a) + dos.iloc[rng.integers(len(dos))] * a
        rows.append(r)
    syn = pd.DataFrame(rows, columns=feats)
    syn["t"] = 1
    return pd.concat([tr[feats + ["t"]], syn], ignore_index=True)

for f in sorted(d.source_file.unique()):
    tr, te = d[d.source_file != f], d[d.source_file == f]
    tr_aug = augment(tr)                      # le fichier testé n'est jamais augmenté
    rf = RandomForestClassifier(n_estimators=300, max_depth=8,
                                class_weight="balanced", random_state=42).fit(tr_aug[feats], tr_aug.t)
    te = te.assign(p=rf.predict(te[feats]))
    a, n = te[te.t == 1], te[te.t == 0]
    rec = f"{a.p.mean():.2f}" if len(a) else " - "
    print(f"{f[:42]:42s} recall: {rec} | faux positifs: {n.p.mean():.3f} ({len(n)})")
