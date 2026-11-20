#!/usr/bin/env python3
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"]
d = d[~d.source_file.str.contains("eclipse")].copy()   # config du modèle final
d["t"] = (d.y_bin == "attack").astype(int)

def augment(tr, lo, hi, rng, n=300):
    normal = tr[tr.t == 0][feats].reset_index(drop=True)
    dos = tr[tr.y == "dos_p2p"][feats].reset_index(drop=True)
    rows = []
    for _ in range(n):
        a = rng.uniform(lo, hi)
        rows.append(normal.iloc[rng.integers(len(normal))] * (1 - a)
                    + dos.iloc[rng.integers(len(dos))] * a)
    syn = pd.DataFrame(rows, columns=feats); syn["t"] = 1
    return pd.concat([tr[feats + ["t"]], syn], ignore_index=True)

folds = {"dos_low": "dos_low", "normal1": "normal_mixed_2026", "normal2": "normal_mixed2"}
print("config (lo-hi) | seed | recall dos_low | FP normal1 | FP normal2")
for lo, hi in [(0, 0), (0.05, 0.6), (0.05, 0.3), (0.2, 0.6), (0.3, 0.6)]:
    for seed in range(3):
        rng = np.random.default_rng(seed)
        res = {}
        for name, key in folds.items():
            m = d.source_file.str.contains(key)
            tr, te = d[~m], d[m]
            tr_a = tr[feats + ["t"]] if hi == 0 else augment(tr, lo, hi, rng)
            rf = RandomForestClassifier(n_estimators=300, max_depth=8,
                    class_weight="balanced", random_state=seed).fit(tr_a[feats], tr_a.t)
            p = rf.predict(te[feats])
            res[name] = p[te.t.values == 1].mean() if name == "dos_low" else p[te.t.values == 0].mean()
        print(f"{lo}-{hi:<4} | {seed} | {res['dos_low']:.2f} | {res['normal1']:.3f} | {res['normal2']:.3f}")
