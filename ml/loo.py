#!/usr/bin/env python3
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"]
d["t"] = (d.y_bin == "attack").astype(int)

for f in sorted(d.source_file.unique()):
    tr, te = d[d.source_file != f], d[d.source_file == f]
    rf = RandomForestClassifier(n_estimators=300, max_depth=8,
                                class_weight="balanced", random_state=42).fit(tr[feats], tr.t)
    te = te.assign(p=rf.predict(te[feats]))
    a, n = te[te.t == 1], te[te.t == 0]
    print(f"{f}\n   recall attaque: {a.p.mean():.2f} ({len(a)} lignes) | faux positifs: {n.p.mean():.3f} ({len(n)} lignes)")
