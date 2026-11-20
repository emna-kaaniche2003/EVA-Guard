#!/usr/bin/env python3
import pandas as pd
from sklearn.ensemble import IsolationForest

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"].copy()
d["t"] = (d.y_bin == "attack").astype(int)

for cont in (0.01, 0.03, 0.05):
    print(f"\n=== contamination = {cont} ===")
    for f in sorted(d.source_file.unique()):
        tr, te = d[d.source_file != f], d[d.source_file == f]
        iso = IsolationForest(n_estimators=200, contamination=cont, random_state=42)
        iso.fit(tr[tr.t == 0][feats])          # normal seulement
        p = (iso.predict(te[feats]) == -1).astype(int)
        te = te.assign(p=p)
        a, n = te[te.t == 1], te[te.t == 0]
        rec = f"{a.p.mean():.2f}" if len(a) else " - "
        print(f"{f[:42]:42s} recall: {rec} | faux positifs: {n.p.mean():.3f} ({len(n)})")

