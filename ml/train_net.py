#!/usr/bin/env python3
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

DROP = {"api_block", "host_mem_sys_pct", "host_rss_geth_mb", "host_fds_geth",
        "host_threads_geth", "host_swap_pct", "api_txpool_pending", "api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]

tr = pd.read_csv("ml/data/train.csv"); tr = tr[tr.y != "node_down"]
te = pd.read_csv("ml/data/test.csv")
ytr = (tr.y_bin == "attack").astype(int); yte = (te.y_bin == "attack").astype(int)

rf = RandomForestClassifier(n_estimators=300, max_depth=8, class_weight="balanced",
                            random_state=42).fit(tr[feats], ytr)
p = rf.predict(te[feats])
print(classification_report(yte, p, target_names=["normal", "attack"], digits=3))
te["p"] = p
for f, g in te.groupby("source_file"):
    a = g[g.y_bin == "attack"]
    print(f, "recall:", round(a.p.mean(), 2) if len(a) else "-", "| FP:", round(g[g.y_bin=="normal"].p.mean(), 3))
print(pd.Series(rf.feature_importances_, index=feats).sort_values(ascending=False).head(8))
