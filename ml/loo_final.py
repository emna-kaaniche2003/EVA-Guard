#!/usr/bin/env python3
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DROP = {"api_block","host_mem_sys_pct","host_rss_geth_mb","host_fds_geth",
        "host_threads_geth","host_swap_pct","api_txpool_pending","api_txpool_queued"}
feats = [f for f in open("ml/data/feature_list.txt").read().splitlines() if f not in DROP]
print(len(feats), "features")

d = pd.concat([pd.read_csv("ml/data/train.csv"), pd.read_csv("ml/data/test.csv")], ignore_index=True)
d = d[d.y != "node_down"]
d = d[~d.source_file.str.contains("eclipse")].copy()   # config du modèle final
d["t"] = (d.y_bin == "attack").astype(int)
rng = np.random.default_rng(42)

def augment(tr, n=300):
    normal = tr[tr.t == 0][feats].reset_index(drop=True)
    dos = tr[tr.y == "dos_p2p"][feats].reset_index(drop=True)
    rows = []
    for _ in range(n):
        a = rng.uniform(0.05, 0.6)
        rows.append(normal.iloc[rng.integers(len(normal))] * (1 - a)
                    + dos.iloc[rng.integers(len(dos))] * a)
    syn = pd.DataFrame(rows, columns=feats); syn["t"] = 1
    return pd.concat([tr[feats + ["t"]], syn], ignore_index=True)

allp = []
for f in sorted(d.source_file.unique()):
    tr, te = d[d.source_file != f], d[d.source_file == f]
    tr_a = augment(tr)
    rf = RandomForestClassifier(n_estimators=300, max_depth=8,
            class_weight="balanced", random_state=42).fit(tr_a[feats], tr_a.t)
    p = rf.predict(te[feats])
    a, n = te[te.t == 1], te[te.t == 0]
    pa = p[te.t.values == 1]; pn = p[te.t.values == 0]
    rec = f"{pa.mean():.2f}" if len(a) else " - "
    print(f"{f[:42]:42s} recall: {rec} ({len(a)}) | FP: {pn.mean():.3f} ({len(n)})")
    allp.append(pd.DataFrame({"t": te.t.values, "p": p}))

r = pd.concat(allp)
print("\n=== Métriques globales (out-of-fold, 6 fichiers) ===")
print("Accuracy :", round(accuracy_score(r.t, r.p), 3))
print(classification_report(r.t, r.p, target_names=["normal", "attack"], digits=3))
print("Matrice de confusion :\n", confusion_matrix(r.t, r.p))
