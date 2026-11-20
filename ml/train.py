#!/usr/bin/env python3
import pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier

features = [f for f in open("ml/data/feature_list.txt").read().splitlines()
            if f != "api_block"]
joblib.dump(features, "ml/models/features_used.joblib")

train = pd.read_csv("ml/data/train.csv")
train = train[train["y"] != "node_down"]
X = train[features]
y = (train["y_bin"] == "attack").astype(int)
print("Train :", y.value_counts().to_dict())

rf = RandomForestClassifier(n_estimators=300, max_depth=10,
                            class_weight="balanced", random_state=42).fit(X, y)
xgb = XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                    scale_pos_weight=(y == 0).sum() / (y == 1).sum(),
                    eval_metric="logloss", random_state=42).fit(X, y)
iso = IsolationForest(n_estimators=200, contamination=0.05,
                      random_state=42).fit(X[y == 0])   # normal seulement

for n, m in [("rf", rf), ("xgb", xgb), ("iso", iso)]:
    joblib.dump(m, f"ml/models/{n}_bin.joblib")
print("Modèles sauvegardés.")
