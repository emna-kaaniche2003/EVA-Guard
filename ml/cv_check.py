#!/usr/bin/env python3
import pandas as pd
from sklearn.model_selection import GroupKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

features = open("ml/data/feature_list.txt").read().splitlines()
train = pd.read_csv("ml/data/train.csv")
le = LabelEncoder().fit(train["y"])
y = le.transform(train["y"])
X = train[features]
groups = train["source_file"]

n_groups = groups.nunique()
gkf = GroupKFold(n_splits=min(4, n_groups))
model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
scores = cross_val_score(model, X, y, groups=groups, cv=gkf, scoring="f1_macro")
print(f"F1 macro par pli (groupes = fichiers) : {scores}")
print(f"Moyenne : {scores.mean():.3f}  écart-type : {scores.std():.3f}")
