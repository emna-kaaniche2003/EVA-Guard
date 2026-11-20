#!/usr/bin/env python3
import pandas as pd

df = pd.read_csv("ml/data/all_features.csv")

# Assignation manuelle : on choisit quel fichier va où, car il y a trop peu
# de groupes par classe pour un split aléatoire fiable.
TEST_FILES = {
    "run_normal_mixed2_20261119_094757.csv",   # normal (2e run, indépendant)
    "merged_dos_p2p_high_dos_high_01.csv",      # dos_p2p (intensité la plus nette)
    "merged_dos_test_dostest01.csv",            # dos_p2p (run de test)
}
# Tout le reste va en train, y compris le seul fichier eclipse disponible
train = df[~df["source_file"].isin(TEST_FILES)]
test = df[df["source_file"].isin(TEST_FILES)]

for name, part in [("train", train), ("test", test)]:
    print(f"{name}: {len(part)} lignes | classes: {part['y'].value_counts().to_dict()}")
    part.to_csv(f"ml/data/{name}.csv", index=False)

assert not set(train.source_file) & set(test.source_file)
print("\nAucun fichier partagé entre train et test : OK")
