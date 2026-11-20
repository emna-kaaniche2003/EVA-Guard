#!/usr/bin/env python3
import pandas as pd
df = pd.read_csv("ml/data/all_clean.csv")

def target(row):
    raw = str(row["label"])
    active = row.get("attack_active", 0)
    if row.get("node_down", 0) == 1:
        return "node_down"              # catégorie à part : redémarrage, pas une mesure propre
    if raw.startswith("normal"):
        return "normal"
    if raw.startswith("benign"):
        return "benign"
    if active == 1:
        if "eclipse" in raw: return "eclipse"
        if "dos" in raw:     return "dos_p2p"
        return "attack_inconnue"
    return "normal"                      # phase avant/après l'attaque dans le même fichier

df["y"] = df.apply(target, axis=1)
print(df["y"].value_counts())
df.to_csv("ml/data/all_target.csv", index=False)
