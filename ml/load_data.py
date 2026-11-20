#!/usr/bin/env python3
import glob, os
import pandas as pd

ROOT = os.path.expanduser("~/EVA-Guard/data")

# Fichiers de MESURES uniquement (échantillons toutes les 5s).
# On exclut explicitement les journaux d'événements (attack_*.csv, traffic_*.csv).
NORMAL_FILES = glob.glob(f"{ROOT}/raw/run_normal_*.csv")
ATTACK_FILES = (glob.glob(f"{ROOT}/merged/merged_*.csv") +
                 glob.glob(f"{ROOT}/merged/merged_*.txt"))

all_files = NORMAL_FILES + ATTACK_FILES
print(f"{len(NORMAL_FILES)} fichiers normaux (raw), {len(ATTACK_FILES)} fichiers d'attaque (merged)")

frames = []
for path in all_files:
    df = pd.read_csv(path, encoding="utf-8-sig")
    df.columns = [c.strip() for c in df.columns]
    if "timestamp" not in df.columns or "p2p_n_peers" not in df.columns:
        print(f"IGNORÉ (pas un fichier de mesures) : {path}")
        print("  colonnes :", list(df.columns)[:6])
        continue
    df["source_file"] = os.path.basename(path)
    frames.append(df)

if not frames:
    raise SystemExit("Aucun fichier valide trouvé.")

full = pd.concat(frames, ignore_index=True, sort=False)
print(f"\n{len(frames)} fichiers chargés, {len(full)} lignes")
print("Colonnes finales :", list(full.columns))
print(full["source_file"].value_counts())
full.to_csv("ml/data/all_raw.csv", index=False)
