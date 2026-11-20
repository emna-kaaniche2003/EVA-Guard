#!/usr/bin/env python3
import sys
import joblib
import numpy as np
import pandas as pd

rf = joblib.load("ml/models/rf_dos_final.joblib")
feats = joblib.load("ml/models/features_final.joblib")


def prepare(df):
    """Même nettoyage et mêmes features qu'à l'entraînement."""
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

    # débits négatifs (reset de compteur) -> manquant
    for c in ["p2p_in_kbps", "p2p_out_kbps"]:
        df.loc[df[c] < 0, c] = np.nan

    # colonnes créées au nettoyage
    df["host_overload"] = (df["host_cpu_sys"] >= 95).astype(int)

    # valeurs sentinelles
    for c in ["api_block", "api_is_syncing"]:
        if c in df.columns:
            df[c] = df[c].fillna(-1)

    # features dérivées
    df["p2p_all_inbound"] = ((df["p2p_n_outbound"] == 0) &
                             (df["p2p_n_peers"] > 0)).astype(int)
    for c in ["api_lat_blocknumber_ms", "api_lat_peers_ms"]:
        df[c + "_avg5"] = df[c].rolling(5, min_periods=1).mean()

    # imputation des manquants restants (médiane, puis 0)
    num = df.select_dtypes("number").columns
    df[num] = df[num].fillna(df[num].median()).fillna(0)
    return df


def detect(df):
    df = prepare(df)
    dos = rf.predict(df[feats])
    out = pd.Series("normal", index=df.index)
    out[dos == 1] = "dos_p2p"
    out[df["p2p_all_inbound"] == 1] = "eclipse"   # la règle Eclipse est prioritaire
    return out


if __name__ == "__main__":
    path = sys.argv[1]
    df = pd.read_csv(path, encoding="utf-8-sig")
    df.columns = [c.strip() for c in df.columns]
    df = prepare(df)
    df["pred"] = detect(df)
    print(path, "->", df["pred"].value_counts().to_dict())

