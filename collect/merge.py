#!/usr/bin/env python3
"""EVA-Guard - fusionne la collecte victime avec le trafic et le journal d'attaque."""
import argparse, csv, os, sys
from datetime import datetime


def load_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def parse_ts(s):
    return datetime.fromisoformat(s)


def build_timeline(events):
    segments = []
    for i, e in enumerate(events):
        start = parse_ts(e["timestamp"])
        end = parse_ts(events[i + 1]["timestamp"]) if i + 1 < len(events) else None
        segments.append((start, end, e))
    return segments


def value_at(segments, ts, keys):
    result = {k: "" for k in keys}
    for start, end, e in segments:
        if start <= ts and (end is None or ts < end):
            for k in keys:
                result[k] = e.get(k, "")
            break
    return result


def _is_after_last_end(segments, ts):
    if not segments:
        return True
    last_start, last_end, last_e = segments[-1]
    return last_e.get("event") == "end" and ts >= last_start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--out-dir", default="data/merged")
    args = ap.parse_args()

    collect_path = os.path.join(args.raw_dir, f"run_{args.label}_{args.run_id}.csv")
    traffic_path = os.path.join(args.raw_dir, f"traffic_{args.run_id}.csv")
    attack_path = os.path.join(args.raw_dir, f"attack_{args.run_id}.csv")

    if not os.path.exists(collect_path):
        print(f"ERREUR : fichier de collecte introuvable : {collect_path}")
        sys.exit(1)

    collect_rows = load_rows(collect_path)
    print(f"Collecte victime : {len(collect_rows)} lignes ({collect_path})")

    traffic_segments = []
    if os.path.exists(traffic_path):
        traffic_events = load_rows(traffic_path)
        traffic_segments = build_timeline(traffic_events)
        print(f"Trafic honnête   : {len(traffic_events)} événements")
    else:
        print(f"Pas de fichier trafic ({traffic_path})")

    attack_segments = []
    if os.path.exists(attack_path):
        attack_events = load_rows(attack_path)
        attack_segments = build_timeline(attack_events)
        print(f"Journal d'attaque : {len(attack_events)} événements")
    else:
        print(f"Pas de journal d'attaque ({attack_path}) — normal si run normal/benign")

    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, f"merged_{args.label}_{args.run_id}.csv")

    extra_fields = ["traffic_profile", "traffic_mult",
                     "attack_name", "attack_intensity", "attack_active"]
    fieldnames = list(collect_rows[0].keys()) + extra_fields

    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in collect_rows:
            ts = parse_ts(row["timestamp"])
            tv = value_at(traffic_segments, ts, ["profile", "mult"]) if traffic_segments else {"profile": "", "mult": ""}
            av = value_at(attack_segments, ts, ["attack", "intensity"]) if attack_segments else {"attack": "", "intensity": ""}
            row["traffic_profile"] = tv.get("profile", "")
            row["traffic_mult"] = tv.get("mult", "")
            row["attack_name"] = av.get("attack", "")
            row["attack_intensity"] = av.get("intensity", "")
            row["attack_active"] = int(bool(av.get("attack")) and not _is_after_last_end(attack_segments, ts))
            w.writerow(row)

    print(f"Fusion terminée : {out_path} ({len(collect_rows)} lignes)")


if __name__ == "__main__":
    main()
