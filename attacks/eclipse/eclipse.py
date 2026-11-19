#!/usr/bin/env python3
"""EVA-Guard - simulation d'attaque Eclipse sur le nœud victime (node2).

Principe : redémarrage à froid de la victime avec maxpeers réduit, puis
course aux créneaux de pairs gagnée par des nœuds attaquants plus nombreux
et plus agressifs que les nœuds honnêtes. Simplification documentée car le
réseau utilise --nodiscover (pas d'empoisonnement de table Kademlia possible).
"""
import argparse, csv, os, shutil, subprocess, sys, time
from datetime import datetime
import requests

NETWORK_ID = 12345
VICTIM_RPC = "http://127.0.0.1:8546"
VICTIM_DATADIR = os.path.expanduser("~/eva-data/node2")
VICTIM_PORT = 30302
VICTIM_MAXPEERS_NORMAL = 50
ADDR_FILE = os.path.expanduser("~/eva-data/addr.txt")
PASSWORD_FILE = os.path.expanduser("~/eva-data/pwd.txt")
GENESIS_FILE = os.path.expanduser("~/EVA-Guard/infra/genesis.json")
ATTACK_BASE_PORT = 31000
ATTACK_DATADIR_BASE = os.path.expanduser("~/eva-data/attackers")
GETH_BIN = shutil.which("geth") or "geth"
LOG_PATH = os.path.expanduser("~/eva-data/logs/node2.log")


def rpc(url, method, params=None, timeout=5):
    try:
        r = requests.post(url, timeout=timeout, json={
            "jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).json()
        return r.get("result")
    except Exception:
        return None


def get_victim_enode():
    info = rpc(VICTIM_RPC, "admin_nodeInfo")
    if not info:
        print("ERREUR : impossible de lire admin_nodeInfo sur la victime.")
        sys.exit(1)
    enode = info["enode"]
    return enode.split("?")[0]


def stop_victim():
    subprocess.run(["pkill", "-f", f"datadir {VICTIM_DATADIR}"], check=False)
    time.sleep(3)


def start_victim(maxpeers):
    """Redémarre la victime à froid (0 pair) avec maxpeers réduit."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    addr = open(ADDR_FILE).read().strip() if os.path.exists(ADDR_FILE) else None
    cmd = [GETH_BIN, "--networkid", str(NETWORK_ID), "--datadir", VICTIM_DATADIR,
           "--nat", "none", "--netrestrict", "127.0.0.0/8",
           "--port", str(VICTIM_PORT), "--http", "--http.addr", "127.0.0.1",
           "--http.port", "8546", "--authrpc.port", "8552",
           "--http.api", "eth,net,web3,admin,txpool",
           "--metrics", "--metrics.addr", "127.0.0.1", "--metrics.port", "6062",
           "--cache", "128",
           "--maxpeers", str(maxpeers), "--nodiscover", "--verbosity", "3"]
    log = open(LOG_PATH, "a")
    subprocess.Popen(cmd, stdout=log, stderr=log)
    for _ in range(30):
        if rpc(VICTIM_RPC, "eth_blockNumber") is not None:
            return
        time.sleep(1)
    print("ERREUR : la victime n'a pas redémarré à temps. "
          "Vérifiez les chemins (datadir, genesis) et comparez avec infra/start_network.sh.")
    sys.exit(1)


def spawn_attacker(idx):
    port = ATTACK_BASE_PORT + idx
    http_port = 9000 + idx
    datadir = f"{ATTACK_DATADIR_BASE}/n{idx}"
    os.makedirs(datadir, exist_ok=True)
    if not os.path.exists(os.path.join(datadir, "geth")):
        subprocess.run([GETH_BIN, "--datadir", datadir, "init", GENESIS_FILE],
                        check=True, capture_output=True)
    cmd = [GETH_BIN, "--networkid", str(NETWORK_ID), "--datadir", datadir,
           "--nat", "none", "--netrestrict", "127.0.0.0/8",
           "--port", str(port), "--nodiscover", "--maxpeers", "4",
           "--http", "--http.port", str(http_port), "--http.addr", "127.0.0.1",
           "--authrpc.port", str(http_port + 1000),
           "--syncmode", "full", "--verbosity", "1"]
    log = open(f"{datadir}/attacker.log", "w")
    p = subprocess.Popen(cmd, stdout=log, stderr=log)
    return p, f"http://127.0.0.1:{http_port}"


def wait_attacker_ready(rpc_url, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if rpc(rpc_url, "eth_blockNumber") is not None:
            return True
        time.sleep(1)
    return False


def race_connect(attacker_rpcs, victim_enode, duration):
    """Boucle agressive : chaque attaquant retente la connexion en continu."""
    end = time.time() + duration
    while time.time() < end:
        for url in attacker_rpcs:
            rpc(url, "admin_addPeer", [victim_enode])
        time.sleep(1)


def cleanup_attackers(procs):
    for p in procs:
        p.terminate()
    time.sleep(2)
    for p in procs:
        if p.poll() is None:
            p.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--intensity", type=int, choices=[10, 20, 40], default=20,
                     help="part visée des créneaux de pairs par l'attaquant (%%)")
    ap.add_argument("--duration", type=int, default=240)
    ap.add_argument("--maxpeers", type=int, default=12,
                     help="maxpeers réduit de la victime pendant le run")
    ap.add_argument("--run-id", default=None)
    args = ap.parse_args()

    run_id = args.run_id or f"{datetime.now():%Y%m%d_%H%M%S}"
    os.makedirs("data/raw", exist_ok=True)
    log_path = f"data/raw/attack_{run_id}.csv"
    log_file = open(log_path, "w", newline="")
    log_writer = csv.writer(log_file)
    log_writer.writerow(["timestamp", "event", "attack", "intensity", "n_attackers"])

    n_attackers = max(1, round(args.maxpeers * args.intensity / 100))
    print(f"Intensité {args.intensity}% -> {n_attackers} nœuds attaquants "
          f"(maxpeers victime = {args.maxpeers})")

    print("Redémarrage à froid de la victime...")
    stop_victim()
    start_victim(args.maxpeers)
    victim_enode = get_victim_enode()
    print("Enode victime :", victim_enode)

    log_writer.writerow([datetime.now().isoformat(timespec="seconds"), "start",
                         "eclipse", args.intensity, n_attackers])
    log_file.flush()

    print(f"Lancement de {n_attackers} nœuds attaquants...")
    procs, rpcs = [], []
    for i in range(n_attackers):
        p, url = spawn_attacker(i)
        procs.append(p)
        if wait_attacker_ready(url):
            rpcs.append(url)
        else:
            print(f"  Attaquant {i} non prêt, ignoré.")

    print(f"Course aux créneaux pendant {args.duration}s "
          f"(collect.py doit tourner en parallèle)...")
    try:
        race_connect(rpcs, victim_enode, args.duration)
    except KeyboardInterrupt:
        pass

    peers = rpc(VICTIM_RPC, "admin_peers") or []
    print(f"Fin du run : {len(peers)} pairs connectés sur la victime.")

    print("Nettoyage des nœuds attaquants...")
    cleanup_attackers(procs)

    log_writer.writerow([datetime.now().isoformat(timespec="seconds"), "end",
                         "eclipse", args.intensity, n_attackers])
    log_file.close()

    print("Restauration de la victime (maxpeers normal)...")
    stop_victim()
    start_victim(VICTIM_MAXPEERS_NORMAL)
    print("Terminé. Les nœuds honnêtes devraient se reconnecter automatiquement "
          "via leurs --bootnodes ; vérifiez avec admin.peers.")
    print("Journal d'attaque :", log_path)


if __name__ == "__main__":
    main()
