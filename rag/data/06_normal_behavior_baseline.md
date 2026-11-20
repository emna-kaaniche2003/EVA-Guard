---
doc_id: 06_normal_behavior_baseline
title: Comportement normal d'un nœud Ethereum (baseline)
category: normal_baseline
attack_type: NORMAL
surface: P2P,SYSTEM,RPC
label: normal
evidence_level: theoretical
target_agent: interpretation,confirmation
---

# Comportement normal d'un nœud Ethereum (baseline)

## 0. Statut de ce document

Les comportements décrits sont **qualitatifs**. Les valeurs numériques (plages, seuils) doivent être **mesurées sur le banc EVA-Guard** et reportées dans la section 2. Tant qu'une valeur est marquée `[À RENSEIGNER]`, ne pas inventer de seuil : le LLM doit raisonner par tendance, concomitance et corroboration, pas par valeur absolue.

## 1. Situations normales et comportement attendu

### 1.1 Fonctionnement normal
<!-- meta: scenario_id=BASE_001 -->
Métriques relativement stables : `p2p_n_peers` autour d'une valeur stable, diversité des pairs élevée, `p2p_sync_lag` faible, CPU/RAM modérés, latences RPC faibles, `api_ok_ratio` proche de 1, `api_is_syncing` à 0.

### 1.2 Synchronisation (initiale ou rattrapage)
<!-- meta: scenario_id=BASE_002 -->
Activité réseau et CPU variable et élevée ; `api_is_syncing` à 1 ; `p2p_sync_lag` élevé mais **décroissant** ; `api_block` progresse. Une augmentation de CPU pendant une synchronisation n'est pas nécessairement une attaque (voir FP_007).

### 1.3 Découverte des pairs
<!-- meta: scenario_id=BASE_003 -->
Variation du nombre de pairs, `p2p_joined`/`p2p_left` non nuls, `p2p_log_peer_search` présent au démarrage puis faible. Le churn modéré et dispersé est normal (voir FP_004).

### 1.4 Réception de nouveaux blocs
<!-- meta: scenario_id=BASE_004 -->
Pics courts et réguliers de CPU et de trafic réseau à l'arrivée de chaque bloc ; retour à la normale ensuite. Un bloc exceptionnellement lourd produit un pic plus marqué mais isolé (voir FP_003).

### 1.5 Redémarrage
<!-- meta: scenario_id=BASE_005 -->
Reconnexion progressive des pairs ; `p2p_n_peers` remonte par paliers, `p2p_churn` transitoire, `p2p_sync_lag` transitoirement élevé puis décroissant, diversité rétablie (voir FP_008).

### 1.6 Charge RPC élevée
<!-- meta: scenario_id=BASE_006 -->
Augmentation possible de la latence RPC et de `api_txpool_pending`, sans hausse du débit P2P ni des erreurs de protocole (voir FP_005, FP_006).

### 1.7 Opérations internes de maintenance
<!-- meta: scenario_id=BASE_007 -->
GC du runtime Go et compaction de base : pics CPU/RAM isolés, sans signal P2P (voir FP_001, FP_002).

## 2. Conditions expérimentales de la baseline (à compléter)

Ces champs conditionnent la validité de toute plage normale. Ils sont à renseigner avec les valeurs réelles du banc.

| Paramètre | Valeur |
|---|---|
| Client Ethereum et version | Geth — version `[À RENSEIGNER]` |
| Réseau (mainnet / testnet / réseau privé) | `[À RENSEIGNER]` |
| Configuration matérielle (CPU, RAM, disque) | `[À RENSEIGNER]` |
| `maxpeers` configuré | `[À RENSEIGNER]` |
| Nombre de pairs observé en régime normal | `[À RENSEIGNER]` |
| Intervalle de collecte | 5 s (d'après les playbooks) — à confirmer |
| Durée d'observation de la baseline | `[À RENSEIGNER]` |
| Nœud de référence | `REF_RPC` |
| Charge réseau normale | `[À RENSEIGNER]` |
| Générateur de charge applicative | `traffic.py` (profils dont `high`, rafale x2.5 de 10 s) — détails `[À RENSEIGNER]` |

## 3. Plages normales mesurées (à compléter)

| Métrique | Médiane | P95 | Unité | Run de référence |
|---|---|---|---|---|
| `p2p_n_peers` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | pairs | |
| `p2p_in_kbps` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | kbit/s | |
| `host_cpu_geth` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | % | |
| `host_rss_geth_mb` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | Mo | |
| `p2p_sync_lag` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | blocs | |
| `api_lat_blocknumber_ms` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | ms | |
| `api_ok_ratio` | `[À RENSEIGNER]` | `[À RENSEIGNER]` | ratio | |

## 4. Limites de la baseline

- Une baseline mesurée sur un banc local ou un réseau privé (peu de pairs, faible diversité) ne se transpose pas au mainnet.
- La baseline dépend de la version de Geth, du matériel et de la charge : toute modification de ces éléments invalide les plages.
- Un comportement dans la plage normale ne prouve pas l'absence d'attaque ; il indique seulement l'absence de dérive sur cette métrique.
