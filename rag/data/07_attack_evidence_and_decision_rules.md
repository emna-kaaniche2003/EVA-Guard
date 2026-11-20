---
doc_id: 07_attack_evidence_and_decision_rules
title: Preuves d'attaque et règles de décision
category: decision_rules
attack_type: GENERIC
surface: P2P,SYSTEM,RPC
label: neutral
evidence_level: theoretical
target_agent: interpretation,confirmation
---

# Preuves d'attaque et règles de décision

## 0. Périmètre et rôle

Ce document définit les **critères de décision** permettant de distinguer Eclipse Attack, DoS P2P et anomalie bénigne. La **confirmation finale appartient à l'agent de confirmation**, pas au LLM : le LLM formule des hypothèses avec un niveau de confiance et la liste des preuves manquantes.

## 1. Règles Eclipse Attack

| Réf. | Condition | Interprétation |
|---|---|---|
| ECL_R1 | Diminution durable du nombre de pairs (`p2p_n_peers`) | Signal suspect |
| ECL_R2 | Diminution de la diversité des pairs (IP/sous-réseaux/ASN) | Preuve complémentaire |
| ECL_R3 | Augmentation monotone de `p2p_sync_lag` (RPC_SYNC) ; stagnation d'`api_block` | Preuve complémentaire |
| ECL_R4 | `host_cpu_geth` et `host_cpu_sys` normaux, latences RPC normales | Élément discriminant (exclut DoS) |
| ECL_R5 | Redémarrage récent suivi d'une diversité qui ne se rétablit pas | Renforce l'hypothèse Eclipse |
| ECL_R6 | Hausse de `p2p_log_peer_search` | Preuve complémentaire |

## 2. Règles DoS P2P

| Réf. | Condition | Interprétation |
|---|---|---|
| DOS_R1 | Augmentation du trafic P2P (`p2p_in_kbps`, `p2p_out_kbps`) | Signal suspect |
| DOS_R2 | `host_cpu_geth` élevé, concomitant | Preuve complémentaire |
| DOS_R3 | `host_rss_geth_mb` élevé ou en hausse | Preuve complémentaire |
| DOS_R4 | Hausse de `p2p_tcp_syn_recv` concentrée sur peu d'IP, ou erreurs de protocole | Preuve complémentaire |
| DOS_R5 | RPC_LATENCE élevée, `api_ok_ratio` en baisse | Impact collatéral (confirme la cascade, ne suffit pas seul) |

## 3. Matrice « surfaces en dérive → hypothèse »

### 3.0 Deux familles d'indicateurs RPC à ne pas confondre

La surface RPC regroupe deux familles aux significations opposées :

- **RPC_LATENCE** (santé du service) : `api_lat_blocknumber_ms`, `api_lat_peercount_ms`, `api_lat_getblock_ms`, `api_lat_peers_ms`, `api_ok_ratio`. Une dégradation indique un nœud **surchargé** (DoS) ou une charge locale (requête lourde).
- **RPC_SYNC** (fraîcheur de l'information) : `p2p_sync_lag` (calculé vs `REF_RPC`), `api_block`, `api_is_syncing`. Une dégradation indique un nœud **à jour en retard**, ce qui est la signature de l'Eclipse, y compris quand le service répond vite.

Conséquence : « P2P + RPC » n'a de sens que si la famille est précisée. **Eclipse = P2P + RPC_SYNC avec RPC_LATENCE normale.** **DoS = P2P + SYSTEM + RPC_LATENCE.** Une dégradation RPC_LATENCE seule, ou avec SYSTEM seul, n'est pas une Eclipse ; une dégradation générale du service RPC ne doit jamais être interprétée comme une preuve d'Eclipse.

Une **surface en dérive** est un groupe (`P2P`, `SYSTEM`, `RPC`) dont au moins un indicateur dérive de façon significative par rapport à la baseline, dans une fenêtre temporelle cohérente de quelques intervalles de 5 s.

| Surfaces en dérive | Hypothèse la plus prudente | Notes |
|---|---|---|
| Une seule surface | Anomalie bénigne / preuves insuffisantes | Nommer le diagnostic bénin le plus probable (FP_001 à FP_006) |
| P2P + RPC_SYNC, SYSTEM et RPC_LATENCE normaux | Eclipse Attack (hypothèse à approfondir) | Vérifier diversité, tendance du sync lag, redémarrage récent ; exclure FP_004, FP_008 |
| P2P + SYSTEM + RPC_LATENCE concomitants, avec trafic élevé | DoS P2P (hypothèse à approfondir) | Vérifier concentration `p2p_tcp_syn_recv`, erreurs de protocole ; exclure Initial Sync (FP_007) |
| P2P + SYSTEM, RPC_LATENCE normale | DoS P2P à un stade précoce **ou** synchronisation | Vérifier tendance du sync lag et erreurs de protocole |
| SYSTEM + RPC_LATENCE, P2P normal | Charge locale (bénin probable) | Évoquer requête lourde, GC, compaction, rafale applicative |
| Signaux contradictoires | Analyse supplémentaire requise | Voir section 4.4 |

## 4. Règles de confirmation

1. **Une seule surface anormale : preuves insuffisantes.** Ne pas conclure à une attaque.
2. **Deux surfaces anormales : hypothèse à approfondir.** Lister les preuves manquantes.
3. **Plusieurs preuves indépendantes et cohérentes : confirmation possible** selon les critères définis, **par l'agent de confirmation uniquement**.
4. **Signaux contradictoires : demander une analyse supplémentaire.** Exemples : baisse de pairs **et** CPU saturé (un DoS peut provoquer des déconnexions ; Eclipse et DoS peuvent aussi coexister) ; sync lag croissant **et** débit entrant élevé.
5. **Concomitance temporelle obligatoire** : des signaux séparés par des heures ne corroborent pas.
6. **Tendance avant valeur** : pour `p2p_sync_lag`, une croissance monotone suggère Eclipse, une décroissance suggère synchronisation/redémarrage.
7. **Indépendance des preuves** : deux métriques fortement dépendantes (ex. `p2p_in_kbps` et `p2p_out_kbps`) comptent pour une seule preuve.

## 5. Règles de contrôle du biais pour le LLM

- La prédiction du modèle ML est un **signal à évaluer**, pas une preuve.
- Toujours évaluer l'hypothèse **alternative** : bénigne et autre attaque.
- Toujours nommer le diagnostic bénin le plus probable quand il existe.
- Ne jamais écrire « confirmée » ; écrire « hypothèse », avec niveau de confiance (faible, moyen, fort) et preuves manquantes.
- Les valeurs chiffrées citées doivent provenir de `06_normal_behavior_baseline.md` ou du run ; ne pas inventer de seuil.

## 6. Critères de l'agent de confirmation (propositions de départ, à calibrer sur le banc)

Ces critères sont des **valeurs de départ proposées**, non validées expérimentalement. Elles doivent être calibrées avec les scénarios `experimental` de `04`.

### 6.1 Comptage des preuves indépendantes
Les indicateurs sont regroupés en **familles** ; une famille compte pour **une seule** preuve :
`P2P_COMPOSITION` (`p2p_n_peers`, `p2p_n_inbound`, `p2p_n_outbound`, diversité), `P2P_CHURN` (`p2p_joined`, `p2p_left`, `p2p_churn`), `P2P_VOLUME` (`p2p_in_kbps`, `p2p_out_kbps`), `P2P_CONNEXIONS` (`p2p_tcp_*`), `P2P_LOGS` (`p2p_log_*`), `SYS_CPU` (`host_cpu_geth`, `host_cpu_sys`, `host_load1`), `SYS_RESSOURCES` (`host_rss_geth_mb`, `host_threads_geth`, `host_fds_geth`), `RPC_SYNC`, `RPC_LATENCE`.

### 6.2 Statuts possibles
`INSUFFISANT` (une seule surface), `HYPOTHESE` (deux surfaces), `CONFIRMABLE` (critères ci-dessous remplis), `CONTRADICTOIRE` (analyse supplémentaire).

### 6.3 Critères par attaque
- **Eclipse — CONFIRMABLE si** : ≥ 3 familles de preuves indépendantes, **dont obligatoirement** diversité des pairs en baisse (`P2P_COMPOSITION`), `RPC_SYNC` croissant (monotone ≥ 3 intervalles consécutifs, soit ≥ 15 s), et `SYS_CPU` normal avec `RPC_LATENCE` normale ; et aucune contradiction.
- **DoS P2P — CONFIRMABLE si** : ≥ 3 familles de preuves indépendantes, **dont obligatoirement** une famille `P2P_VOLUME` ou `P2P_CONNEXIONS`, une famille `SYS_CPU` ou `SYS_RESSOURCES`, et `RPC_LATENCE` dégradée ; et aucune contradiction.

### 6.4 Cohérence temporelle
Toutes les preuves retenues doivent tomber dans une même fenêtre de **W intervalles de collecte** (valeur de départ proposée : W = 6, soit 30 s à 5 s d'intervalle ; `[À CALIBRER]`).

### 6.5 Contradictions (→ `CONTRADICTOIRE`)
- `RPC_SYNC` croissant **et** `SYS_CPU` saturé avec `P2P_VOLUME` élevé (DoS et Eclipse simultanés, ou DoS provoquant des déconnexions).
- `P2P_COMPOSITION` en baisse **et** `RPC_SYNC` décroissant (redémarrage/synchronisation, voir FP_007, FP_008).
- Preuves hors fenêtre W.
- Un faux positif de `03` explique toutes les preuves observées.
