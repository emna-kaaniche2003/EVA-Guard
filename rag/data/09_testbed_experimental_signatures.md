---
doc_id: KB09
title: Signatures expérimentales mesurées sur le banc EVA-Guard
category: scenario
attack_type: GENERIC
surface: P2P+SYSTEME+RPC
label: neutral
evidence_level: experimental
target_agent: interpretation,correlation,confirmation
---

## 1. DoS P2P — signature mesurée sur le banc
<!-- meta: scenario_id=SCN_DOS_EXP_001; attack_type=DOS_P2P; label=attack -->
- **Niveau de preuve** : experimental (médianes mesurées sur les campagnes dos_p2p_low / medium / high, comparées aux campagnes normales).
- **Signaux qui augmentent avec l'intensité** : `p2p_in_kbps` (≈ x5 en low, ≈ x45 en medium, ≈ x200 en high par rapport à la baseline normale de 4 à 5 kbps), `p2p_tcp_established` (9 / 24 / 60 contre 4), `host_lo_kbps` (685 / 1990 / 10180 contre 554-580), `host_fds_geth` (86 / 100 / 130 contre 81), `host_rss_geth_mb` (85 / 89 / 91 contre 73-78).
- **Signaux qui restent NORMAUX pendant l'attaque** : `host_cpu_geth` (≈ 2 %), `p2p_tcp_syn_recv` = 0, `p2p_log_error` = 0, `p2p_log_warn` = 0, `api_ok_ratio` = 1, `p2p_sync_lag` = 0, `p2p_n_peers` = 4 avec 4 pairs sortants. Les latences RPC et `host_cpu_sys` ne montent pas (elles sont même plus basses que sur les campagnes normales).
- **Conséquence pour l'interprétation** : sur ce banc, l'absence de saturation CPU, de SYN_RECV, d'erreurs de protocole et de dégradation RPC ne permet PAS d'écarter un DoS P2P. Le signal distinctif est la hausse **conjointe** du débit entrant, des connexions TCP établies, des descripteurs de fichiers et de la mémoire, avec une composition des pairs inchangée (pairs sortants conservés).
- **Limites du banc** : l'attaquant tourne sur la même machine, donc le flux passe par la boucle locale (`host_lo_kbps` très élevé) ; ce signal n'existerait pas pour un attaquant distant.

## 2. Eclipse — signature mesurée sur le banc
<!-- meta: scenario_id=SCN_ECL_EXP_001; attack_type=ECLIPSE; label=attack -->
- **Niveau de preuve** : experimental (médianes de la campagne eclipse_test).
- **Signal principal** : composition des pairs inversée. `p2p_n_outbound` = 0 et `p2p_n_inbound` = 4 (baseline normale : 0 entrant et 4 sortants), avec `p2p_n_peers` inchangé à 4. Au moment du basculement, `p2p_joined` et `p2p_churn` valent 4.
- **Signaux secondaires** : `host_load1` en hausse (≈ 4 contre 1,0 à 1,4) et `host_cpu_sys` en hausse (≈ 22 % contre 13 %), compatibles avec un processus attaquant sur la même machine.
- **Signaux NORMAUX ou BAS pendant l'attaque** : `p2p_in_kbps` bas (≈ 1 kbps) et `p2p_out_kbps` bas (≈ 0,2), `host_cpu_geth` bas (≈ 0,2 %), `host_rss_geth_mb` légèrement plus bas (65 contre 73-78), `p2p_sync_lag` = 0, `p2p_tcp_syn_recv` = 0, pas d'erreurs de protocole, latences RPC normales ou plus basses.
- **Conséquence pour l'interprétation** : un trafic faible et un CPU Geth bas sont attendus pour une Eclipse (pairs contrôlés par l'attaquant, peu d'échanges) et ne contredisent pas l'hypothèse. Le point à vérifier sur une fenêtre est la persistance de `p2p_n_outbound` = 0 et l'absence de retour de pairs sortants.
- **Diagnostic bénin à écarter** : nœud derrière un NAT ou un pare-feu qui n'accepte que des connexions entrantes. Il se distingue par l'absence de basculement : la composition entrante seule est stable depuis le démarrage (`p2p_joined` et `p2p_churn` = 0).

## 3. Comportement normal mesuré sur le banc
<!-- meta: category=normal_baseline; attack_type=NORMAL; label=normal -->
- **Niveau de preuve** : experimental (médianes des campagnes normal_mixed et normal_mixed2, trafic mixte).
- **Composition des pairs** : `p2p_n_peers` = 4, `p2p_n_inbound` = 0, `p2p_n_outbound` = 4, `p2p_churn` = 0, `p2p_sync_lag` = 0.
- **Trafic et connexions** : `p2p_in_kbps` ≈ 4,3 à 5,0 ; `p2p_out_kbps` ≈ 2,5 à 3,0 ; `p2p_tcp_established` = 4 ; `p2p_tcp_syn_recv` = 0 ; pas d'erreurs ni d'avertissements de protocole.
- **Système** : `host_cpu_geth` ≈ 2,2 à 2,4 % ; `host_rss_geth_mb` ≈ 73 à 78 ; `host_fds_geth` = 81 ; `host_cpu_sys` ≈ 13 % ; `host_load1` ≈ 1,0 à 1,4 ; `host_lo_kbps` ≈ 554 à 580.
- **RPC** : latences ≈ 3,6 à 4,6 ms ; `api_ok_ratio` = 1 ; `api_is_syncing` = 0.
- **Limite** : ce sont des médianes sur un banc à quatre pairs ; elles servent de référence relative et non de seuils universels.
