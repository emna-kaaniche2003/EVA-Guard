---
doc_id: 04_attack_scenarios_examples
title: Scénarios de référence — situations observables sur un nœud Ethereum
category: scenario
attack_type: GENERIC
surface: P2P,SYSTEM,RPC
label: neutral
evidence_level: illustrative
target_agent: interpretation,correlation
---

# Scénarios de référence

## 0. Statut des exemples (à lire en premier)

<!-- meta: scenario_id=SCN_META; category=scenario; attack_type=GENERIC; label=neutral; evidence_level=illustrative -->

Chaque scénario porte un **niveau de preuve unique** : `illustrative`, `simulated` ou `experimental`. Ces catégories ne doivent jamais être mélangées dans un même scénario.

- `illustrative` : profil qualitatif construit à partir de la logique des playbooks 01-03 ; **aucune valeur mesurée**.
- `simulated` : produit par un simulateur/générateur ; à renseigner avec l'identifiant du run.
- `experimental` : mesuré sur le banc EVA-Guard ; à renseigner avec l'identifiant du run, la date et la configuration.

**Tous les scénarios ci-dessous sont `illustrative`.** Ils ne contiennent pas de chiffres mesurés. Ils servent à comparer des *formes* de situations, pas à fixer des seuils. Les seuils viennent de `06_normal_behavior_baseline.md`, une fois la baseline mesurée.

## 1. Tableau comparatif synthétique (illustratif)

| Scénario | P2P | CPU | RAM | RPC | Diagnostic |
|---|---|---|---|---|---|
| Normal | Normal | Normal | Normal | Normal | Normal |
| Eclipse | Pairs en baisse, diversité basse | Normal | Normal | Sync retardée | Eclipse |
| DoS P2P | Trafic élevé | Élevé | Élevée | Latence élevée | DoS P2P |
| GC | Normal | Pic | Variable | Normal | Bénin |
| Churn naturel | Variation | Normal | Normal | Normal | Bénin |
| RPC lourd | Normal | Normal | Stable | Latence élevée | Bénin |

## 2. Fiches de scénarios

### SCN_NOR_001 — Fonctionnement normal
<!-- meta: scenario_id=SCN_NOR_001; category=scenario; attack_type=NORMAL; surface=P2P,SYSTEM,RPC; label=normal; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : n_peers stable ; diversité élevée ; débit P2P modéré et régulier ; CPU/RAM stables ; latences RPC normales ; sync lag faible
- **Durée de l'anomalie** : Continue (régime permanent)
- **Surfaces affectées** : Aucune (référence)
- **Preuves présentes** : Toutes les métriques dans leur plage de baseline
- **Preuves absentes** : Aucune dérive sur aucune surface
- **Diagnostic attendu** : Normal — aucune action

### SCN_ECL_001 — Eclipse — isolation partielle
<!-- meta: scenario_id=SCN_ECL_001; category=scenario; attack_type=ECLIPSE; surface=P2P,RPC; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : p2p_n_peers en baisse modérée ; diversité en baisse ; p2p_churn élevé sur peu de plages IP ; p2p_sync_lag en hausse lente ; CPU/RAM normaux ; latences RPC normales
- **Durée de l'anomalie** : Plusieurs minutes (dérive durable, ≥ 3 intervalles consécutifs)
- **Surfaces affectées** : P2P puis RPC (sync lag)
- **Preuves présentes** : Baisse de diversité + sync lag croissant + CPU normal
- **Preuves absentes** : Pas de saturation CPU/RAM, pas d'explosion de débit
- **Diagnostic attendu** : Eclipse Attack (hypothèse) — confiance moyenne ; à distinguer du churn naturel (FP_004)

### SCN_ECL_002 — Eclipse — isolation complète
<!-- meta: scenario_id=SCN_ECL_002; category=scenario; attack_type=ECLIPSE; surface=P2P,RPC; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : p2p_n_peers très bas ; diversité très basse ; asymétrie inbound/outbound ; p2p_sync_lag élevé et monotone ; api_block stagne ; CPU/RAM normaux ; latences RPC normales
- **Durée de l'anomalie** : Durable, s'aggrave avec le temps
- **Surfaces affectées** : P2P et RPC
- **Preuves présentes** : Chute de diversité, sync lag monotone, api_block stagnant, CPU normal, latence RPC normale
- **Preuves absentes** : Pas de signal de flooding (débit/CPU/RAM normaux)
- **Diagnostic attendu** : Eclipse Attack (hypothèse) — confiance forte si toutes les preuves sont concomitantes ; confirmation par l'agent aval

### SCN_ECL_003 — Eclipse — après redémarrage
<!-- meta: scenario_id=SCN_ECL_003; category=scenario; attack_type=ECLIPSE; surface=P2P,RPC; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Redémarrage récent ; n_peers remonte mais la diversité reste basse ; p2p_log_peer_search en hausse ; p2p_sync_lag croît au lieu de décroître ; CPU normal
- **Durée de l'anomalie** : Persistant après la fenêtre normale de reconnexion
- **Surfaces affectées** : P2P et RPC
- **Preuves présentes** : Redémarrage récent + diversité basse persistante + sync lag croissant
- **Preuves absentes** : Pas de rétablissement de la diversité ; pas de saturation CPU
- **Diagnostic attendu** : Eclipse Attack (hypothèse) ; à distinguer de la reconnexion normale (FP_008)

### SCN_DOS_001 — DoS — SYN flooding
<!-- meta: scenario_id=SCN_DOS_001; category=scenario; attack_type=DOS_P2P; surface=P2P,SYSTEM,RPC; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : p2p_tcp_syn_recv en forte hausse concentré sur peu d'IP ; p2p_in_kbps élevé ; host_cpu_geth et host_cpu_sys en hausse ; host_fds_geth en hausse ; latences RPC en hausse ; api_ok_ratio en baisse
- **Durée de l'anomalie** : Durée soutenue (au-delà de 2 intervalles de 5 s)
- **Surfaces affectées** : P2P, SYSTEM, RPC (cascade)
- **Preuves présentes** : Hausse simultanée débit + connexions semi-ouvertes + CPU + latence RPC
- **Preuves absentes** : Pas de chute de diversité ciblée comme signal principal
- **Diagnostic attendu** : DoS P2P (hypothèse) — confiance forte si les trois surfaces sont concomitantes

### SCN_DOS_002 — DoS — flooding de messages applicatifs
<!-- meta: scenario_id=SCN_DOS_002; category=scenario; attack_type=DOS_P2P; surface=P2P,SYSTEM,RPC; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : p2p_in_kbps élevé ; host_cpu_geth saturé ; host_rss_geth_mb en hausse ; p2p_log_warn/p2p_log_error en hausse ; latences RPC en hausse ; déconnexions de pairs légitimes (p2p_churn par surcharge)
- **Durée de l'anomalie** : Soutenue
- **Surfaces affectées** : P2P, SYSTEM, RPC
- **Preuves présentes** : Erreurs de protocole + saturation CPU/RAM + dégradation RPC
- **Preuves absentes** : Pas de signature SYN flood obligatoire (p2p_tcp_syn_recv peut rester modéré)
- **Diagnostic attendu** : DoS P2P (hypothèse)

### SCN_DOS_003 — DoS — répétition de handshakes
<!-- meta: scenario_id=SCN_DOS_003; category=scenario; attack_type=DOS_P2P; surface=P2P,SYSTEM; label=attack; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : host_cpu_geth élevé avec débit modéré ; p2p_tcp_time_wait en hausse ; erreurs de handshake dans p2p_log_error ; connexions courtes à rotation rapide
- **Durée de l'anomalie** : Soutenue
- **Surfaces affectées** : P2P et SYSTEM, RPC ensuite
- **Preuves présentes** : CPU élevé + rotation de connexions + erreurs de handshake
- **Preuves absentes** : Débit P2P pas nécessairement explosif
- **Diagnostic attendu** : DoS P2P (hypothèse) — peut être confondu avec FP_001 si p2p_log_error et p2p_tcp_time_wait ne sont pas examinés

### SCN_BEN_GC_001 — Bénin — Garbage Collection / compaction
<!-- meta: scenario_id=SCN_BEN_GC_001; category=scenario; attack_type=BENIGN; surface=SYSTEM; label=benign; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Pic isolé de host_cpu_geth / host_rss_geth_mb ; débit P2P normal ; n_peers stable ; latences RPC normales ou légèrement en hausse
- **Durée de l'anomalie** : Bref, ne se prolonge pas
- **Surfaces affectées** : SYSTEM uniquement
- **Preuves présentes** : Aucune autre surface en dérive
- **Preuves absentes** : Pas de hausse de p2p_in_kbps/p2p_out_kbps, pas de chute de p2p_n_peers, pas de p2p_tcp_syn_recv élevé
- **Diagnostic attendu** : Anomalie bénigne (GC / compaction DB) — voir FP_001, FP_002

### SCN_BEN_CHURN_001 — Bénin — churn P2P naturel
<!-- meta: scenario_id=SCN_BEN_CHURN_001; category=scenario; attack_type=BENIGN; surface=P2P; label=benign; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Variation modérée de p2p_n_peers et p2p_churn ; diversité conservée ; sync lag faible ; CPU/RAM normaux
- **Durée de l'anomalie** : Intermittent, sans tendance monotone
- **Surfaces affectées** : P2P uniquement
- **Preuves présentes** : Aucune autre surface en dérive ; diversité conservée
- **Preuves absentes** : Pas d'augmentation de p2p_sync_lag, pas de chute de diversité
- **Diagnostic attendu** : Anomalie bénigne (churn naturel) — voir FP_004

### SCN_BEN_RPC_001 — Bénin — requête RPC lourde
<!-- meta: scenario_id=SCN_BEN_RPC_001; category=scenario; attack_type=BENIGN; surface=RPC; label=benign; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Latence RPC élevée (ex. api_lat_getblock_ms) ; débit P2P, CPU, n_peers normaux
- **Durée de l'anomalie** : Ponctuelle, liée à la requête
- **Surfaces affectées** : RPC uniquement
- **Preuves présentes** : Aucune autre surface en dérive
- **Preuves absentes** : Pas de hausse du débit P2P, host_cpu_geth dans la norme
- **Diagnostic attendu** : Anomalie bénigne (charge applicative RPC) — voir FP_005

### SCN_BEN_SYNC_001 — Bénin — synchronisation initiale
<!-- meta: scenario_id=SCN_BEN_SYNC_001; category=scenario; attack_type=BENIGN; surface=P2P,SYSTEM,RPC; label=benign; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Débit entrant élevé ; CPU élevé ; api_is_syncing à 1 ; p2p_sync_lag élevé mais décroissant ; api_block progresse ; erreurs de protocole normales
- **Durée de l'anomalie** : Longue mais avec tendance décroissante du lag
- **Surfaces affectées** : P2P, SYSTEM, RPC
- **Preuves présentes** : Tendance décroissante du sync lag, progression d'api_block
- **Preuves absentes** : Pas de concentration d'IP sources, pas de p2p_log_error élevé
- **Diagnostic attendu** : Anomalie bénigne (Initial Sync) — voir FP_007 ; ne pas confondre avec DOS_001/DOS_002

### SCN_BEN_RESTART_001 — Bénin — redémarrage du nœud
<!-- meta: scenario_id=SCN_BEN_RESTART_001; category=scenario; attack_type=BENIGN; surface=P2P,RPC; label=benign; evidence_level=illustrative -->

- **Niveau de preuve** : illustrative
- **Métriques observées** : Chute puis remontée progressive de p2p_n_peers ; p2p_churn transitoire ; sync lag transitoire puis décroissant ; diversité rétablie
- **Durée de l'anomalie** : Transitoire (rétablissement progressif)
- **Surfaces affectées** : P2P et RPC
- **Preuves présentes** : Redémarrage récent + rétablissement de la diversité + sync lag décroissant
- **Preuves absentes** : Pas de diversité basse persistante, pas de sync lag croissant
- **Diagnostic attendu** : Anomalie bénigne (reconnexion normale) — voir FP_008

## 3. Gabarit pour ajouter un scénario mesuré

```
### SCN_<TYPE>_<NNN> — <titre>
<!-- meta: scenario_id=SCN_<TYPE>_<NNN>; category=scenario; attack_type=<ECLIPSE|DOS_P2P|BENIGN|NORMAL>; surface=<P2P,SYSTEM,RPC>; label=<attack|benign|normal>; evidence_level=<simulated|experimental> -->
- Niveau de preuve : experimental
- Run : <identifiant du run>, date <AAAA-MM-JJ>, configuration <voir 06>
- Métriques observées : <valeurs mesurées + unités + fenêtre>
- Durée de l'anomalie : <secondes ou nombre d'intervalles de 5 s>
- Surfaces affectées : <...>
- Preuves présentes : <...>
- Preuves absentes : <...>
- Diagnostic attendu : <...>
```
