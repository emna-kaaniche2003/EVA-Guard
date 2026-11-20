---
doc_id: 03_differential_diagnosis_false_positives
title: Guide de diagnostic différentiel et d'exclusion des faux positifs
category: false_positive
attack_type: BENIGN
surface: P2P,SYSTEM,RPC
label: benign
evidence_level: theoretical
target_agent: interpretation,confirmation
---

# Guide de diagnostic différentiel et d'exclusion des faux positifs

## 1. Principe directeur

Une dérive détectée par le modèle ML sur une **seule surface** (P2P seule, Système seule, ou RPC seule) est **insuffisante** pour confirmer une attaque. Elle doit être traitée par défaut comme une **anomalie bénigne potentielle** ou un **faux positif**, et formulée comme telle tant qu'aucune corroboration indépendante n'est trouvée sur une surface distincte.

## 2. Tableau des cas de faux positifs connus

| Cas | Symptôme ML observé | Signal absent (critère d'exclusion) | Diagnostic correct | Hypothèse à exclure |
|---|---|---|---|---|
| **A** | Pic isolé de `host_cpu_geth` / `host_rss_geth_mb` | Pas d'explosion de `p2p_in_kbps`/`p2p_out_kbps`, pas de chute de `p2p_n_peers` | Opération interne légitime : Garbage Collection (GC) du runtime Go, compaction de base de données (LevelDB/Pebble ancestry), validation d'un bloc exceptionnellement lourd (forte activité calldata/contrats) | **DoS par flooding P2P** |
| **B** | Fluctuation modérée de `p2p_n_peers` (`p2p_churn` modéré) | Pas d'augmentation de `p2p_sync_lag`, pas de chute de diversité des sous-réseaux/ASN | Churn P2P naturel du réseau Ethereum (rotation normale de pairs, redémarrages de pairs tiers, découverte continue) | **Eclipse Attack** |
| **C** | Hausse isolée de latence RPC (ex. `api_lat_getblock_ms`) | Pas de hausse de `p2p_in_kbps`/`p2p_out_kbps`, `host_cpu_geth` dans la norme | Requête locale lourde côté client RPC (ex. `eth_getLogs` sur une large plage de blocs, appel `debug_traceTransaction`) — charge applicative ponctuelle, pas réseau | **DoS par flooding P2P** (volet RPC collatéral) |
| **D** | Hausse brève (1 à 2 intervalles de 5s) de `api_lat_*`, `api_txpool_pending` et `host_cpu_geth` | Durée ≤ 10s, pas d'explosion de `p2p_tcp_syn_recv` ni de `p2p_log_error` | Rafale légitime de trafic applicatif (`traffic.py` profil `high` ou rafale `x2.5` de 10s) | **DoS par flooding P2P** |
| **E** | Trafic P2P élevé + CPU élevé + `p2p_sync_lag` élevé qui **décroît** | `p2p_log_error` normal, pas de concentration d'IP sources, `api_block` progresse | Synchronisation initiale (Initial Sync) ou rattrapage après arrêt | **DoS par flooding P2P** ; **Eclipse Attack** si le lag ne décroît pas |
| **F** | Changement brutal de `p2p_n_peers`/`p2p_churn` après arrêt/relance | `p2p_n_peers` se rétablit progressivement, diversité retrouvée, sync lag décroît | Redémarrage du nœud : reconnexion normale des pairs | **Eclipse Attack** (sauf si diversité basse persistante + sync lag croissant) |

## 3. Règles de décision pour l'agent d'interprétation (LLM)

1. **Règle de mono-source** : si un seul groupe de métriques (`[P2P]` *ou* `[SYSTEME]` *ou* `[RPC]`) présente une dérive significative, et que les deux autres groupes restent dans leurs plages normales sur la même fenêtre temporelle, l'hypothèse formulée doit être : **« Anomalie bénigne / Preuves insuffisantes pour confirmer une attaque »**.
2. **Règle de concomitance temporelle** : une corroboration n'est valable que si les signaux des différentes surfaces apparaissent dans une fenêtre temporelle cohérente (ex. quelques intervalles de collecte, pas des heures d'écart).
3. **Règle de non-confirmation unilatérale du LLM** : même en présence d'un signal fort sur une seule surface, le LLM formule uniquement une **hypothèse** avec son niveau de confiance et la liste des preuves manquantes ; il ne statue jamais CONFIRMÉE — ce rôle appartient exclusivement aux agents de corrélation/confirmation en aval.
4. **Règle de spécificité du diagnostic bénin** : chaque fois qu'un cas correspond au tableau ci-dessus (A à F), le LLM doit nommer explicitement le diagnostic bénin le plus probable plutôt que de simplement rejeter l'hypothèse d'attaque sans explication.
5. **Règle de non-renforcement du ML** : le LLM ne doit pas considérer la prédiction du modèle ML comme une preuve ; il doit toujours évaluer l'hypothèse alternative (bénin, autre attaque) avant de conclure.

## 4. Fiches détaillées par faux positif

### FP_001 — Garbage Collection du runtime Go
<!-- meta: scenario_id=FP_001; category=false_positive; attack_type=BENIGN; surface=SYSTEM; label=benign; evidence_level=theoretical -->

- **Symptômes** : pic bref de `host_cpu_geth` et/ou `host_rss_geth_mb`, souvent avec variation de mémoire (libération après le pic).
- **Signaux absents (exclusion DoS)** : `p2p_in_kbps`/`p2p_out_kbps` normaux, `p2p_tcp_syn_recv` normal, `p2p_n_peers` stable, pas d'erreurs `p2p_log_error`.
- **Durée typique** : courte, ne se répète pas de façon soutenue ; retour à la normale rapide.
- **Diagnostic bénin** : GC du runtime Go.
- **À vérifier** : le pic CPU/RAM est-il isolé (une seule surface) ? la mémoire redescend-elle ?

### FP_002 — Compaction de la base de données
<!-- meta: scenario_id=FP_002; category=false_positive; attack_type=BENIGN; surface=SYSTEM; label=benign; evidence_level=theoretical -->

- **Symptômes** : activité CPU et surtout disque élevée, parfois latence RPC en hausse légère.
- **Signaux absents (exclusion DoS)** : débit P2P normal, pas de hausse de connexions TCP, pas d'erreurs de protocole.
- **Limite** : le jeu de métriques actuel ne contient pas de mesure d'I/O disque ; la compaction ne se distingue donc que par l'**absence** de signal P2P. Une métrique d'I/O disque améliorerait ce diagnostic.
- **Diagnostic bénin** : maintenance de la base (LevelDB/Pebble).

### FP_003 — Validation d'un bloc lourd
<!-- meta: scenario_id=FP_003; category=false_positive; attack_type=BENIGN; surface=SYSTEM; label=benign; evidence_level=theoretical -->

- **Symptômes** : CPU élevé ponctuel lié à la validation d'un bloc exceptionnellement chargé (calldata/contrats).
- **Signaux absents** : pas de hausse durable du débit P2P, pas de concentration d'IP sources, un seul pic corrélé à l'arrivée d'un bloc.
- **Diagnostic bénin** : charge de validation.

### FP_004 — Churn P2P naturel
<!-- meta: scenario_id=FP_004; category=false_positive; attack_type=BENIGN; surface=P2P; label=benign; evidence_level=theoretical -->

- **Symptômes** : fluctuation modérée de `p2p_n_peers`, `p2p_churn` modéré, va-et-vient de pairs.
- **Signaux absents (exclusion Eclipse)** : `p2p_sync_lag` n'augmente pas, diversité des pairs conservée, churn dispersé sur de nombreuses plages IP/ASN.
- **Diagnostic bénin** : rotation normale des pairs, redémarrages de pairs tiers, découverte continue.

### FP_005 — Requête RPC lourde (charge applicative locale)
<!-- meta: scenario_id=FP_005; category=false_positive; attack_type=BENIGN; surface=RPC; label=benign; evidence_level=theoretical -->

- **Symptômes** : hausse isolée de latence RPC, notamment `api_lat_getblock_ms`.
- **Signaux absents (exclusion DoS)** : débit P2P normal, `host_cpu_geth` dans la norme, pas de baisse durable de `api_ok_ratio`.
- **Diagnostic bénin** : `eth_getLogs` sur large plage, `debug_traceTransaction`, autre requête applicative lourde.

### FP_006 — Rafale légitime de trafic applicatif
<!-- meta: scenario_id=FP_006; category=false_positive; attack_type=BENIGN; surface=RPC,SYSTEM; label=benign; evidence_level=theoretical -->

- **Symptômes** : hausse brève (1 à 2 intervalles de 5 s) de `api_lat_*`, `api_txpool_pending` et `host_cpu_geth`.
- **Signaux absents** : durée ≤ 10 s, pas d'explosion de `p2p_tcp_syn_recv` ni de `p2p_log_error`.
- **Diagnostic bénin** : profil `high` ou rafale `x2.5` de 10 s du générateur `traffic.py`.

### FP_007 — Synchronisation initiale (Initial Sync)
<!-- meta: scenario_id=FP_007; category=false_positive; attack_type=BENIGN; surface=P2P,SYSTEM,RPC; label=benign; evidence_level=theoretical -->

- **Symptômes** : trafic entrant élevé, CPU élevé, `api_is_syncing` à 1, `p2p_sync_lag` élevé — **plusieurs surfaces simultanément**, ce qui ressemble à un DoS.
- **Discriminants** : `p2p_sync_lag` **décroît** au fil du temps, `api_block` progresse, `p2p_log_error` normal, pas de concentration de sources `p2p_tcp_syn_recv`.
- **Piège** : ce cas est un faux positif *multi-surfaces* ; la règle de mono-source ne suffit pas. Il faut contrôler la **tendance** du sync lag et la progression de `api_block`.
- **Diagnostic bénin** : Initial Sync ou rattrapage.

### FP_008 — Redémarrage du nœud (reconnexion normale)
<!-- meta: scenario_id=FP_008; category=false_positive; attack_type=BENIGN; surface=P2P,RPC; label=benign; evidence_level=theoretical -->

- **Symptômes** : chute puis remontée de `p2p_n_peers`, `p2p_churn` élevé, `api_is_syncing` possible, `p2p_sync_lag` transitoirement élevé.
- **Discriminants** : le nombre de pairs se rétablit progressivement, la diversité des pairs est restaurée, le sync lag décroît.
- **Attention** : un redémarrage est aussi la fenêtre de vulnérabilité maximale d'une Eclipse Attack (`01_attack_eclipse.md`, §2.1). Si, après redémarrage, la diversité reste basse et le sync lag **croît** de façon monotone, ne pas conclure à un simple redémarrage.
- **Diagnostic bénin** : reconnexion normale après redémarrage.

## 5. Formulation attendue (gabarit de sortie du LLM)

```
Hypothèse : [Anomalie bénigne probable | Eclipse Attack (hypothèse) | DoS P2P (hypothèse)]
Surface(s) en dérive : [P2P | SYSTEME | RPC] (lister)
Surface(s) corroborante(s) attendue(s) et absente(s) : [...]
Diagnostic bénin le plus probable si applicable : [GC | compaction DB | bloc lourd | churn naturel | requête RPC lourde | rafale applicative | initial sync | redémarrage]
Hypothèse alternative évaluée : [...]
Niveau de confiance : [faible | moyen | fort]
Preuves manquantes à vérifier par l'agent de corrélation : [...]
```

## 6. Checklist des cas d'exclusion

- `[SYSTEME]` Pic CPU/RAM sans aucun signal `[P2P]` → exclure DoS P2P, évoquer GC/compaction/bloc lourd
- `[P2P]` Churn modéré sans `p2p_sync_lag` ni chute de diversité → exclure Eclipse Attack, évoquer churn naturel
- `[RPC]` Latence isolée sans signal `[P2P]`/`[SYSTEME]` → exclure DoS P2P, évoquer requête locale lourde
- `[P2P+SYSTEME+RPC]` Trafic + CPU + sync lag mais lag **décroissant** et `api_block` progresse → évoquer Initial Sync avant DoS
- `[P2P]` Variation de pairs juste après redémarrage avec diversité rétablie → évoquer reconnexion normale avant Eclipse
