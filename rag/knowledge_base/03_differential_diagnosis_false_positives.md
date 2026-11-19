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
## 3. Règles de décision pour l'agent d'interprétation (LLM)

1. **Règle de mono-source** : si un seul groupe de métriques (`[P2P]` *ou* `[SYSTEME]` *ou* `[RPC]`) présente une dérive significative, et que les deux autres groupes restent dans leurs plages normales sur la même fenêtre temporelle, l'hypothèse formulée doit être : **« Anomalie bénigne / Preuves insuffisantes pour confirmer une attaque »**.
2. **Règle de concomitance temporelle** : une corroboration n'est valable que si les signaux des différentes surfaces apparaissent dans une fenêtre temporelle cohérente (ex. quelques intervalles de collecte, pas des heures d'écart).
3. **Règle de non-confirmation unilatérale du LLM** : même en présence d'un signal fort sur une seule surface, le LLM formule uniquement une **hypothèse** avec son niveau de confiance et la liste des preuves manquantes ; il ne statue jamais CONFIRMÉE — ce rôle appartient exclusivement aux agents de corrélation/confirmation en aval.
4. **Règle de spécificité du diagnostic bénin** : chaque fois qu'un cas correspond au tableau ci-dessus (A, B ou C), le LLM doit nommer explicitement le diagnostic bénin le plus probable plutôt que de simplement rejeter l'hypothèse d'attaque sans explication.

## 4. Formulation attendue (gabarit de sortie du LLM)

```
Hypothèse : [Anomalie bénigne probable | Eclipse Attack (hypothèse) | DoS P2P (hypothèse)]
Surface(s) en dérive : [P2P | SYSTEME | RPC] (lister)
Surface(s) corroborante(s) attendue(s) et absente(s) : [...]
Diagnostic bénin le plus probable si applicable : [GC/compaction DB | churn naturel | requête RPC lourde]
Niveau de confiance : [faible | moyen | fort]
Preuves manquantes à vérifier par l'agent de corrélation : [...]
```

## Checklist des cas d'exclusion

- `[SYSTEME]` Pic CPU/RAM sans aucun signal `[P2P]` → exclure DoS P2P, évoquer GC/compaction/bloc lourd
- `[P2P]` Churn modéré sans `p2p_sync_lag` ni chute de diversité → exclure Eclipse Attack, évoquer churn naturel
- `[RPC]` Latence isolée sans signal `[P2P]`/`[SYSTEME]` → exclure DoS P2P, évoquer requête locale lourde