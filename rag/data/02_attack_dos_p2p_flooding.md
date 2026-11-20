---
doc_id: 02_attack_dos_p2p_flooding
title: DoS par flooding P2P sur Ethereum — Playbook de détection
category: attack_playbook
attack_type: DOS_P2P
surface: P2P,SYSTEM,RPC
label: attack
evidence_level: theoretical
target_agent: interpretation,correlation
---

# DoS par flooding P2P sur Ethereum — Playbook de détection

## 1. Définition et objectif de l'attaquant

Le DoS par flooding P2P vise à **saturer les ressources de traitement réseau** d'un nœud Ethereum (sockets, CPU, mémoire, files de messages) en lui envoyant un volume massif de connexions et/ou de messages sur le canal RLPx et le sous-protocole `eth`, jusqu'à dégrader ou interrompre sa disponibilité. Contrairement à l'Eclipse Attack, l'objectif n'est pas la manipulation de la vue de la chaîne mais l'**épuisement de ressources**.

## 2. Mécanisme protocolaire

### 2.1 Saturation des canaux RLPx et du sous-protocole `eth`
- RLPx établit une session chiffrée/authentifiée par pair (handshake ECIES puis frames chiffrées). Chaque frame entrante doit être déchiffrée, désérialisée (RLP) puis dispatchée au sous-protocole concerné (`eth/66`, `eth/67`…).
- Deux vecteurs typiques :
  - **SYN flood / connexions TCP massives** vers le port P2P (ex. 30303/30302) : ouverture d'un grand nombre de connexions TCP (partielles ou complètes) pour épuiser les files d'attente de connexion et les sockets disponibles du processus Geth.
  - **Flooding applicatif** : envoi massif de messages RLPx (handshake répétés, frames malformées ou redondantes — annonces de blocs/transactions dupliquées, requêtes `GetBlockHeaders` en boucle) une fois la session établie, pour saturer les files de traitement internes et forcer une validation cryptographique/RLP répétée côté victime.

### 2.2 Épuisement des files de traitement et des sockets
- Chaque frame reçue consomme du CPU (déchiffrement, désérialisation RLP, validation de structure) et de la mémoire (buffers de réception, files d'attente de messages en attente de traitement).
- Un volume de messages dépassant la capacité de traitement du nœud entraîne un empilement des files internes, une hausse de la latence de traitement, puis des timeouts côté pairs légitimes (déconnexions en cascade) et côté clients RPC.

### 2.3 Formes de flooding (classification)

| Forme | Mécanisme | Signal le plus discriminant |
|---|---|---|
| **TCP SYN flooding** | Connexions TCP semi-ouvertes massives vers le port P2P | `p2p_tcp_syn_recv` en forte hausse, souvent concentré sur peu d'IP sources |
| **Connexions P2P massives** | Connexions TCP complètes + handshakes RLPx en grand nombre | `p2p_tcp_established` et `host_fds_geth` en hausse, `p2p_n_peers` saturé ou instable |
| **Flooding de messages applicatifs** | Frames `eth` redondantes ou lourdes (annonces dupliquées, requêtes en boucle) sur sessions établies | `p2p_in_kbps` et `host_cpu_geth` en hausse, `p2p_log_warn`/`p2p_log_error` en hausse |
| **Répétition excessive de handshakes** | Handshakes ECIES répétés (coûteux en CPU cryptographique) | `host_cpu_geth` élevé avec débit modéré, erreurs de handshake dans `p2p_log_error`, `p2p_tcp_time_wait` en hausse |

## 3. Signature comportementale multi-sources (cascade de dégradation)

### 3.0 Phases de dégradation (ordre typique)

1. **Augmentation du trafic entrant** : `p2p_in_kbps` monte en premier (parfois `p2p_out_kbps` ensuite).
2. **Augmentation du nombre de connexions** : `p2p_tcp_established`, `p2p_tcp_syn_recv`, `host_fds_geth`.
3. **Consommation CPU et RAM** : `host_cpu_geth`, `host_cpu_sys`, `host_rss_geth_mb`, `host_threads_geth`, `host_load1`.
4. **Augmentation de la latence RPC** : `api_lat_*` en hausse.
5. **Dégradation de la disponibilité** : `api_ok_ratio` en baisse, timeouts, déconnexions de pairs légitimes (`p2p_churn` par surcharge).

Toutes les phases ne sont pas toujours visibles à l'intervalle de collecte (5 s) ; une attaque courte ou faible peut s'arrêter aux phases 1-2. L'ordre sert à interpréter une observation **partielle** : P2P seul = début possible de cascade ou faux positif ; l'absence de toute phase ≥ 3 affaiblit fortement l'hypothèse DoS.

### 3.1 Surface P2P
| Indicateur | Comportement attendu en DoS P2P |
|---|---|
| `p2p_in_kbps` / `p2p_out_kbps` | Explosion du débit réseau entrant/sortant (bandwidth spike) |
| `p2p_tcp_established` / `p2p_tcp_syn_recv` | Forte hausse, en particulier `p2p_tcp_syn_recv` (connexions semi-ouvertes en file d'attente — signature SYN flood) |
| `p2p_tcp_time_wait` | Hausse si rotation rapide de connexions courtes |
| `p2p_log_warn` / `p2p_log_error` | Hausse des erreurs de protocole et des avertissements (frames invalides, handshakes échoués) |
| `p2p_churn` | Hausse du churn par timeouts/déconnexions forcées de pairs légitimes (surcharge), signature différente du churn ciblé de l'Eclipse Attack |

### 3.2 Surface Système
| Indicateur | Comportement attendu |
|---|---|
| `host_cpu_geth` | **Saturation marquée** (traitement cryptographique RLPx + validation RLP en continu) |
| `host_cpu_sys` | Hausse corrélée au niveau système |
| `host_rss_geth_mb` | Hausse de l'empreinte mémoire (buffers réseau, files de messages en attente) |
| `host_threads_geth` / `host_fds_geth` | Hausse (threads de traitement, descripteurs de fichiers/sockets ouverts) |
| `host_load1` | Hausse de la charge système (load average) |

### 3.3 Surface RPC (impact collatéral — pas de fiche dédiée)
| Indicateur | Comportement attendu |
|---|---|
| `api_lat_blocknumber_ms`, `api_lat_peercount_ms`, `api_lat_getblock_ms`, `api_lat_peers_ms` | Hausse généralisée de la latence des réponses RPC (le processus Geth est occupé par le traitement P2P) |
| `api_ok_ratio` | Baisse (timeouts/erreurs RPC en hausse) |
| `api_is_syncing` | Peut passer à 1 si le traitement des blocs entrants est retardé |

**Point clé de discrimination :** le DoS P2P produit une dégradation **conjointe** débit réseau + CPU + mémoire + latence RPC. L'Eclipse Attack ne produit **aucune** saturation CPU/mémoire (voir `01_attack_eclipse.md`, §3.2).

### 3.4 Distinctions importantes (ce qui n'est pas forcément un DoS)

- **Un pic de trafic sans augmentation du CPU ne constitue pas nécessairement un DoS** : gros bloc légitime, rafale de transactions, synchronisation de pairs.
- **Une hausse de CPU sans hausse du trafic P2P n'est pas un DoS P2P** : GC, compaction de base, validation de bloc lourd (voir `03_differential_diagnosis_false_positives.md`).
- **Une latence RPC isolée n'est pas un DoS P2P** : requête locale lourde (`eth_getLogs` large, `debug_traceTransaction`).
- Un DoS qui provoque des déconnexions de pairs peut **réduire `p2p_n_peers` et faire croître `p2p_sync_lag`** comme une Eclipse : le discriminant reste la saturation CPU/mémoire et le débit entrant, présents en DoS, absents en Eclipse.

## 4. Preuves observables indépendantes à vérifier obligatoirement

1. La hausse de `p2p_in_kbps`/`p2p_out_kbps` est-elle concomitante (même fenêtre temporelle) avec une hausse de `host_cpu_geth` ?
2. `host_rss_geth_mb` progresse-t-il en parallèle (exclusion d'un simple pic de débit sans impact mémoire, ex. gros bloc légitime unique) ?
3. La dégradation RPC (`api_lat_*`, `api_ok_ratio`) est-elle simultanée à la saturation P2P/Système, ou isolée (voir fiche diagnostic différentiel, Cas C) ?
4. `p2p_tcp_syn_recv` élevé provient-il d'un nombre restreint d'IP sources (flood ciblé) ou dispersé (trafic légitime en pic) ?
5. `p2p_log_error`/`p2p_log_warn` montrent-ils des erreurs de protocole typiques d'un flooding (frames malformées, handshakes répétés) plutôt que des erreurs applicatives classiques ?

## 5. Checklist des preuves observables indépendantes

- `[P2P]` Explosion simultanée de `p2p_in_kbps` et `p2p_out_kbps`
- `[P2P]` Hausse marquée de `p2p_tcp_syn_recv` concentrée sur peu d'IP sources
- `[P2P]` Hausse de `p2p_log_warn`/`p2p_log_error` (erreurs de protocole)
- `[P2P]` Hausse anormale de `p2p_churn` par déconnexions forcées (timeouts pairs légitimes)
- `[SYSTEME]` Saturation de `host_cpu_geth` et `host_cpu_sys`
- `[SYSTEME]` Hausse de `host_rss_geth_mb`, `host_threads_geth`, `host_fds_geth`
- `[SYSTEME]` Hausse de `host_load1`
- `[RPC]` Hausse généralisée de `api_lat_blocknumber_ms`/`api_lat_peercount_ms`/`api_lat_getblock_ms`/`api_lat_peers_ms`
- `[RPC]` Baisse de `api_ok_ratio` (timeouts/erreurs)
