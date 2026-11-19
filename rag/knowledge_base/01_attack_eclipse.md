# Eclipse Attack sur Ethereum — Playbook de détection

## 1. Définition et objectif de l'attaquant

Une **Eclipse Attack** vise à isoler un nœud Ethereum cible (victime) du reste du réseau P2P légitime en monopolisant **la totalité** de ses connexions entrantes et sortantes devp2p/RLPx avec des nœuds contrôlés par l'attaquant. Contrairement à un DoS, l'objectif n'est pas de rendre le nœud indisponible mais de **contrôler sa vue de la blockchain** : lui présenter une chaîne falsifiée, retarder la propagation de blocs/transactions légitimes, ou préparer un double-spend / une attaque par timestamp.

## 2. Mécanisme protocolaire

### 2.1 Empoisonnement de la table de routage Kademlia (DHT)
- Le client Ethereum (Geth, Erigon…) maintient une table de routage Kademlia (`k-buckets`) peuplée via le protocole de découverte RLPx Node Discovery (Discv4/Discv5).
- L'attaquant génère un grand nombre d'identifiants de nœuds (`Node ID`) proches des buckets ciblés et répond massivement aux requêtes `FINDNODE`/`PING` du nœud victime, remplissant progressivement sa table avec des entrées malveillantes.
- Au redémarrage du nœud (reboot, crash, mise à jour), la table de routage est reconstruite à partir des entrées en cache ou des bootnodes : c'est le moment de plus forte vulnérabilité, exploité par les implémentations pratiques récentes (cf. §6).

### 2.2 Monopolisation des connexions devp2p
- Un nœud Geth par défaut accepte un nombre limité de pairs (`maxpeers`, typiquement 25–50) répartis entre connexions **entrantes** et **sortantes**.
- L'attaquant :
  1. Sature les **slots sortants** en forçant la victime à ne découvrir et ne sélectionner que des pairs malveillants (via l'empoisonnement Kademlia).
  2. Sature les **slots entrants** en initiant lui-même un grand nombre de connexions TCP vers le port P2P de la victime (30303 par défaut) depuis des IP distinctes (Sybil), jusqu'à occuper tous les slots disponibles.
- Une fois les deux ensembles de slots occupés par l'attaquant, la victime n'a plus aucun chemin réseau vers un pair honnête.

### 2.3 Isolement de la vue de la blockchain
- Les pairs malveillants contrôlent désormais tout ce que la victime reçoit : propagation de blocs, de transactions (`eth` sous-protocole), et réponses à ses requêtes `GetBlockHeaders`/`GetBlockBodies`.
- L'attaquant peut alors retenir ou retarder sélectivement des blocs légitimes, ou injecter une vue divergente de la chaîne.

## 3. Signature comportementale multi-sources

### 3.1 Surface P2P (signal primaire)
| Indicateur | Comportement attendu en Eclipse Attack |
|---|---|
| `p2p_n_peers` | Chute marquée et durable (peer count drop) |
| `p2p_n_inbound` / `p2p_n_outbound` | Asymétrie anormale (ex. tous entrants ou tous sortants contrôlés) |
| Diversité des pairs (IP/sous-réseaux/Node ID) | Chute de la diversité — concentration sur peu de sous-réseaux ou d'ASN (peer diversity collapse) |
| `p2p_churn` (via `p2p_joined`/`p2p_left`) | Fort churn P2P : déconnexions/reconnexions rapides et répétées des mêmes plages d'IP |
| `p2p_tcp_established` / `p2p_tcp_syn_recv` | Nombre de connexions établies anormalement stable mais avec rotation rapide des pairs (remplacement continu) |
| `p2p_log_peer_search` | Hausse des logs "Looking for peers" / échecs de découverte malgré tentatives actives |

### 3.2 Surface Système & RPC (signal secondaire / discriminant)
| Indicateur | Comportement attendu |
|---|---|
| `p2p_sync_lag` | Augmentation progressive du retard de hauteur de bloc (sync lag) — absence de nouveaux blocs reçus |
| `api_block` | Stagnation ou progression anormalement lente de la hauteur de bloc locale |
| `api_is_syncing` | Peut basculer à 1 (resynchronisation) sans cause de charge visible |
| `host_cpu_geth`, `host_cpu_sys` | **Typiquement normal ou légèrement abaissé** (moins de traitement cryptographique car moins de trafic réel) — c'est le critère discriminant majeur vs. DoS P2P |
| `host_rss_geth_mb` | Stable ou légèrement en baisse |
| `api_lat_blocknumber_ms`, `api_lat_peercount_ms` | Latences RPC normales (le nœud répond vite car il n'est pas surchargé — seule la donnée retournée est obsolète) |

**Point clé de discrimination :** une Eclipse Attack produit une dégradation de la **qualité/fraîcheur de l'information** (pairs, sync) sans dégradation de la **capacité de calcul** du nœud. Un DoS P2P produit l'inverse (voir `02_attack_dos_p2p_flooding.md`).

## 4. Preuves observables indépendantes à vérifier obligatoirement

Avant de statuer, l'agent de corrélation doit vérifier au minimum :
1. La chute de `p2p_n_peers` est-elle corroborée par une chute de diversité des sous-réseaux/IP des pairs restants (pas seulement du nombre) ?
2. `p2p_sync_lag` augmente-t-il de façon monotone sur plusieurs intervalles consécutifs (pas un pic isolé) ?
3. `host_cpu_geth` et `host_cpu_sys` restent-ils dans leur plage normale pendant la même fenêtre temporelle (exclusion d'un DoS concomitant) ?
4. Y a-t-il un événement de redémarrage récent du nœud (fenêtre de vulnérabilité maximale de la table de routage) ?
5. Le `p2p_churn` est-il concentré sur un faible nombre de blocs CIDR/ASN source, ou dispersé (churn naturel) ?

## 5. Ancrage scientifique

- **Marcus, Heilman & Goldberg (2018)**, *"Low-Resource Eclipse Attacks on Ethereum's Peer-to-Peer Network"*, Cryptology ePrint Archive — démontrent la faisabilité de saturer les tables Kademlia d'Ethereum avec des ressources limitées, en exploitant les règles d'insertion dans les k-buckets.
- **Henningsen et al. (2019)**, *"Eclipsing Ethereum Peers with False Friends"* — exploitent le mécanisme de découverte de pairs pour forcer la sélection de pairs malveillants.
- **Wang et al. (arXiv:2601.16560, 2026)**, *"Eclipse Attacks on Ethereum's Peer-to-Peer Network"* — première implémentation pratique d'une Eclipse Attack **post-Merge** sur les nœuds de la couche exécution, exploitant la logique de bootstrap et de gestion des pairs au redémarrage pour isoler totalement un nœud ; divulgation responsable faite à l'équipe sécurité d'Ethereum.
- **Gomez Ramirez et al.**, *"Tikuna: An Ethereum Blockchain Network Security Monitoring System"* — système de détection par LSTM non supervisé sur les logs de découverte de pairs (client Prysm), validé sur mainnet.

> Note de correction : la référence initialement demandée *« Rehman et al. (2026) »* n'a pu être localisée dans aucune base indexée (arXiv, ACM, Google Scholar) lors de la vérification web du 2026-11-19. Elle n'est donc pas incluse ; les références ci-dessus, vérifiées, la remplacent.

## Checklist des preuves observables indépendantes (adaptée au banc local EVA-Guard)
- `[P2P]` Chute marquée de `p2p_n_peers` sur une fenêtre ≥ 3 intervalles consécutifs (≥ 15s)
- `[P2P]` Asymétrie anormale entre `p2p_n_inbound` et `p2p_n_outbound` (isolement sur les pairs de l'attaquant)
- `[P2P]` Pic initial de `p2p_left` / `p2p_churn` suivi d'une stabilisation sur un sous-ensemble isolé de pairs
- `[P2P]` Hausse de `p2p_log_peer_search` (logs "Looking for peers")
- `[SYSTEME]` `host_cpu_geth` et `host_cpu_sys` dans leur plage normale (absence de saturation)
- `[RPC]` Augmentation monotone de `p2p_sync_lag` (retard par rapport au nœud de référence `REF_RPC`)
- `[RPC]` Stagnation de `api_block` malgré des latences RPC (`api_lat_blocknumber_ms`, `api_lat_peercount_ms`) normales