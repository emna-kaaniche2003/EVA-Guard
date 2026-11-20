---
doc_id: 05_ethereum_metrics_dictionary
title: Dictionnaire des métriques EVA-Guard
category: metrics_dictionary
attack_type: GENERIC
surface: P2P,SYSTEM,RPC
label: neutral
evidence_level: theoretical
target_agent: interpretation,correlation
---

# Dictionnaire des métriques EVA-Guard

## 0. Avertissement de fidélité (à lire en premier)

Les **noms** de métriques proviennent des playbooks 01-03. Les **unités**, **méthodes de collecte** et **plages normales** ci-dessous sont des *hypothèses raisonnables* : chaque champ marqué `[À VÉRIFIER dans le collecteur]` doit être comparé au code réel du collecteur EVA-Guard et corrigé. Les définitions et méthodes de collecte doivent correspondre exactement au système de monitoring.

Intervalle de collecte indiqué dans les playbooks : 5 s. Le nœud de référence est `REF_RPC`.

La **diversité des pairs** (IP, sous-réseaux, ASN, Node ID) n'est pas une métrique de cette liste : c'est une caractéristique dérivée dont la méthode de calcul est à documenter dans le système de monitoring.

## 1. Fiches de métriques

### p2p_n_peers
<!-- meta: metric=p2p_n_peers; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_n_peers`
- **Surface** : P2P
- **Définition** : Nombre de pairs devp2p connectés au nœud à l'instant de la mesure.
- **Unité** : pairs (entier)
- **Méthode de collecte** : Probablement via l'API admin (liste de pairs) ou net_peerCount. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Stable autour d'une valeur proche de la configuration `maxpeers` ; fluctuations modérées.
- **Causes de hausse/baisse** : Baisse : redémarrage, perte réseau, churn, Eclipse (durable), DoS (déconnexions par surcharge). Hausse : fin de synchronisation, reconnexion, ouverture de slots.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse (signal primaire, chute durable) ; DoS (indirect).

### p2p_n_inbound
<!-- meta: metric=p2p_n_inbound; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_n_inbound`
- **Surface** : P2P
- **Définition** : Nombre de pairs connectés dont la connexion a été initiée par le pair distant.
- **Unité** : pairs
- **Méthode de collecte** : Dérivé de la liste de pairs (sens de connexion). [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Proportion équilibrée avec les sortants selon la configuration.
- **Causes de hausse/baisse** : Déséquilibre : Eclipse (slots occupés par l'attaquant), pare-feu/NAT, réseau privé.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse (asymétrie inbound/outbound).

### p2p_n_outbound
<!-- meta: metric=p2p_n_outbound; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_n_outbound`
- **Surface** : P2P
- **Définition** : Nombre de pairs connectés dont la connexion a été initiée par le nœud.
- **Unité** : pairs
- **Méthode de collecte** : Dérivé de la liste de pairs. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Proportion équilibrée avec les entrants.
- **Causes de hausse/baisse** : Chute : découverte défaillante, Eclipse via poisoning de la table de routage.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse.

### p2p_joined
<!-- meta: metric=p2p_joined; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_joined`
- **Surface** : P2P
- **Définition** : Nombre de pairs ajoutés pendant l'intervalle de collecte.
- **Unité** : pairs / intervalle
- **Méthode de collecte** : Différence entre deux listes de pairs consécutives. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible et régulier.
- **Causes de hausse/baisse** : Hausse : redémarrage, découverte, rotation ; rafales : Eclipse (remplacement par pairs malveillants) ou DoS.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse, DoS.

### p2p_left
<!-- meta: metric=p2p_left; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_left`
- **Surface** : P2P
- **Définition** : Nombre de pairs retirés pendant l'intervalle de collecte.
- **Unité** : pairs / intervalle
- **Méthode de collecte** : Différence entre deux listes de pairs consécutives. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible et régulier.
- **Causes de hausse/baisse** : Hausse : churn, timeouts de surcharge (DoS), expulsion par l'attaquant (Eclipse), redémarrage de pairs.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse (pic initial), DoS (déconnexions forcées).

### p2p_churn
<!-- meta: metric=p2p_churn; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_churn`
- **Surface** : P2P
- **Définition** : Fréquence de changement de composition des pairs (arrivées + départs) sur l'intervalle.
- **Unité** : pairs / intervalle (ou ratio)
- **Méthode de collecte** : Probablement dérivé de p2p_joined et p2p_left. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Modéré, dispersé sur de nombreuses sources.
- **Causes de hausse/baisse** : Hausse : churn naturel, redémarrage, Eclipse (churn concentré sur peu de plages IP), DoS (churn par surcharge). Le churn ne discrimine pas seul : examiner la concentration des sources et la surface Système.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse (concentré), DoS (par surcharge) ; faux positif fréquent (churn naturel).

### p2p_in_kbps
<!-- meta: metric=p2p_in_kbps; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_in_kbps`
- **Surface** : P2P
- **Définition** : Débit réseau entrant du trafic P2P.
- **Unité** : kbit/s
- **Méthode de collecte** : Mesure du trafic de l'interface/processus sur le port P2P. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Modéré avec pics à l'arrivée des blocs.
- **Causes de hausse/baisse** : Hausse : gros bloc, synchronisation, rafale de transactions, DoS. Baisse : Eclipse (moins de trafic réel) ou perte de pairs.
- **Attaques pour lesquelles elle contribue à la détection** : DoS (signal primaire) ; Initial Sync (faux positif).

### p2p_out_kbps
<!-- meta: metric=p2p_out_kbps; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_out_kbps`
- **Surface** : P2P
- **Définition** : Débit réseau sortant du trafic P2P.
- **Unité** : kbit/s
- **Méthode de collecte** : Mesure du trafic de l'interface/processus sur le port P2P. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Modéré.
- **Causes de hausse/baisse** : Hausse : réponses aux requêtes de pairs, DoS.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### p2p_tcp_established
<!-- meta: metric=p2p_tcp_established; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_tcp_established`
- **Surface** : P2P
- **Définition** : Nombre de connexions TCP à l'état ESTABLISHED sur le port P2P.
- **Unité** : connexions
- **Méthode de collecte** : Comptage des sockets TCP (ex. outil système ss). [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Proche du nombre de pairs.
- **Causes de hausse/baisse** : Hausse : connexions massives (DoS), pairs nombreux. Stable avec rotation rapide : Eclipse.
- **Attaques pour lesquelles elle contribue à la détection** : DoS, Eclipse.

### p2p_tcp_syn_recv
<!-- meta: metric=p2p_tcp_syn_recv; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_tcp_syn_recv`
- **Surface** : P2P
- **Définition** : Nombre de connexions TCP à l'état SYN_RECV (semi-ouvertes) sur le port P2P.
- **Unité** : connexions
- **Méthode de collecte** : Comptage des sockets TCP. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Proche de zéro.
- **Causes de hausse/baisse** : Hausse : SYN flood. Origine : peu d'IP sources → flood ciblé ; dispersée → pic légitime.
- **Attaques pour lesquelles elle contribue à la détection** : DoS (signature SYN flood).

### p2p_tcp_time_wait
<!-- meta: metric=p2p_tcp_time_wait; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_tcp_time_wait`
- **Surface** : P2P
- **Définition** : Nombre de connexions TCP à l'état TIME_WAIT sur le port P2P.
- **Unité** : connexions
- **Méthode de collecte** : Comptage des sockets TCP. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible à modéré.
- **Causes de hausse/baisse** : Hausse : rotation rapide de connexions courtes (DoS, handshakes répétés).
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### p2p_log_peer_search
<!-- meta: metric=p2p_log_peer_search; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_log_peer_search`
- **Surface** : P2P
- **Définition** : Nombre de lignes de log de type recherche de pairs (ex. « Looking for peers ») sur l'intervalle.
- **Unité** : lignes / intervalle
- **Méthode de collecte** : Comptage de motifs dans les logs de Geth. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible une fois les pairs trouvés.
- **Causes de hausse/baisse** : Hausse : découverte difficile (Eclipse, perte réseau, redémarrage).
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse.

### p2p_log_warn
<!-- meta: metric=p2p_log_warn; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_log_warn`
- **Surface** : P2P
- **Définition** : Nombre de lignes de log de niveau WARN sur l'intervalle.
- **Unité** : lignes / intervalle
- **Méthode de collecte** : Comptage de logs. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible.
- **Causes de hausse/baisse** : Hausse : frames invalides, handshakes échoués (DoS), problèmes divers.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### p2p_log_error
<!-- meta: metric=p2p_log_error; category=metrics_dictionary; attack_type=GENERIC; surface=P2P; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_log_error`
- **Surface** : P2P
- **Définition** : Nombre de lignes de log de niveau ERROR sur l'intervalle.
- **Unité** : lignes / intervalle
- **Méthode de collecte** : Comptage de logs. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Quasi nul.
- **Causes de hausse/baisse** : Hausse : erreurs de protocole (DoS), pannes locales.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### p2p_sync_lag
<!-- meta: metric=p2p_sync_lag; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `p2p_sync_lag`
- **Surface** : RPC (calculé par rapport à REF_RPC) — surface à confirmer selon l'implémentation
- **Définition** : Retard de hauteur de bloc du nœud surveillé par rapport au nœud de référence REF_RPC.
- **Unité** : blocs (à confirmer)
- **Méthode de collecte** : Différence entre la hauteur de REF_RPC et celle du nœud surveillé. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible (0 à quelques blocs).
- **Causes de hausse/baisse** : Hausse : Eclipse (croissance monotone), Initial Sync (décroissante), redémarrage (transitoire), surcharge. La **tendance** est plus informative que la valeur.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse (preuve secondaire majeure) ; faux positifs Initial Sync / redémarrage.

### api_block
<!-- meta: metric=api_block; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_block`
- **Surface** : RPC
- **Définition** : Hauteur de bloc locale renvoyée par le nœud.
- **Unité** : numéro de bloc
- **Méthode de collecte** : Appel RPC eth_blockNumber. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Croît régulièrement avec la chaîne.
- **Causes de hausse/baisse** : Stagnation : Eclipse, nœud bloqué. Progression rapide : synchronisation.
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse.

### api_is_syncing
<!-- meta: metric=api_is_syncing; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_is_syncing`
- **Surface** : RPC
- **Définition** : Indicateur de synchronisation en cours du nœud.
- **Unité** : 0/1
- **Méthode de collecte** : Appel RPC eth_syncing converti en booléen. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : 0 en régime permanent.
- **Causes de hausse/baisse** : Passe à 1 : synchronisation initiale, redémarrage, retard de traitement (DoS), resynchronisation (Eclipse).
- **Attaques pour lesquelles elle contribue à la détection** : Eclipse, DoS ; faux positifs Initial Sync/redémarrage.

### api_lat_blocknumber_ms
<!-- meta: metric=api_lat_blocknumber_ms; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_lat_blocknumber_ms`
- **Surface** : RPC
- **Définition** : Latence de la requête RPC eth_blockNumber.
- **Unité** : ms
- **Méthode de collecte** : Temps de réponse mesuré par le collecteur. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible et stable.
- **Causes de hausse/baisse** : Hausse généralisée : DoS (CPU saturé). Normale pendant une Eclipse (le nœud répond vite mais avec une donnée obsolète).
- **Attaques pour lesquelles elle contribue à la détection** : DoS (impact collatéral) ; discriminant négatif pour Eclipse.

### api_lat_peercount_ms
<!-- meta: metric=api_lat_peercount_ms; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_lat_peercount_ms`
- **Surface** : RPC
- **Définition** : Latence de la requête RPC de nombre de pairs.
- **Unité** : ms
- **Méthode de collecte** : Temps de réponse mesuré par le collecteur. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible et stable.
- **Causes de hausse/baisse** : Hausse : DoS. Normale en Eclipse.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### api_lat_getblock_ms
<!-- meta: metric=api_lat_getblock_ms; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_lat_getblock_ms`
- **Surface** : RPC
- **Définition** : Latence de la requête RPC de lecture de bloc.
- **Unité** : ms
- **Méthode de collecte** : Temps de réponse mesuré par le collecteur. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible à modérée.
- **Causes de hausse/baisse** : Hausse isolée : requête locale lourde (faux positif). Hausse conjointe avec CPU/P2P : DoS.
- **Attaques pour lesquelles elle contribue à la détection** : DoS ; faux positif RPC lourd.

### api_lat_peers_ms
<!-- meta: metric=api_lat_peers_ms; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_lat_peers_ms`
- **Surface** : RPC
- **Définition** : Latence de la requête RPC de liste des pairs.
- **Unité** : ms
- **Méthode de collecte** : Temps de réponse mesuré par le collecteur. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible, croît avec le nombre de pairs.
- **Causes de hausse/baisse** : Hausse : DoS ou nombre de pairs élevé.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### api_ok_ratio
<!-- meta: metric=api_ok_ratio; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_ok_ratio`
- **Surface** : RPC
- **Définition** : Proportion de requêtes RPC réussies sur l'intervalle.
- **Unité** : ratio 0–1 (ou %) — à confirmer
- **Méthode de collecte** : Succès/total des requêtes du collecteur. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Proche de 1.
- **Causes de hausse/baisse** : Baisse : timeouts/erreurs RPC par surcharge (DoS), arrêt du nœud.
- **Attaques pour lesquelles elle contribue à la détection** : DoS (dégradation de disponibilité).

### api_txpool_pending
<!-- meta: metric=api_txpool_pending; category=metrics_dictionary; attack_type=GENERIC; surface=RPC; label=neutral; evidence_level=theoretical -->

- **Nom** : `api_txpool_pending`
- **Surface** : RPC
- **Définition** : Nombre de transactions en attente dans la txpool.
- **Unité** : transactions
- **Méthode de collecte** : Appel RPC de statut de la txpool. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Dépend de la charge applicative.
- **Causes de hausse/baisse** : Hausse : rafale légitime (traffic.py profil high), congestion.
- **Attaques pour lesquelles elle contribue à la détection** : Faux positif (rafale applicative) ; indice de charge légitime.

### host_cpu_geth
<!-- meta: metric=host_cpu_geth; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_cpu_geth`
- **Surface** : SYSTEM
- **Définition** : Utilisation CPU du processus Geth.
- **Unité** : % (base à confirmer : % d'un cœur ou % total)
- **Méthode de collecte** : Mesure du processus Geth (ex. psutil). [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Modéré, pics lors du traitement des blocs.
- **Causes de hausse/baisse** : Hausse : DoS (saturation), GC, compaction, bloc lourd, synchronisation. Normale ou basse : Eclipse.
- **Attaques pour lesquelles elle contribue à la détection** : DoS (signal primaire) ; critère discriminant Eclipse vs DoS.

### host_cpu_sys
<!-- meta: metric=host_cpu_sys; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_cpu_sys`
- **Surface** : SYSTEM
- **Définition** : Utilisation CPU au niveau système.
- **Unité** : %
- **Méthode de collecte** : Mesure globale de la machine. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Modérée.
- **Causes de hausse/baisse** : Hausse corrélée : DoS ; hausse due à d'autres processus de la machine : faux positif.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### host_rss_geth_mb
<!-- meta: metric=host_rss_geth_mb; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_rss_geth_mb`
- **Surface** : SYSTEM
- **Définition** : Mémoire résidente (RSS) du processus Geth.
- **Unité** : Mo
- **Méthode de collecte** : Mesure du processus Geth. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Stable ou croissance lente.
- **Causes de hausse/baisse** : Hausse : DoS (buffers/files), synchronisation, cache. Pic variable : GC.
- **Attaques pour lesquelles elle contribue à la détection** : DoS ; faux positif GC.

### host_threads_geth
<!-- meta: metric=host_threads_geth; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_threads_geth`
- **Surface** : SYSTEM
- **Définition** : Nombre de threads du processus Geth.
- **Unité** : threads
- **Méthode de collecte** : Mesure du processus Geth. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Stable.
- **Causes de hausse/baisse** : Hausse : charge de traitement P2P (DoS).
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### host_fds_geth
<!-- meta: metric=host_fds_geth; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_fds_geth`
- **Surface** : SYSTEM
- **Définition** : Nombre de descripteurs de fichiers/sockets ouverts par Geth.
- **Unité** : descripteurs
- **Méthode de collecte** : Mesure du processus Geth. [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Stable.
- **Causes de hausse/baisse** : Hausse : connexions massives (DoS), ouverture de fichiers de base.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.

### host_load1
<!-- meta: metric=host_load1; category=metrics_dictionary; attack_type=GENERIC; surface=SYSTEM; label=neutral; evidence_level=theoretical -->

- **Nom** : `host_load1`
- **Surface** : SYSTEM
- **Définition** : Charge moyenne du système sur 1 minute (load average).
- **Unité** : sans unité (charge)
- **Méthode de collecte** : Mesure système (load average 1 min). [À VÉRIFIER dans le collecteur]
- **Comportement normal** : Faible à modérée selon le nombre de cœurs.
- **Causes de hausse/baisse** : Hausse : DoS, autres processus de la machine.
- **Attaques pour lesquelles elle contribue à la détection** : DoS.
