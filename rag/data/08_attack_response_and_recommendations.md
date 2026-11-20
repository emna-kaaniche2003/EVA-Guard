---
doc_id: 08_attack_response_and_recommendations
title: Recommandations et réponse aux attaques détectées
category: recommendations
attack_type: GENERIC
surface: P2P,SYSTEM,RPC
label: neutral
evidence_level: theoretical
target_agent: restitution
---

# Recommandations et réponse aux attaques détectées

## 0. Portée

Ces recommandations sont **défensives** et destinées à l'agent de restitution pour produire des rapports explicables. Les noms d'options de configuration cités (Geth, iptables, sysctl) sont à **valider sur la version et l'environnement du banc** avant toute application. Une hypothèse non confirmée appelle des **vérifications**, pas des mesures de blocage.

## 1. Eclipse Attack

### 1.1 Niveau de gravité et risques
<!-- meta: attack_type=ECLIPSE; label=attack -->
Gravité potentielle **élevée** si confirmée (vue de la chaîne contrôlée par l'attaquant : retard ou falsification de blocs et transactions, double-spend, attaque par timestamp). Gravité **faible à moyenne** tant que l'hypothèse n'est qu'une dérive P2P.

### 1.2 Vérifications supplémentaires
<!-- meta: attack_type=ECLIPSE; label=attack -->
- Vérifier la diversité des pairs (IP, sous-réseaux, ASN, Node ID) et la répartition inbound/outbound.
- Comparer la hauteur de bloc locale à celle de `REF_RPC` et suivre la tendance du `p2p_sync_lag`.
- Vérifier la présence d'un redémarrage récent et la concentration du churn par plage CIDR/ASN.
- Consulter les logs de recherche de pairs et les sources de découverte.

### 1.3 Actions préventives
<!-- meta: attack_type=ECLIPSE; label=attack -->
- Maintenir un ensemble de pairs de confiance (pairs statiques/de confiance) et surveiller leur présence.
- Surveiller de près les redémarrages (fenêtre de vulnérabilité de la table de routage).
- Limiter le nombre de pairs par sous-réseau/IP si le client le permet.
- Utiliser `REF_RPC` ou une source de comparaison indépendante pour détecter un retard.

## 2. DoS P2P

### 2.1 Niveau de gravité et risques
<!-- meta: attack_type=DOS_P2P; label=attack -->
Gravité **élevée** pour la disponibilité si confirmée (saturation CPU/RAM, latence RPC, déconnexions). Gravité **faible** si la dérive est limitée à une surface.

### 2.2 Vérifications supplémentaires
<!-- meta: attack_type=DOS_P2P; label=attack -->
- Vérifier les connexions TCP (états SYN_RECV, ESTABLISHED, TIME_WAIT) et la concentration des IP sources.
- Vérifier les ressources système (CPU, RAM, descripteurs de fichiers, threads, load).
- Examiner les erreurs de protocole dans les logs (frames invalides, handshakes répétés).
- Vérifier la corrélation temporelle entre débit entrant, CPU et latence RPC.

### 2.3 Actions préventives
<!-- meta: attack_type=DOS_P2P; label=attack -->
- Règles de limitation de connexions et de débit au niveau pare-feu pour le port P2P (par exemple limitation par IP source).
- Activation de protections TCP contre le SYN flood (par exemple SYN cookies).
- Limites sur le nombre de pairs et de connexions en attente configurables dans le client.
- Supervision des seuils de CPU/RAM/descripteurs.

## 3. Anomalie bénigne

### 3.1 Recommandations
<!-- meta: attack_type=BENIGN; label=benign -->
- Continuer le monitoring et observer l'évolution des métriques sur plusieurs intervalles.
- Nommer le diagnostic bénin le plus probable (GC, compaction, bloc lourd, churn naturel, requête RPC lourde, rafale applicative, synchronisation initiale, redémarrage).
- Définir ce qui ferait changer d'avis : apparition d'une seconde surface en dérive, tendance monotone du sync lag, concentration des sources.
- Ne déclencher aucune mesure de blocage sur un signal mono-surface.

## 4. Tableau de synthèse

<!-- meta: attack_type=GENERIC -->

| Situation | Gravité | Action immédiate | Vérification prioritaire |
|---|---|---|---|
| Eclipse (hypothèse) | Moyenne à élevée | Surveiller, ne pas bloquer sans confirmation | Diversité des pairs, tendance du sync lag |
| DoS P2P (hypothèse) | Moyenne à élevée | Surveiller, préparer limitation de connexions | Concentration IP sources, erreurs de protocole |
| Anomalie bénigne | Faible | Continuer le monitoring | Apparition d'une seconde surface |
| Signaux contradictoires | Indéterminée | Demander une analyse supplémentaire | Concomitance temporelle, indépendance des preuves |

## 5. Gabarit de rapport explicable

<!-- meta: attack_type=GENERIC -->

```
Résumé : hypothèse + niveau de confiance
Preuves observées : [liste par surface]
Preuves absentes : [liste]
Diagnostic alternatif évalué : [...]
Gravité potentielle : [faible | moyenne | élevée]
Vérifications recommandées : [...]
Actions préventives : [...]
Statut : hypothèse — confirmation réservée à l'agent de confirmation
```
