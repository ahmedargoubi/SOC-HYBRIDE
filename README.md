# Hybrid Enterprise Cybersecurity Architecture with AI-Assisted SOC Triage

> Architecture de cybersécurité hybride (on-premise + AWS) : un réseau d'entreprise segmenté par OPNsense, un SOC centralisé dans le cloud, et un agent IA qui assiste le triage des alertes. Projet universitaire TEK-UP, équipe de 3 étudiants.

> **État du dépôt :** ce dépôt documente pour l'instant la **fondation on-premise** (segmentation, règles de pare-feu, MFA, Active Directory, Velociraptor). Les éléments en cours ou prévus sont listés dans la section [Avancement](#-avancement). Rien n'est présenté comme terminé s'il n'a pas été configuré et testé.

---

## 🎯 Objectif du projet

**La motivation première de ce projet est de concevoir et construire une architecture de sécurité d'entreprise réelle — segmentation, détection, investigation, triage — pas uniquement de "faire des simulations d'attaque".** Les scénarios d'attaque ne sont pas le but du projet : ce sont des outils de validation, utilisés pour vérifier que l'architecture construite se comporte comme prévu.

Il s'agit d'un seul SOC hybride intégré, et non de trois projets séparés. Le travail se déroule dans cet ordre. On construit d'abord la fondation on-premise : segmentation OPNsense, Active Directory, MFA et collecte DFIR avec Velociraptor. On ajoute ensuite la détection, avec un IDS réseau (Snort), un SIEM/XDR (Wazuh) et un honeypot dans le cloud. Les alertes sont ensuite centralisées dans un SOC cloud sur AWS (Wazuh, TheHive, Cortex, MISP), relié à l'on-premise par un VPN, avec un agent IA optionnel qui assiste le triage sans jamais prendre d'action lui-même. Enfin, on valide l'ensemble avec des attaques autorisées depuis Kali Linux, dans le lab uniquement.

La méthode est Scrum sur 70 jours : un Sprint 0 suivi de 5 sprints de 2 semaines. Les principes directeurs sont le moindre privilège, la défense en profondeur, la segmentation par zone de confiance et la sécurité dès la conception.

---

## 🏗️ Architecture

L'hyperviseur est VMware Workstation. Le pare-feu central est OPNsense 26.7, avec 5 interfaces réseau, une par zone, en deny-by-default. Le cloud est AWS (us-east-1), avec un VPC `hybrid-soc-vpc` en `10.20.0.0/16`.

Le **Security LAN** (`192.168.9.0/24`, interface em1, passerelle `192.168.9.1`) est le cœur des outils SOC et sécurité. Il héberge Security-Core (`192.168.9.115`, avec le serveur Velociraptor) et la Management Workstation. Le **Server LAN** (`192.168.7.0/24`, em2, passerelle `192.168.7.1`) héberge les serveurs internes, c'est-à-dire l'AD-DC (`192.168.7.122`, domaine `TEKUP.local`). Le **User LAN** (`192.168.8.0/24`, em3, passerelle `192.168.8.1`) accueille les postes utilisateurs, des clients Windows 10. Le **Target LAN** (`192.168.11.0/24`, em4, passerelle `192.168.11.1`) contient la machine Ubuntu volontairement vulnérable, cible des attaques ; son rôle de DMZ est prévu mais la décision est en attente. Enfin, le réseau **WAN / Attacker** (`192.168.163.0/24`, em0, en DHCP, via le NAT VMware) héberge Kali Linux (`192.168.163.164`) côté attaquant. Le DHCP est assuré par Dnsmasq sur chaque LAN, avec une plage de `.100` à `.200`.

Côté cloud, le sous-réseau privé **security-a** (`10.20.3.0/24`) accueillera le Wazuh manager, TheHive, Cortex, MISP et l'agent IA optionnel. Le sous-réseau **honeypot-a** (`10.20.4.0/24`) accueillera un honeypot exposé, sans agent, dont les logs partent en syslog à sens unique vers Wazuh.

### Topologie complète

![Architecture](architecture.png)

📄 Détails : [`docs/architecture-overview.md`](docs/architecture-overview.md) · [`docs/network-topology.md`](docs/network-topology.md)

---

## 🛠️ Stack de sécurité

**OPNsense** assure le pare-feu, la segmentation, le DHCP et l'extrémité du VPN, dans une VM VMware à 5 interfaces. **Active Directory** fournit l'identité avec le domaine `TEKUP.local`, hébergé sur l'AD-DC `192.168.7.122`. **Velociraptor** assure la collecte DFIR sur les endpoints : le serveur est installé nativement sur Security-Core, avec l'interface web sur le port `8889` et les agents sur le port `8000`.

**Snort 3** joue le rôle de NIDS réseau, en détection passive uniquement (pas d'IPS). Il tourne sur Security-Core, avec une interface d'écoute sans adresse IP pour chaque segment surveillé. **Wazuh** est le SIEM/XDR : le manager sera dans le cloud (`security-a`) et les agents sur les machines surveillées. **TheHive, Cortex et MISP** apportent la gestion de cas, l'enrichissement des observables et la threat intelligence, également dans `security-a`. Un **agent IA de triage** optionnel assiste l'analyste en lecture seule et ne prend aucune action. Un **honeypot** dans `honeypot-a` collecte l'activité malveillante externe.

**Kali Linux** sert aux simulations d'attaque autorisées depuis le réseau WAN. Pour le **MFA**, deux mécanismes sont utilisés : le TOTP natif d'OPNsense pour l'interface d'administration, et PAM Google Authenticator pour le SSH de Security-Core.

📄 Guides d'installation et de configuration détaillés : [`config/`](config/)

---

## 🎭 Les rôles du projet

Un seul SOC, sept angles de travail sur la même architecture :

- 🔵 **SOC Analyst** — Wazuh, TheHive, Cortex : détection, triage, gestion de cas.
- 🏛️ **Security Architect** — conception de l'architecture hybride et de la segmentation.
- 🟡 **CTI** — MISP, MITRE ATT&CK, honeypot, VirusTotal, OSINT.
- 🟢 **DFIR** — Velociraptor, SANS SIFT : collecte et investigation sur les endpoints.
- ⚪ **GRC** — AWS Config, cartographie risques/contrôles, NIST CSF.
- 🔴 **Red Teamer** — Kali, reconnaissance OSINT, simulation d'attaques autorisées.
- 🌐 **Network Security** — OPNsense, Snort, Wireshark, Security Groups, NACLs.

---

## 🔐 Politique d'accès réseau (règles confirmées)

OPNsense applique **deny-by-default** sur toute interface sans règle explicite. Aucune règle "allow any" n'est utilisée sur les interfaces OPT.

| Alias | Type | Contenu |
|---|---|---|
| `AD_DC` | Hôte | `192.168.7.122` |
| `AD_Ports` | Ports | `53, 88, 123, 135, 389, 445, 464, 636, 3268, 3269, 49152:65535` |

| Interface | Action | Protocole | Source | Destination | Ports | Objectif |
|---|---|---|---|---|---|---|
| OPT2 (User LAN) | Pass | TCP/UDP | OPT2 net | `AD_DC` | `AD_Ports` | Jonction au domaine et authentification |

📄 Détails : [`config/opnsense-aliases-and-rules.md`](config/opnsense-aliases-and-rules.md)

---

## 🔧 Avancement

| Élément | Statut | Détails |
|---|---|---|
| Interfaces OPNsense, segmentation, DHCP | ✅ Terminé | [`config/opnsense-interfaces-segmentation.md`](config/opnsense-interfaces-segmentation.md) |
| Aliases et règle AD (User LAN → AD-DC) | ✅ Terminé | [`config/opnsense-aliases-and-rules.md`](config/opnsense-aliases-and-rules.md) |
| Active Directory (`TEKUP.local`) | ✅ Terminé | [`config/active-directory.md`](config/active-directory.md) |
| Jonction du client Windows 10 au domaine | ⏳ En cours | [`config/domain-join-client.md`](config/domain-join-client.md) |
| Velociraptor — serveur (Security-Core) | ✅ Terminé (serveur actif) | [`config/velociraptor.md`](config/velociraptor.md) — agents à déployer |
| MFA — OPNsense (GUI admin) | ⚠️ Documenté, application non confirmée | [`config/opnsense-mfa.md`](config/opnsense-mfa.md) |
| MFA — SSH (Security-Core) | ⚠️ Documenté, application non confirmée | [`config/security-core-ssh-mfa.md`](config/security-core-ssh-mfa.md) |
| Snort NIDS | ⏳ En cours | Interfaces d'écoute préparées, Snort non installé |
| Target LAN en DMZ et ses règles | 📅 À venir | |
| VPN site-à-site vers AWS | 📅 À venir | |
| Fondation AWS (VPC, sous-réseaux, routage, NAT, flow logs) | ✅ Terminé | |
| SOC cloud (Wazuh, TheHive, Cortex, MISP) et honeypot | 📅 À venir | |
| Agent IA de triage | 📅 À venir (optionnel) | |
| Simulations d'attaque | 📅 À venir | |

⚠️ **Point GRC à noter :** le MFA n'est pas centralisé. Deux mécanismes distincts selon le point d'accès (TOTP natif OPNsense, PAM Google Authenticator pour SSH). Compromis assumé, avec la centralisation (par exemple privacyIDEA) en amélioration future.

---

## 🎬 Scénarios d'attaque prévus

| # | Scénario | Zone cible |
|---|---|---|
| 1 | Attaque web locale contre la machine Ubuntu (T1190), détectée par Snort et Wazuh | Target LAN |
| 2 | Mouvement latéral interne, investigué avec Velociraptor | Réseaux internes |
| 3 | Reconnaissance et brute force externes contre le honeypot cloud | Cloud |

Tous les tests sont réalisés uniquement sur ce lab, avec autorisation.

---

## 🧭 Principes de conception

La **segmentation par zone de confiance** est le premier principe : chaque zone a sa propre interface OPNsense et rien n'est autorisé par défaut. Il s'appuie sur le **moindre privilège** : les règles sont étroites, écrites avec des alias d'hôtes et de ports, et aucune règle "allow any" n'est utilisée sur les zones OPT. La **détection est passive** : Snort fonctionne en IDS seulement, avec des interfaces d'écoute sans adresse IP, donc invisibles et inatteignables depuis les LAN surveillés. Le projet est aussi **honnête sur ses écarts** : les éléments non confirmés sont marqués comme tels dans les guides. Enfin, **aucun secret n'est stocké dans le dépôt** : mots de passe, graines TOTP, codes de récupération et clés privées ne sont jamais commités.

---

## 🗺️ Structure du dépôt

À la racine se trouve ce `README.md`. Le dossier `docs/` contient la vue d'ensemble de l'architecture (`architecture-overview.md`), la topologie réseau (`network-topology.md`) et les principes de sécurité (`security-principles.md`). Le dossier `config/` contient un guide par sujet : `opnsense-interfaces-segmentation.md`, `opnsense-aliases-and-rules.md`, `opnsense-mfa.md`, `security-core-ssh-mfa.md`, `velociraptor.md`, `active-directory.md` et `domain-join-client.md`. Le schéma d'architecture se trouve dans `network/diagrams/architecture.png`, et les captures d'écran de chaque guide sont rangées dans `images/<nom-du-guide>/`, sous la forme `NN-nom-court.png`.

---

## 👥 Équipe

| Membre | Rôle |
|---|---|
| `<nom>` | `<rôle>` |
| `<nom>` | `<rôle>` |
| `<nom>` | `<rôle>` |

---

## 📖 Comment lire les guides

Chaque guide suit la même structure : prérequis, étapes avec captures, tests de vérification, erreurs courantes, liste des preuves. Les captures sont rangées dans `images/<nom-du-guide>/`.
