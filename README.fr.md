<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.it.md">Italiano</a> ·
  <a href="README.pt-br.md">Português (BR)</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <img src="docs/logo.png" alt="InfraFence" width="200">
</p>

<h3 align="center">Stoppez l'attaque. Corrigez ce qui l'a laissée entrer.</h3>

<p align="center">
  InfraFence bloque les attaques contre vos serveurs Linux au moment où elles arrivent, en entrée comme en sortie. Puis il durcit la configuration, applique les correctifs, vérifie le résultat et annule toute correction qui casse quelque chose.<br>
  Force brute SSH, attaques web, bots, malwares, menaces DNS et sortantes, intégrité des fichiers, Docker — avec des réglages sûrs par défaut, piloté depuis un seul tableau de bord.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com/fr/">Site web</a> ·
  <a href="https://infrafence.com/fr/pricing">Tarifs</a> ·
  <a href="https://infrafence.com/fr/documentation">Documentation</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Tickets</a>
</p>

---

## Pourquoi InfraFence

- **Il voit ce qui sort du serveur.** Il signale les connexions sortantes vers des IP malveillantes connues et lit chaque requête DNS au niveau des paquets, rattachée au programme qui l'a faite : tunnels DNS et domaines aléatoires (DGA) arrivent avec le nom du processus et son pid.
- **Il sait qui était connecté.** Chaque session SSH reçoit un score de risque de 0 à 100, qui monte si le WAF, l'intégrité des fichiers, les malwares, un scan de ports, le trafic sortant ou le DNS se déclenchent pendant qu'elle est ouverte.
- **Des corrections qui ne cassent pas la production.** Après chaque changement (fermeture d'un port, blocage du trafic sortant, correctif de durcissement, patch virtuel), il vérifie SSH et les sites surveillés, et annule le changement s'ils ne répondent plus.
- **Une IA qui n'agit que dans des limites fixes.** AutoMode choisit dans un catalogue fixe d'actions, n'exécute jamais ses propres commandes et ne bloque jamais vos propres adresses ni vos connexions SSH. Les actions qui ne sont pas automatiques (par exemple fermer un port MySQL ou PostgreSQL qui n'est pas attaqué, certaines corrections PHP, un patch virtuel hors de la règle automatique) attendent une approbation dans le tableau de bord, et seul un propriétaire ou un administrateur connecté avec l'authentification à deux facteurs peut en décider. [Ce qui demande votre approbation](https://infrafence.com/fr/documentation/automode#what-needs-your-approval)

Starter est gratuit pour un serveur, offres payantes à partir de 8,90 € par serveur et par mois : [voir les tarifs](https://infrafence.com/fr/pricing).

## Démarrage rapide

Créez un jeton d'installation dans le tableau de bord (Serveurs → Ajouter un serveur), puis sur le serveur, en root :

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Vous voulez d'abord voir ce qu'il ferait ? Ajoutez `--dry-run` (sans token) : il télécharge l'agent, vérifie le serveur en lecture seule, affiche le plan et ne modifie rien.

> **[Obtenez votre jeton sur infrafence.com](https://infrafence.com/add-server)** — l'offre Starter est gratuite et inclut 1 serveur avec protection complète.

---

## Ce qu'il détecte

### SSH et force brute
15 motifs de détection dans le log SSH : mauvais mots de passe, utilisateurs inexistants, échecs PAM, scans avant authentification, incompatibilités de protocole, échanges de clés interrompus. Les attaquants sont bannis au niveau du pare-feu pour des durées croissantes — 24 heures, 7 jours, 30 jours, puis définitivement — ou pour la durée choisie dans le tableau de bord.

### Web Application Firewall
Lit les logs d'accès de vos serveurs web et attribue un score à chaque IP visiteuse :

| Type d'attaque | Score | Mode |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Par score |
| UA de scanner (sqlmap, nikto, nmap, nuclei…) | +50 | Par score |
| Injection SQL / SSRF / Exploits web | +40 | Par score |
| Piège honeypot (chemins leurres définis comme règles personnalisées) | +40 | Par score |
| Path traversal / Injection d'en-têtes | +30 | Par score |
| Force brute WordPress | +30 | Seuil (10 requêtes / 2 min) |
| XSS / Recherche de `.env` / XMLRPC | +25 | Par score |
| Recherche de fichiers de configuration | +20 | Par score |
| Rafale de 404 | +15 | Seuil (15 requêtes / 5 min) |

Le score baisse de 5 points par minute. Niveaux d'action : **observer** (30) → **ralentir** (60) → **bloquer** (80) → **bannissement pare-feu** (100). Dans le tableau de bord, vous voyez chaque règle intégrée, modifiez poids, seuils et mode par type, désactivez des motifs précis et ajoutez vos propres règles (URL, User-Agent ou Referer, texte ou regex). Chaque version publie le catalogue des règles intégrées sous forme de `waf-catalog.json`.

### Gestion des bots
Environ 1 500 bots connus, issus de listes publiques mises à jour chaque jour ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), toutes deux sous MIT) — moteurs de recherche, crawlers d'IA, outils SEO, scanners, supervision, aperçus de liens et plus. Les faux bots de moteurs de recherche sont démasqués par DNS inverse. Pour chaque catégorie, ou bot précis, choisissez dans le tableau de bord : **autoriser**, **journaliser seulement** ou **bloquer**. Les bots bloqués sont bannis au pare-feu ; si vous autorisez les modifications du serveur web, ils sont aussi refusés par nginx/Apache.

### Scanner de malwares
- **Analyse par signatures** — 28 motifs intégrés pour web shells, backdoors, mineurs de cryptomonnaie et kits de phishing
- **Moteur YARA** — règles communautaires contre les menaces web issues de [YARA Forge](https://github.com/YARAHQ/yara-forge), mises à jour chaque jour, uniquement depuis des sources dont la licence autorise l'usage commercial (signature-base, ReversingLabs). Nécessite l'outil `yara`, installable en un clic depuis le tableau de bord
- **Chaque détection** explique pourquoi elle a été signalée, sa gravité et le SHA-256 du fichier, avec des liens pour le vérifier dans les bases publiques de malwares
- **Reconnaissance des frameworks** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Contrôles de sécurité des frameworks** — `.env` exposé, mode DEBUG, APP_KEY, permissions trop ouvertes, Telescope, wp-config
- **Heuristiques** — entropie de Shannon, anomalies de date dans les dossiers d'upload
- **Intégrité du système** — binaires système modifiés (`dpkg -V` / `rpm -Va`), indicateurs de rootkit
- **Analyse des identifiants** — fichiers `.env` exposés, permissions des clés SSH, `.git` dans le dossier web, identifiants cloud
- **Analyse de la base WordPress** — scripts injectés dans les articles et options, administrateurs non autorisés
- **Détection des processus** — mineurs en cours d'exécution, reverse shells, scripts suspects lancés depuis `/tmp`
- **Quarantaine et ignorer** — en un clic, déplacez un fichier malveillant vers `/var/lib/infrafence/quarantine/` (restaurable) ou marquez un faux positif, que les analyses suivantes ignorent
- **Analyses planifiées** toutes les 3, 6, 12 ou 24 heures, plus « Analyser maintenant » depuis le tableau de bord
- **Contrôle en temps réel** — vérifie toutes les 30 secondes les dossiers d'upload à la recherche de nouveaux fichiers PHP

### WAF en ligne ModSecurity (optionnel)
- Uniquement si vous autorisez les modifications du serveur web dans les réglages du tableau de bord — désactivé par défaut
- Jamais sur les serveurs dont la configuration est gérée par un panneau d'hébergement ou un outil de gestion de configuration
- Pour Apache avec mod_security2 : 13 règles (injection SQL, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, blocage des scanners), blocage dès la première requête
- Sûr : si le test de configuration d'Apache échoue, la modification est annulée

### Menaces sortantes et DNS
- **Connexions sortantes** vers des IP figurant dans des listes publiques de threat intelligence, téléchargées par chaque serveur une fois par jour (réseaux connus pour avoir été détournés, liste des hôtes compromis d'Emerging Threats)
- **Inspection DNS** — chaque requête et réponse DNS est lue au niveau des paquets (UDP 53, lecture seule, avec un filtre exécuté dans le noyau) et rattachée au programme qui l'a émise : requêtes vers des serveurs DNS inattendus ou malveillants, domaines pointant vers des IP malveillantes connues, tunnels DNS et malwares qui génèrent des domaines aléatoires (DGA)
- Le service DNS du serveur et les requêtes des antivirus et antispam sont reconnus et non signalés
- Le blocage en entrée des réseaux listés est désactivé par défaut et s'active depuis le tableau de bord (nécessite `ipset`)

### Intégrité des fichiers et persistance
Empreintes SHA-256 de référence, avec alerte à chaque modification :
- Fichiers système essentiels — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Tâches planifiées — `/etc/crontab`, `/etc/cron.d/*`, crontabs de chaque utilisateur
- Persistance SSH — `authorized_keys` de root et de chaque utilisateur dans `/home/*`
- `/etc/ld.so.preload` et unités systemd (`/etc/systemd/system/*.service`, `*.timer`)

### Risque des sessions SSH
Suit chaque session SSH du début à la fin — méthode d'authentification, réputation de l'IP source, heure de connexion, commandes privilégiées (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — et lui attribue un score de 0 à 100 à sa fermeture. **Corrélation Sigma** : si un autre détecteur (WAF, intégrité, malware, scan de ports, sortant, DNS) se déclenche pendant qu'une session est ouverte, le risque de cette session augmente.

### Et aussi
- **Mail, bases de données et FTP** — détection de force brute pour Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD et vsftpd
- **Compatible Docker** — trouve les logs des conteneurs web et protège les ports publiés (`DOCKER-USER`)
- **Blocage par pays** depuis le tableau de bord (nécessite `ipset`). L'agent télécharge la base des pays depuis votre tableau de bord ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0) uniquement tant qu'un pays est bloqué, au plus une fois par jour. La liste autorisée, les adresses du serveur lui-même et les sessions SSH authentifiées au moment du blocage d'un pays ne sont jamais bloquées (une connexion qui tente encore de s'authentifier, comme une attaque par force brute, ne compte pas). [Blocage par pays](https://infrafence.com/fr/documentation/blocage-par-pays)
- **Panneaux d'hébergement reconnus** (24, par ex. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) et **LiteSpeed / OpenLiteSpeed** — InfraFence ne modifie jamais une configuration gérée par un panneau ou par LiteSpeed
- **Mode surveillance** — détecte tout, ne bloque rien
- **Métriques système** — CPU, mémoire, disque et réseau

---

## Au-delà de la détection

Ce qu'InfraFence ajoute aux détecteurs ci-dessus, chacun avec sa page dans la [documentation](https://infrafence.com/fr/documentation) :

- **Durcissement, vulnérabilités et score de sécurité** — une quarantaine de contrôles de durcissement, avec correction en un clic pour ceux qui sont sûrs ; les vulnérabilités connues (CVE) des paquets installés par risque réel : d'abord celles déjà exploitées (CISA KEV), puis par probabilité d'exploitation (EPSS) ; un score de sécurité de 0 à 100. Les contrôles SSH lisent la configuration que sshd utilise réellement (`sshd -T`, ou les fichiers dans l'ordre de sshd) et indiquent le fichier et la ligne qui fixent chaque valeur : un fichier de `sshd_config.d`, comme `50-cloud-init.conf` de cloud-init, l'emporte sur `sshd_config`. Les corrections SSH ne modifient jamais `sshd_config` : elles vont dans un fichier lu en premier et sont annulées si sshd utilise encore une autre valeur. [Durcissement et vulnérabilités](https://infrafence.com/fr/documentation/durcissement-et-vulnerabilites)
- **Durcissement de PHP** — repère les paramètres PHP risqués dans chaque runtime et pool, et corrige ceux qui sont sûrs. Les correctifs vont dans un fichier qui appartient à InfraFence (`zz-infrafence-hardening.ini`), sont vérifiés et annulés si un site cesse de répondre ; `cgi.fix_pathinfo` et `disable_functions` demandent une approbation. L'agent surveille aussi la configuration de PHP et signale une valeur risquée dès qu'elle apparaît. C'est du durcissement et de la surveillance de configuration : rien n'est chargé dans PHP, et ce n'est pas une protection qui tourne à l'intérieur de vos applications. [Durcissement de PHP](https://infrafence.com/fr/documentation/durcissement-et-vulnerabilites#php-hardening)
- **Fermer les ports exposés, bloquer les destinations dangereuses** (Pro · AutoMode) — chaque changement est vérifié et annulé s'il casse quelque chose. Le trafic sortant n'est jamais bloqué vers une adresse connectée en SSH avec une session authentifiée ; une connexion SSH non authentifiée ne protège personne. Une destination avec laquelle le serveur communique régulièrement (3 des 7 derniers jours, comme l'API d'un client) n'est jamais bloquée automatiquement lorsqu'elle apparaît dans une liste de menaces : le blocage attend votre approbation. [Ports et blocage sortant](https://infrafence.com/fr/documentation/ports-et-blocage-sortant)
- **Correctifs virtuels pour les vulnérabilités exploitées** (Pro · AutoMode) — une règle ModSecurity ciblée protège le logiciel vulnérable jusqu'à ce que vous installiez la mise à jour ; Apache avec ModSecurity. [Correctifs virtuels](https://infrafence.com/fr/documentation/correctifs-virtuels)
- **Mode urgence** — un bouton rouge : pendant 24 heures, InfraFence répond seul à l'attaque, avec le même catalogue sûr et les mêmes limites qu'AutoMode (à partir de Basic). [Mode urgence](https://infrafence.com/fr/documentation/mode-urgence)
- **Alertes** par e-mail, Slack, Discord, Telegram ou webhook, plus un résumé hebdomadaire par e-mail. [Alertes](https://infrafence.com/fr/documentation/alertes)
- **Analyse par IA** — une analyse instantanée de chaque incident sur toutes les offres, calculée dans le tableau de bord ; une analyse par IA avec des corrections sûres en un clic à partir de Pro. [Événements et activité](https://infrafence.com/fr/documentation/evenements-et-activite)
- **Réseau InfraFence et carte des attaques** — partage facultatif : les adresses qui attaquent plusieurs clients sont signalées, et les chiffres du réseau ne s'affichent que là où 3 organisations ou plus ont contribué. [Le réseau InfraFence](https://infrafence.com/fr/documentation/reseau-infrafence) · [Carte des attaques](https://infrafence.com/fr/documentation/carte-des-attaques)
- **Badge de surveillance** — le badge « Surveillé par InfraFence » renvoie vers une page de transparence publique avec l'heure de la dernière vérification, les attaques bloquées ces 30 derniers jours et les protections actives. Pour prouver que le domaine est servi par votre serveur, l'agent place un fichier de vérification, `/.well-known/infrafence-verification.txt`, à la racine du site, et le supprime quand le badge est désactivé. Ce n'est pas un certificat. [Badge de surveillance](https://infrafence.com/fr/features#trust-badge) · [Voir un exemple de page de transparence](https://infrafence.com/fr/trust/demo)
- **Protection même quand le tableau de bord est injoignable** — les bannissements, la liste blanche et les blocages par pays restent en vigueur, les nouvelles attaques sont toujours bannies et les événements attendent dans une file. [Quand le tableau de bord est injoignable](https://infrafence.com/fr/documentation/tableau-de-bord-injoignable)
- **À côté de CSF et des autres outils** — InfraFence s'en tient à ses propres chaînes et ne modifie jamais les fichiers de CSF ni les règles d'un autre outil ; après un `csf -r`, il remet ses propres règles en quelques secondes. [Coexistence avec d'autres outils de sécurité](https://infrafence.com/fr/documentation/coexistence)
- **Plugin pour cPanel & WHM** (disponible) **et extension pour Plesk** (en développement), inclus dans les offres Basic, Pro et AutoMode — état de la protection, bannissements, détections, événements et analyses par site dans le panneau. [cPanel & WHM](https://infrafence.com/fr/integrations/cpanel-whm) · [Panneaux d'hébergement](https://infrafence.com/fr/documentation/panneaux-d-hebergement) · [Plugin WHM](https://infrafence.com/fr/documentation/plugin-whm)

---

## Sûr sur les serveurs de production

- **Vérifie avant de modifier** — `infrafence-agent preflight` est une vérification du serveur en lecture seule (pare-feu et autres outils de sécurité, serveurs web, panneaux d'hébergement, gestion de configuration, opérations sur les paquets, ressources). L'installateur la lance avant toute modification ; l'agent, au démarrage et chaque jour.
- **Réglages prudents par défaut** — les modifications du serveur web et le blocage en entrée par listes de menaces restent désactivés jusqu'à ce que vous les activiez ; les mises à jour de l'agent sont sur « Prévenir seulement » jusqu'à ce que vous choisissiez l'installation automatique, et seules des versions signées avec cosign sont installées.
- **Chaînes de pare-feu dédiées** — chaque règle vit dans les chaînes `INFRAFENCE` de l'agent, appelées depuis `INPUT` (et `DOCKER-USER`), reconstruites de façon atomique et restaurées automatiquement en quelques secondes si un autre outil (ufw, firewalld, CSF) les supprime. Vos règles existantes ne sont jamais modifiées. Les IP en liste blanche sont exemptées, jamais ouvertes.
- **Désinstallation propre** — supprime l'agent et tout ce qu'il a ajouté : chaînes de pare-feu, modifications du serveur web, le service.

---

## Fonctionnement

```
SSH, web, mail, database and FTP logs · DNS packets · connections · files
    │
    ▼
Detectors (per log line, per packet, periodic scans)
    │
    ▼
Per-IP scoring (web) / thresholds (SSH, mail, DB, FTP)
    │
    ▼
Ban → ipset "infrafence-bans" in the INFRAFENCE chain
      (without ipset: one rule per IP in the chain, up to 500)
    │
    └──► event and ban reported to the dashboard (HTTPS)

Dashboard changes (settings, bans, whitelist, rules, scans)
    └──► pushed to the agent in about a second (real-time channel),
         checked on every heartbeat (60 s), full sync every 5 minutes
```

L'agent **ne bannit jamais** les IP réservées ou privées, les adresses du serveur lui-même, l'adresse du tableau de bord ou les IP en liste blanche — même si on le lui demande.

---

## Installation

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Option | Effet |
|---|---|
| `--dry-run` | Vérifie le serveur et affiche le plan ; ne modifie rien. Pas besoin de token |
| `--no-ipset` | N'installe pas `ipset` (les bannissements fonctionnent toujours, jusqu'à 500 ; le blocage par pays et par listes de menaces en a besoin) |
| `--skip-checksum` | **Dangereux.** Installe même quand la somme de contrôle de la release ne peut pas être téléchargée (le binaire n'est pas vérifié). Uniquement pour un réseau qui bloque le fichier `.sha256` et rien d'autre |
| `--uninstall` | Supprime l'agent et tout ce qu'il a ajouté |

L'agent est téléchargé uniquement depuis GitHub Releases, et l'installateur s'arrête si la somme de contrôle de la version manque ou ne correspond pas. Le certificat racine de Let's Encrypt dont il peut avoir besoin (ISRG Root X1) est intégré au script, avec une empreinte fixée, au lieu d'être téléchargé. [Ce que fait l'installateur](https://infrafence.com/fr/documentation/ce-que-fait-l-installateur)

**Prérequis :** x86-64 ou ARM64, accès root, `iptables` ; systemd, upstart ou sysvinit. L'installateur utilise `apt`, `dnf` ou `yum` pour les dépendances manquantes et n'installe `ipset` que lorsque la vérification du serveur indique que c'est sans risque.

**Testé avant chaque version** sur 15 distributions : Ubuntu 20.04, 22.04, 24.04 et 26.04, Debian 12 et 13, Rocky Linux 8 et 9, AlmaLinux 8 et 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 et 42, Amazon Linux 2023. Sur chacune, le vrai installateur s'exécute, détecte une attaque par force brute SSH, la bannit au pare-feu et se désinstalle proprement. Les autres distributions des familles Debian et RHEL fonctionnent en général : lancez d'abord l'installateur avec `--dry-run`. Voir [Distributions prises en charge](https://infrafence.com/fr/documentation/distributions-prises-en-charge).

### Docker

```bash
docker run -d --name infrafence-agent --restart unless-stopped \
  --privileged --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrafence-config:/etc/infrafence \
  -e INFRAFENCE_TOKEN=<YOUR_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest
```

Image multi-architecture (amd64 + arm64) publiée à chaque version. Une stack pour Docker Swarm se trouve dans [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Kubernetes

Créez une clé de cluster dans le tableau de bord (Paramètres → Kubernetes), puis :

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Chaque nœud s'enregistre comme un serveur. Toutes les valeurs, les mises à jour et GitOps : [Kubernetes](https://infrafence.com/fr/documentation/kubernetes) dans la documentation, et le [README du chart](charts/infrafence-agent/README.md).

### Désinstallation

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

Presque tout se règle depuis le tableau de bord et arrive sur les serveurs en une seconde environ : seuils de force brute, durée des bannissements, mode surveillance, règles WAF, choix sur les bots, liste blanche, pays bloqués, planification des analyses de malwares, inspection DNS, modifications du serveur web, blocage par listes de menaces, mises à jour automatiques. Référence complète : [Configuration](https://infrafence.com/fr/documentation/configuration).

Sur le serveur :

| Variable d'environnement | Effet |
|---|---|
| `AUTH_LOG_PATH` | Fichier de log SSH à lire à la place du journal systemd (par défaut : le journal sur les systèmes avec systemd, sinon `/var/log/auth.log` ou `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs d'accès web, séparés par des virgules (par défaut : détectés depuis nginx, Apache, LiteSpeed, panneaux, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Remplacent les logs mail, base de données et FTP détectés |
| `MODSEC_AUDIT_LOG` | Log d'audit ModSecurity |
| `GEOIP_DB_PATH` | Base des pays (format MaxMind DB) à utiliser à la place de celle téléchargée depuis le tableau de bord dans `/etc/infrafence/geoip-country.mmdb` ; si elle est définie, rien n'est téléchargé |
| `INFRAFENCE_CONFIG` | Fichier de configuration de l'agent (par défaut `/etc/infrafence/config.json`) |

Définissez-les avec `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), puis redémarrez le service.

**Labels Docker** sur vos conteneurs : `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (chemins sur l'hôte), `infrafence.domain` (domaines).

**Commandes :** `infrafence-agent preflight [--json]` (vérification du serveur en lecture seule), `infrafence-agent version` (version installée), `infrafence-agent check`, `infrafence-agent uninstall --clean`. Toutes les commandes : [Référence des commandes](https://infrafence.com/fr/documentation/reference-des-commandes).

**Panneaux d'hébergement (cPanel/WHM, Plesk) :** les plugins des panneaux exécutent `infrafence-agent panel <command> --json` en root et lisent un objet JSON sur stdout (`{"ok": true, ...}` ou `{"ok": false, "error": "<code>", "message": "..."}`, code de sortie 0 seulement si ok). Commandes : `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score` ; celles qui modifient quelque chose exigent `--actor <utilisateur du panneau>` et sont remontées au tableau de bord comme événements de source `panel`. La commande parle à l'agent en cours d'exécution via `/run/infrafence/panel.sock` (root uniquement, mode 0600, aucun port réseau) ; sans agent en cours d'exécution, elle répond quand même, avec `"agent_running": false`. Les plugins sont inclus dans les offres Basic, Pro et AutoMode (agent 1.0.34 ou plus récent) : `status` répond toujours, avec `"entitled"` et `"entitlement"` (`ok`, `plan_required`, `unpaid`, `unknown`) ; toute autre commande ne répond que cette erreur, sans aucune donnée, quand l'organisation n'y a pas droit (une offre sans les plugins, la protection désactivée après 24 heures de refus, ou une offre pas encore connue). L'offre de la dernière synchronisation réussie est conservée entre les redémarrages : une panne du tableau de bord ne vide pas le plugin. `map` (les attaques contre ce serveur par pays et par catégorie) et `score` (son score de sécurité et sa tendance sur 30 jours) viennent du tableau de bord, demandent l'agent 1.0.33 ou plus récent et sont mis en cache par l'agent : au plus une requête toutes les 5 minutes pour la carte et toutes les 15 minutes pour le score, avec `"stale": true` quand le tableau de bord est injoignable. Tous les champs de chaque réponse : [docs/panel-json.md](docs/panel-json.md) (en anglais).

**Ouvert ou résolu :** chaque événement de problème que l'agent remonte (un port de base de données exposé, un fichier système modifié, un réglage PHP risqué, un malware...) porte `details.subject` (`port:tcp/3306`, `file:/etc/passwd`...). Depuis la 1.0.34, `panel events` et `panel findings` indiquent si chaque problème est encore `open` ou `resolved` (`subject`, `state`, `resolved_at`, `resolved_how`) : résolu dans le tableau de bord, ou corrigé par l'agent lui-même (un port fermé par son pare-feu, un correctif appliqué et vérifié, un fichier mis en quarantaine, un paquet mis à jour). Un port de base de données que le pare-feu de l'agent ferme n'est plus signalé comme exposé au redémarrage de l'agent. Détails : [docs/panel-json.md](docs/panel-json.md#problems-and-resolution) (en anglais).

**Version du plugin :** le plugin du panneau se met à jour depuis le tableau de bord (Plugins de panneaux), pas avec l'agent. Depuis la 1.0.35, l'agent lit la version du plugin WHM installé (en lecture seule : `/usr/local/share/infrafence-whm/VERSION`, sinon le paquet `infrafence-whm` ; au démarrage et au plus une fois par heure) et l'envoie avec le heartbeat (`panel_plugin`). `panel status` l'affiche dans `plugin_installed`, à côté de `plugin_latest`, la dernière version que le tableau de bord envoie à la synchronisation, pour que le plugin puisse signaler une mise à jour disponible. Détails : [docs/panel-json.md](docs/panel-json.md#status).

---

## Pas encore disponible

Liste honnête de ce qui n'existe pas encore :

- **Motifs de détection SSH par serveur** depuis le tableau de bord

Nous y travaillons ; le [changelog](CHANGELOG.md) indique quand ils arrivent.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│              InfraFence dashboard             │
│   web app + API · Postgres · real-time push   │
└───────────────────────┬──────────────────────┘
                        │ HTTPS (agent → dashboard)
                        │ real-time channel (dashboard → agent)
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────┐
   │  Agent  │    │  Agent  │    │  Agent  │
   │  (VPS)  │    │ (Docker)│    │  (...)  │
   └─────────┘    └─────────┘    └─────────┘
```

L'agent est un binaire Go statique unique (~9 Mo, sans dépendances), exécuté comme service systemd (ou upstart/sysvinit) ou comme conteneur Docker. Sur le serveur de démonstration, il utilise environ 25 Mo de mémoire et moins de 1 % de CPU.

---

## Sécurité et confiance

| | Détail |
|---|---|
| **Code consultable** | L'agent est sous licence BSL 1.1 : gratuit en production sur vos serveurs et ceux de vos clients, entièrement transparent, et vous pouvez relire chaque ligne avant de l'installer. |
| **Ce qu'il lit** | Les logs système et du serveur web, les fichiers des sites pour l'analyse de malwares (y compris `.env` et fichiers de configuration), les articles et utilisateurs WordPress pour l'analyse WordPress, ainsi que le trafic DNS et les connexions réseau du serveur. |
| **Ce qu'il envoie** | Uniquement des événements de sécurité : IP de l'attaquant, type, heure et les détails nécessaires pour les comprendre — pour une attaque web, la ligne de log qui l'a déclenchée ; pour un malware, le chemin du fichier et le texte trouvé. Les logs et fichiers complets ne quittent jamais votre serveur. Aucune télémétrie, aucun partage avec des tiers. |
| **Pare-feu** | Ses propres chaînes `INFRAFENCE` ; vos règles existantes ne sont jamais modifiées. |
| **Binaires signés** | Chaque version est compilée par GitHub Actions avec des signatures [Cosign](https://github.com/sigstore/cosign) et une [attestation de provenance](https://github.com/infrafence/infrafence-agent/attestations). |
| **Désinstallation propre** | `install.sh --uninstall` supprime l'agent et tout ce qu'il a ajouté. |

Détails dans [SECURITY.md](SECURITY.md).

---

## Contribuer

Les contributions sont les bienvenues. [Ouvrez un ticket](https://github.com/infrafence/infrafence-agent/issues) avant les changements importants.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Licence

L'agent est source-available sous [Business Source License 1.1](LICENSE) (concédant : ComCart S.r.l.). L'usage en production est gratuit sur n'importe quel nombre de serveurs, y compris ceux de vos clients, tant que vous ne l'utilisez pas pour créer un produit concurrent. Quatre ans après chaque version, celle-ci devient disponible sous licence Apache 2.0.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
