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

<h3 align="center">La sécurité serveur qui s'installe en 30 secondes</h3>

<p align="center">
  Agent Go léger pour serveurs Linux qui détecte les attaques en temps réel et les bloque automatiquement — en entrée comme en sortie.<br>
  Force brute SSH, attaques web, bots, malwares, menaces DNS et sortantes, intégrité des fichiers, Docker — avec des réglages sûrs par défaut, piloté depuis un seul tableau de bord.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Site web</a> ·
  <a href="https://infrafence.com/pricing">Tarifs</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Tickets</a>
</p>

---

## Le problème

Vous lancez un nouveau VPS Linux et le compte à rebours commence aussitôt — des bots automatisés le scannent, tentent la force brute sur SSH et cherchent des failles en quelques minutes, souvent avant même la fin de votre configuration initiale.

L'essentiel de cette activité passe inaperçu. Personne ne regarde les logs pendant que ça se produit.

Les outils classiques réagissent aux lignes de log un serveur à la fois et montrent peu de ce qui s'est passé. Les suites de sécurité complètes offrent visibilité et automatisation, mais demandent un vrai travail de configuration et coûtent plus cher par serveur.

InfraFence se situe entre les deux : **installez-le en une commande, suivez tout en direct depuis un tableau de bord et laissez-le bloquer automatiquement — pour 9 €/serveur**.

## Démarrage rapide

Créez un jeton d'installation dans le tableau de bord (Serveurs → Ajouter un serveur), puis sur le serveur, en root :

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Vous voulez d'abord voir ce qu'il ferait ? Ajoutez `--dry-run` : il télécharge l'agent, vérifie le serveur en lecture seule, affiche le plan et ne modifie rien.

> **[Obtenez votre jeton sur infrafence.com](https://infrafence.com)** — l'offre gratuite inclut 1 serveur avec protection complète.

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
- **Blocage par pays** depuis le tableau de bord (nécessite `ipset`)
- **Panneaux d'hébergement reconnus** (24, par ex. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) et **LiteSpeed / OpenLiteSpeed** — InfraFence ne modifie jamais une configuration gérée par un panneau ou par LiteSpeed
- **Mode surveillance** — détecte tout, ne bloque rien
- **Métriques système** — CPU, mémoire, disque et réseau

---

## Sûr sur les serveurs de production

- **Vérifie avant de modifier** — `infrafence-agent preflight` est une vérification du serveur en lecture seule (pare-feu et autres outils de sécurité, serveurs web, panneaux d'hébergement, gestion de configuration, opérations sur les paquets, ressources). L'installateur la lance avant toute modification ; l'agent, au démarrage et chaque jour.
- **Réglages prudents par défaut** — les modifications du serveur web et le blocage en entrée par listes de menaces restent désactivés jusqu'à ce que vous les activiez ; les mises à jour automatiques peuvent être réglées sur « notification seulement ».
- **Chaînes de pare-feu dédiées** — chaque règle vit dans les chaînes `INFRAFENCE` de l'agent, appelées depuis `INPUT` (et `DOCKER-USER`), reconstruites de façon atomique et restaurées automatiquement en moins d'une minute si un autre outil (ufw, firewalld, CSF) les supprime. Vos règles existantes ne sont jamais modifiées. Les IP en liste blanche sont exemptées, jamais ouvertes.
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
| `--dry-run` | Vérifie le serveur et affiche le plan ; ne modifie rien |
| `--no-ipset` | N'installe pas `ipset` (les bannissements fonctionnent toujours, jusqu'à 500 ; le blocage par pays et par listes de menaces en a besoin) |
| `--uninstall` | Supprime l'agent et tout ce qu'il a ajouté |

**Prérequis :** x86-64 ou ARM64, accès root, `iptables` ; systemd, upstart ou sysvinit. L'installateur utilise `apt`, `dnf` ou `yum` pour les dépendances manquantes et n'installe `ipset` que lorsque la vérification du serveur indique que c'est sans risque.

**Testé à ce jour :** Ubuntu 24.04 (en production) et Debian 12 (installateur et pare-feu, sur les deux backends d'iptables, avec et sans ipset). Les autres distributions des familles RHEL et Debian devraient fonctionner mais ne sont pas encore vérifiées — voir [Pas encore disponible](#pas-encore-disponible).

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

### Désinstallation

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

Presque tout se règle depuis le tableau de bord et arrive sur les serveurs en une seconde environ : seuils de force brute, durée des bannissements, mode surveillance, règles WAF, choix sur les bots, liste blanche, pays bloqués, planification des analyses de malwares, inspection DNS, modifications du serveur web, blocage par listes de menaces, mises à jour automatiques.

Sur le serveur :

| Variable d'environnement | Effet |
|---|---|
| `AUTH_LOG_PATH` | Log SSH à lire (par défaut : `/var/log/auth.log` ou `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs d'accès web, séparés par des virgules (par défaut : détectés depuis nginx, Apache, LiteSpeed, panneaux, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Remplacent les logs mail, base de données et FTP détectés |
| `MODSEC_AUDIT_LOG` | Log d'audit ModSecurity |
| `GEOIP_DB_PATH` | Base GeoIP des pays |
| `INFRAFENCE_CONFIG` | Fichier de configuration de l'agent (par défaut `/etc/infrafence/config.json`) |

Définissez-les avec `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), puis redémarrez le service.

**Labels Docker** sur vos conteneurs : `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (chemins sur l'hôte), `infrafence.domain` (domaines).

**Commandes :** `infrafence-agent preflight [--json]` (vérification du serveur en lecture seule), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Pas encore disponible

Liste honnête de ce qui n'existe pas encore :

- **Kubernetes** — le chart Helm et le DaemonSet existent, mais le tableau de bord ne sait pas encore enregistrer les agents d'un cluster
- **Propagation des bannissements** — un bannissement s'applique sur le serveur qui l'a détecté, pas encore sur tous vos serveurs
- **Contrôles de durcissement et analyse CVE** — le code est dans l'agent, mais le tableau de bord ne peut pas encore les lancer
- **Score de sécurité** (0-100) — calculé par l'agent, pas encore affiché dans le tableau de bord
- **Motifs de détection SSH par serveur** depuis le tableau de bord
- **Bannissements d'IP dans ModSecurity** synchronisés depuis le tableau de bord
- **Logs uniquement dans journald** — la détection SSH nécessite `/var/log/auth.log` ou `/var/log/secure` ; les serveurs sans rsyslog (Debian 12+ minimal, Fedora) ne sont pas encore couverts
- **Davantage de distributions vérifiées** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

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
| **Open source** | L'agent est sous licence MIT. Relisez chaque ligne avant de l'installer. |
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

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
