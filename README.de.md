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

<h3 align="center">Serversicherheit, die in 30 Sekunden installiert ist</h3>

<p align="center">
  Schlanker Go-Agent für Linux-Server, der Angriffe in Echtzeit erkennt und automatisch blockiert — eingehend wie ausgehend.<br>
  SSH-Brute-Force, Web-Angriffe, Bots, Malware, DNS- und ausgehende Bedrohungen, Dateiintegrität, Docker — mit sicheren Voreinstellungen, gesteuert über ein einziges Dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Website</a> ·
  <a href="https://infrafence.com/pricing">Preise</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## Das Problem

Sie starten einen neuen Linux-VPS, und der Countdown läuft sofort — automatisierte Bots scannen ihn, versuchen Brute-Force auf SSH und suchen innerhalb weniger Minuten nach Exploits, oft noch bevor Sie die Grundeinrichtung abgeschlossen haben.

Das meiste davon bleibt unbemerkt. Niemand schaut in die Logs, während es passiert.

Klassische Werkzeuge reagieren auf Logzeilen, Server für Server, und zeigen Ihnen wenig davon, was passiert ist. Vollständige Security-Suiten bieten Transparenz und Automatisierung, erfordern aber echten Einrichtungsaufwand und kosten mehr pro Server.

InfraFence liegt dazwischen: **mit einem Befehl installiert, alles live in einem Dashboard sichtbar, blockiert automatisch — für 9 €/Server**.

## Schnellstart

Erstellen Sie im Dashboard ein Installations-Token (Server → Server hinzufügen) und führen Sie dann auf dem Server als root aus:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Möchten Sie zuerst sehen, was passieren würde? Fügen Sie `--dry-run` hinzu: Der Agent wird heruntergeladen, der Server nur lesend geprüft, der Plan angezeigt — und nichts verändert.

> **[Holen Sie sich Ihr Token auf infrafence.com](https://infrafence.com)** — der kostenlose Tarif umfasst 1 Server mit vollem Schutz.

---

## Was erkannt wird

### SSH und Brute-Force
15 Erkennungsmuster im SSH-Log: falsche Passwörter, nicht existierende Benutzer, PAM-Fehler, Scans vor der Authentifizierung, Protokollkonflikte, abgebrochene Schlüsselaustausche. Angreifer werden in der Firewall für steigende Zeiträume gesperrt — 24 Stunden, 7 Tage, 30 Tage, dann dauerhaft — oder für die im Dashboard gewählte Dauer.

### Web Application Firewall
Liest die Access-Logs Ihrer Webserver und vergibt für jede besuchende IP einen Punktwert:

| Angriffsart | Punkte | Modus |
|---|:---:|---|
| RCE / Web-Shell / Shellshock | +50 | Punktbasiert |
| Scanner-UA (sqlmap, nikto, nmap, nuclei…) | +50 | Punktbasiert |
| SQL-Injection / SSRF / Web-Exploits | +40 | Punktbasiert |
| Honeypot-Falle (Köderpfade als eigene Regeln definiert) | +40 | Punktbasiert |
| Path Traversal / Header-Injection | +30 | Punktbasiert |
| WordPress-Brute-Force | +30 | Schwellenwert (10 Anfragen / 2 Min.) |
| XSS / Suche nach `.env` / XMLRPC | +25 | Punktbasiert |
| Suche nach Konfigurationsdateien | +20 | Punktbasiert |
| 404-Flut | +15 | Schwellenwert (15 Anfragen / 5 Min.) |

Der Punktwert sinkt um 5 Punkte pro Minute. Aktionsstufen: **beobachten** (30) → **drosseln** (60) → **blockieren** (80) → **Firewall-Sperre** (100). Im Dashboard sehen Sie jede eingebaute Regel, ändern Gewichte, Schwellenwerte und Modus pro Typ, deaktivieren einzelne Muster und fügen eigene Regeln hinzu (URL, User-Agent oder Referer, Text oder Regex). Jedes Release veröffentlicht den Katalog der eingebauten Regeln als `waf-catalog.json`.

### Bot-Verwaltung
Rund 1.500 bekannte Bots aus täglich aktualisierten öffentlichen Listen ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), beide MIT) — Suchmaschinen, KI-Crawler, SEO-Tools, Scanner, Monitoring, Link-Vorschauen und mehr. Gefälschte Suchmaschinen-Bots werden per Reverse-DNS entlarvt. Für jede Kategorie oder jeden einzelnen Bot wählen Sie im Dashboard: **erlauben**, **nur protokollieren** oder **blockieren**. Blockierte Bots werden in der Firewall gesperrt; wenn Sie Änderungen am Webserver erlauben, weisen auch nginx/Apache sie ab.

### Malware-Scanner
- **Signatur-Scan** — 28 eingebaute Muster für Web-Shells, Backdoors, Krypto-Miner und Phishing-Kits
- **YARA-Engine** — Community-Regeln gegen Web-Bedrohungen von [YARA Forge](https://github.com/YARAHQ/yara-forge), täglich aktualisiert, nur aus Quellen, deren Lizenz kommerzielle Nutzung erlaubt (signature-base, ReversingLabs). Benötigt das Werkzeug `yara`, mit einem Klick aus dem Dashboard installierbar
- **Jeder Fund** erklärt, warum er gemeldet wurde, den Schweregrad und den SHA-256 der Datei, mit Links zur Prüfung in öffentlichen Malware-Datenbanken
- **Framework-Erkennung** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Framework-Sicherheitsprüfungen** — offene `.env`, DEBUG-Modus, APP_KEY, zu weite Berechtigungen, Telescope, wp-config
- **Heuristiken** — Shannon-Entropie, Datumsanomalien in Upload-Ordnern
- **Systemintegrität** — veränderte System-Binaries (`dpkg -V` / `rpm -Va`), Rootkit-Indikatoren
- **Zugangsdaten-Scan** — offene `.env`-Dateien, Berechtigungen von SSH-Schlüsseln, `.git` im Web-Ordner, Cloud-Zugangsdaten
- **WordPress-Datenbank-Scan** — eingeschleuste Skripte in Beiträgen und Optionen, nicht autorisierte Administratoren
- **Prozesserkennung** — laufende Miner, Reverse Shells, verdächtige Skripte aus `/tmp`
- **Quarantäne und Ignorieren** — mit einem Klick verschieben Sie eine schädliche Datei nach `/var/lib/infrafence/quarantine/` (wiederherstellbar) oder markieren einen Fehlalarm, den spätere Scans überspringen
- **Geplante Scans** alle 3, 6, 12 oder 24 Stunden, dazu „Jetzt scannen" im Dashboard
- **Echtzeit-Prüfung** — prüft Upload-Ordner alle 30 Sekunden auf neue PHP-Dateien

### ModSecurity-Inline-WAF (optional)
- Nur wenn Sie Änderungen am Webserver in den Dashboard-Einstellungen erlauben — standardmäßig aus
- Niemals auf Servern, deren Konfiguration von einem Hosting-Panel oder einem Konfigurationsmanagement-Werkzeug verwaltet wird
- Für Apache mit mod_security2: 13 Regeln (SQL-Injection, XSS, RCE, SSRF, Path Traversal, Shellshock, Log4Shell, Spring4Shell, Scanner-Sperre), Blockierung bei der ersten Anfrage
- Sicher: Schlägt der Apache-Konfigurationstest fehl, wird die Änderung rückgängig gemacht

### Ausgehende und DNS-Bedrohungen
- **Ausgehende Verbindungen** zu IPs aus öffentlichen Threat-Intelligence-Listen, die jeder Server einmal täglich herunterlädt (als gekapert bekannte Netze, die Liste kompromittierter Hosts von Emerging Threats)
- **DNS-Inspektion** — jede DNS-Anfrage und -Antwort wird auf Paketebene gelesen (UDP 53, nur lesend, mit einem im Kernel laufenden Filter) und dem Programm zugeordnet, das sie gestellt hat: Anfragen an unerwartete oder bösartige DNS-Server, Domains, die auf bekannte bösartige IPs zeigen, DNS-Tunnel und Malware, die zufällige Domains erzeugt (DGA)
- Der DNS-Dienst des Servers selbst sowie Abfragen von Antiviren- und Antispam-Software werden erkannt und nicht gemeldet
- Das eingehende Blockieren gelisteter Netze ist standardmäßig aus und wird im Dashboard aktiviert (benötigt `ipset`)

### Dateiintegrität und Persistenz
SHA-256-Referenzhashes, mit Warnung bei jeder Änderung:
- Zentrale Systemdateien — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Geplante Aufgaben — `/etc/crontab`, `/etc/cron.d/*`, Crontabs der einzelnen Benutzer
- SSH-Persistenz — `authorized_keys` von root und jedem Benutzer unter `/home/*`
- `/etc/ld.so.preload` und systemd-Units (`/etc/systemd/system/*.service`, `*.timer`)

### Risiko von SSH-Sitzungen
Verfolgt jede SSH-Sitzung von Anfang bis Ende — Authentifizierungsmethode, Reputation der Quell-IP, Anmeldezeit, privilegierte Befehle (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — und bewertet sie beim Schließen mit 0 bis 100. **Sigma-Korrelation**: Schlägt ein anderer Detektor (WAF, Integrität, Malware, Portscan, ausgehend, DNS) an, während eine Sitzung offen ist, steigt das Risiko dieser Sitzung.

### Und mehr
- **Mail, Datenbanken und FTP** — Brute-Force-Erkennung für Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD und vsftpd
- **Docker-fähig** — findet die Logs von Web-Containern und schützt veröffentlichte Ports (`DOCKER-USER`)
- **Länder-Sperre** im Dashboard (benötigt `ipset`)
- **Erkannte Hosting-Panels** (24, z. B. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) und **LiteSpeed / OpenLiteSpeed** — InfraFence ändert nie eine Konfiguration, die von einem Panel oder von LiteSpeed verwaltet wird
- **Überwachungsmodus** — erkennt alles, blockiert nichts
- **Systemmetriken** — CPU, Arbeitsspeicher, Festplatte und Netzwerk

---

## Sicher auf Produktionsservern

- **Prüfen vor dem Ändern** — `infrafence-agent preflight` ist eine rein lesende Prüfung des Servers (Firewall und andere Sicherheitswerkzeuge, Webserver, Hosting-Panels, Konfigurationsmanagement, Paketoperationen, Ressourcen). Der Installer führt sie aus, bevor er irgendetwas ändert; der Agent beim Start und täglich.
- **Vorsichtige Voreinstellungen** — Änderungen am Webserver und eingehendes Blockieren über Bedrohungslisten bleiben aus, bis Sie sie aktivieren; automatische Updates lassen sich auf „nur benachrichtigen" stellen.
- **Eigene Firewall-Chains** — jede Regel liegt in den `INFRAFENCE`-Chains des Agenten, aufgerufen aus `INPUT` (und `DOCKER-USER`), atomar neu aufgebaut und innerhalb einer Minute automatisch wiederhergestellt, falls ein anderes Werkzeug (ufw, firewalld, CSF) sie entfernt. Ihre bestehenden Regeln werden nie verändert. IPs auf der Whitelist werden ausgenommen, nie freigeschaltet.
- **Saubere Deinstallation** — entfernt den Agenten und alles, was er hinzugefügt hat: Firewall-Chains, Webserver-Änderungen, den Dienst.

---

## Funktionsweise

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

Der Agent **sperrt niemals** reservierte oder private IPs, die eigenen Adressen des Servers, die Adresse des Dashboards oder IPs auf der Whitelist — selbst wenn er dazu aufgefordert wird.

---

## Installation

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Option | Wirkung |
|---|---|
| `--dry-run` | Prüft den Server und zeigt den Plan; ändert nichts |
| `--no-ipset` | Installiert `ipset` nicht (Sperren funktionieren weiterhin, bis zu 500; Länder-Sperre und Bedrohungslisten benötigen es) |
| `--uninstall` | Entfernt den Agenten und alles, was er hinzugefügt hat |

**Voraussetzungen:** x86-64 oder ARM64, root-Zugriff, `iptables`; systemd, upstart oder sysvinit. Der Installer nutzt `apt`, `dnf` oder `yum` für fehlende Abhängigkeiten und installiert `ipset` nur, wenn die Serverprüfung dies als sicher einstuft.

**Bisher getestet:** Ubuntu 24.04 (in Produktion) und Debian 12 (Installer und Firewall, auf beiden iptables-Backends, mit und ohne ipset). Andere Distributionen der RHEL- und Debian-Familie sollten funktionieren, sind aber noch nicht verifiziert — siehe [Noch nicht verfügbar](#noch-nicht-verfügbar).

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

Multi-Architektur-Image (amd64 + arm64), mit jedem Release veröffentlicht. Ein Stack für Docker Swarm liegt in [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Deinstallation

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Konfiguration

Fast alles wird im Dashboard eingestellt und erreicht die Server in etwa einer Sekunde: Brute-Force-Schwellenwerte, Sperrdauer, Überwachungsmodus, WAF-Regeln, Bot-Entscheidungen, Whitelist, gesperrte Länder, Zeitplan der Malware-Scans, DNS-Inspektion, Webserver-Änderungen, Blockieren über Bedrohungslisten, automatische Updates.

Auf dem Server:

| Umgebungsvariable | Wirkung |
|---|---|
| `AUTH_LOG_PATH` | Zu lesendes SSH-Log (Standard: `/var/log/auth.log` oder `/var/log/secure`) |
| `WEB_LOG_PATH` | Web-Access-Logs, kommagetrennt (Standard: erkannt aus nginx, Apache, LiteSpeed, Panels, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Ersetzen die erkannten Mail-, Datenbank- und FTP-Logs |
| `MODSEC_AUDIT_LOG` | ModSecurity-Audit-Log |
| `GEOIP_DB_PATH` | GeoIP-Länderdatenbank |
| `INFRAFENCE_CONFIG` | Konfigurationsdatei des Agenten (Standard `/etc/infrafence/config.json`) |

Setzen Sie sie mit `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) und starten Sie den Dienst neu.

**Docker-Labels** an Ihren Containern: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (Pfade auf dem Host), `infrafence.domain` (Domains).

**Befehle:** `infrafence-agent preflight [--json]` (rein lesende Serverprüfung), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Noch nicht verfügbar

Eine ehrliche Liste dessen, was es heute noch nicht gibt:

- **Kubernetes** — Helm-Chart und DaemonSet existieren, aber das Dashboard kann Agenten eines Clusters noch nicht registrieren
- **Weitergabe von Sperren** — eine Sperre gilt auf dem Server, der sie erkannt hat, noch nicht auf all Ihren Servern
- **Härtungsprüfungen und CVE-Scan** — der Code ist im Agenten, aber das Dashboard kann sie noch nicht starten
- **Sicherheitswert** (0-100) — vom Agenten berechnet, im Dashboard noch nicht angezeigt
- **SSH-Erkennungsmuster pro Server** aus dem Dashboard
- **IP-Sperren in ModSecurity**, synchronisiert aus dem Dashboard
- **Logs nur in journald** — die SSH-Erkennung benötigt `/var/log/auth.log` oder `/var/log/secure`; Server ohne rsyslog (Debian 12+ minimal, Fedora) sind noch nicht abgedeckt
- **Weitere verifizierte Distributionen** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

Wir arbeiten daran; das [Changelog](CHANGELOG.md) sagt, wann sie kommen.

---

## Architektur

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

Der Agent ist ein einzelnes statisches Go-Binary (~9 MB, ohne Abhängigkeiten) und läuft als systemd-Dienst (oder upstart/sysvinit) oder als Docker-Container. Auf dem Demo-Server nutzt er etwa 25 MB Arbeitsspeicher und weniger als 1 % CPU.

---

## Sicherheit und Vertrauen

| | Detail |
|---|---|
| **Open Source** | Der Agent steht unter MIT-Lizenz. Prüfen Sie jede Zeile vor der Installation. |
| **Was er liest** | System- und Webserver-Logs, die Dateien der Websites für den Malware-Scan (einschließlich `.env` und Konfigurationsdateien), WordPress-Beiträge und -Benutzer für den WordPress-Scan sowie den DNS-Verkehr und die Netzwerkverbindungen des Servers. |
| **Was er sendet** | Nur Sicherheitsereignisse: IP des Angreifers, Typ, Zeit und die zum Verständnis nötigen Details — bei einem Web-Angriff die auslösende Logzeile, bei Malware der Dateipfad und der gefundene Text. Vollständige Logs und Dateien verlassen Ihren Server nie. Keine Telemetrie, keine Weitergabe an Dritte. |
| **Firewall** | Eigene `INFRAFENCE`-Chains; Ihre bestehenden Regeln werden nie verändert. |
| **Signierte Binaries** | Jedes Release wird von GitHub Actions gebaut, mit [Cosign](https://github.com/sigstore/cosign)-Signaturen und [Herkunftsnachweis](https://github.com/infrafence/infrafence-agent/attestations). |
| **Saubere Deinstallation** | `install.sh --uninstall` entfernt den Agenten und alles, was er hinzugefügt hat. |

Details in [SECURITY.md](SECURITY.md).

---

## Mitwirken

Beiträge sind willkommen. [Öffnen Sie ein Issue](https://github.com/infrafence/infrafence-agent/issues) vor größeren Änderungen.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Lizenz

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
