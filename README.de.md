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

<h3 align="center">Den Angriff stoppen. Die Lücke schließen, durch die er kam.</h3>

<p align="center">
  InfraFence blockiert Angriffe auf deine Linux-Server, während sie passieren, eingehend wie ausgehend. Danach härtet es das System, spielt Patches ein, prüft das Ergebnis und nimmt jede Korrektur zurück, die etwas kaputtmacht.<br>
  SSH-Brute-Force, Web-Angriffe, Bots, Malware, DNS- und ausgehende Bedrohungen, Dateiintegrität, Docker — mit sicheren Voreinstellungen, gesteuert über ein einziges Dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com/de/">Website</a> ·
  <a href="https://infrafence.com/de/pricing">Preise</a> ·
  <a href="https://infrafence.com/de/dokumentation">Dokumentation</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## Warum InfraFence

- **Es sieht, was den Server verlässt.** Es meldet ausgehende Verbindungen zu bekannten bösartigen IPs und liest jede DNS-Anfrage auf Paketebene, zugeordnet dem Programm, das sie gestellt hat: DNS-Tunnel und zufällige Domains (DGA) kommen mit Prozessname und PID.
- **Es weiß, wer angemeldet war.** Jede SSH-Sitzung erhält eine Risikobewertung von 0 bis 100, die steigt, wenn WAF, Dateiintegrität, Malware-, Portscan-, Egress- oder DNS-Erkennung anschlagen, während sie offen ist.
- **Korrekturen, die die Produktion nicht lahmlegen.** Nach jeder Änderung (Port schließen, ausgehenden Verkehr sperren, Härtungskorrektur, virtueller Patch) prüft es SSH und die überwachten Websites und macht die Änderung rückgängig, wenn sie nicht mehr antworten.
- **KI, die nur innerhalb fester Grenzen handelt.** AutoMode wählt aus einem festen Katalog von Aktionen, führt nie eigene Befehle aus und sperrt nie deine eigenen Adressen oder SSH-Anmeldungen. Aktionen, die nicht automatisch laufen (zum Beispiel einen MySQL- oder PostgreSQL-Port schließen, der nicht angegriffen wird, manche PHP-Korrekturen, ein virtueller Patch außerhalb der automatischen Regel), warten im Dashboard auf eine Freigabe, und entscheiden kann nur ein Inhaber oder Administrator, der mit Zwei-Faktor-Authentifizierung angemeldet ist. [Was deine Freigabe braucht](https://infrafence.com/de/dokumentation/automode#what-needs-your-approval)

Starter ist kostenlos für einen Server, kostenpflichtige Tarife ab 8,90 € pro Server und Monat: [Preise ansehen](https://infrafence.com/de/pricing).

## Schnellstart

Erstelle im Dashboard ein Installations-Token (Server → Server hinzufügen) und führe dann auf dem Server als root aus:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Möchtest du zuerst sehen, was passieren würde? Füge `--dry-run` hinzu (kein Token nötig): Der Agent wird heruntergeladen, der Server nur lesend geprüft, der Plan angezeigt — und nichts verändert.

> **[Hol dir dein Token auf infrafence.com](https://infrafence.com/add-server)** — der Starter-Tarif ist kostenlos und umfasst 1 Server mit vollem Schutz.

---

## Was erkannt wird

### SSH und Brute-Force
15 Erkennungsmuster im SSH-Log: falsche Passwörter, nicht existierende Benutzer, PAM-Fehler, Scans vor der Authentifizierung, Protokollkonflikte, abgebrochene Schlüsselaustausche. Angreifer werden in der Firewall für steigende Zeiträume gesperrt — 24 Stunden, 7 Tage, 30 Tage, dann dauerhaft — oder für die im Dashboard gewählte Dauer.

### Web Application Firewall
Liest die Access-Logs deiner Webserver und vergibt für jede besuchende IP einen Punktwert:

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

Der Punktwert sinkt um 5 Punkte pro Minute. Aktionsstufen: **beobachten** (30) → **drosseln** (60) → **blockieren** (80) → **Firewall-Sperre** (100). Im Dashboard siehst du jede eingebaute Regel, änderst Gewichte, Schwellenwerte und Modus pro Typ, deaktivierst einzelne Muster und fügst eigene Regeln hinzu (URL, User-Agent oder Referer, Text oder Regex). Jedes Release veröffentlicht den Katalog der eingebauten Regeln als `waf-catalog.json`.

### Bot-Verwaltung
Rund 1.500 bekannte Bots aus täglich aktualisierten öffentlichen Listen ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), beide MIT) — Suchmaschinen, KI-Crawler, SEO-Tools, Scanner, Monitoring, Link-Vorschauen und mehr. Gefälschte Suchmaschinen-Bots werden per Reverse-DNS entlarvt. Für jede Kategorie oder jeden einzelnen Bot wählst du im Dashboard: **erlauben**, **nur protokollieren** oder **blockieren**. Blockierte Bots werden in der Firewall gesperrt; wenn du Änderungen am Webserver erlaubst, weisen auch nginx/Apache sie ab.

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
- **Quarantäne und Ignorieren** — mit einem Klick verschiebst du eine schädliche Datei nach `/var/lib/infrafence/quarantine/` (wiederherstellbar) oder markierst einen Fehlalarm, den spätere Scans überspringen
- **Geplante Scans** alle 3, 6, 12 oder 24 Stunden, dazu „Jetzt scannen" im Dashboard
- **Echtzeit-Prüfung** — prüft Upload-Ordner alle 30 Sekunden auf neue PHP-Dateien

### ModSecurity-Inline-WAF (optional)
- Nur wenn du Änderungen am Webserver in den Dashboard-Einstellungen erlaubst — standardmäßig aus
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
- **Länder-Sperre** im Dashboard (benötigt `ipset`). Der Agent lädt die Länderdatenbank von deinem Dashboard ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0), nur solange ein Land gesperrt ist und höchstens einmal am Tag. Die Erlaubt-Liste, die eigenen Adressen des Servers und SSH-Sitzungen, die beim Sperren eines Landes offen sind, werden nie gesperrt. [Ländersperre](https://infrafence.com/de/dokumentation/laendersperre)
- **Erkannte Hosting-Panels** (24, z. B. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) und **LiteSpeed / OpenLiteSpeed** — InfraFence ändert nie eine Konfiguration, die von einem Panel oder von LiteSpeed verwaltet wird
- **Überwachungsmodus** — erkennt alles, blockiert nichts
- **Systemmetriken** — CPU, Arbeitsspeicher, Festplatte und Netzwerk

---

## Über die Erkennung hinaus

Was InfraFence zu den Erkennungen oben hinzufügt, jeweils mit einer Seite in der [Dokumentation](https://infrafence.com/de/dokumentation):

- **Härtung, Schwachstellen und Sicherheitswert** — rund 40 Härtungsprüfungen, mit Korrektur per Klick für die sicheren; bekannte Schwachstellen (CVE) der installierten Pakete nach echtem Risiko: zuerst die bereits ausgenutzten (CISA KEV), dann nach Ausnutzungswahrscheinlichkeit (EPSS); ein Sicherheitswert von 0 bis 100. [Härtung und Schwachstellen](https://infrafence.com/de/dokumentation/haertung-und-schwachstellen)
- **PHP-Härtung** — findet riskante PHP-Einstellungen in jeder Runtime und jedem Pool und behebt die sicheren. Korrekturen kommen in eine Datei, die InfraFence gehört (`zz-infrafence-hardening.ini`), werden geprüft und zurückgenommen, wenn eine Website nicht mehr antwortet; `cgi.fix_pathinfo` und `disable_functions` brauchen eine Freigabe. Der Agent überwacht außerdem die PHP-Konfiguration und meldet einen riskanten Wert, sobald er auftaucht. Das ist Härtung und Überwachung der Konfiguration: Nichts wird in PHP geladen, und es ist kein Schutz, der innerhalb deiner Anwendungen läuft. [PHP-Härtung](https://infrafence.com/de/dokumentation/haertung-und-schwachstellen#php-hardening)
- **Offene Ports schließen, gefährliche Ziele sperren** (Pro · AutoMode) — jede Änderung wird geprüft und zurückgenommen, wenn sie etwas kaputtmacht. [Ports und ausgehende Sperren](https://infrafence.com/de/dokumentation/ports-und-ausgehende-sperren)
- **Virtuelle Patches für ausgenutzte Schwachstellen** (Pro · AutoMode) — eine gezielte ModSecurity-Regel schützt die verwundbare Software, bis du das Update installierst; Apache mit ModSecurity. [Virtuelle Patches](https://infrafence.com/de/dokumentation/virtuelle-patches)
- **Notfallmodus** — ein roter Knopf: 24 Stunden lang reagiert InfraFence selbst auf den Angriff, mit demselben sicheren Katalog und denselben Grenzen wie AutoMode (ab Basic). [Notfallmodus](https://infrafence.com/de/dokumentation/notfallmodus)
- **Benachrichtigungen** per E-Mail, Slack, Discord, Telegram oder Webhook, dazu eine wöchentliche Zusammenfassung per E-Mail. [Benachrichtigungen](https://infrafence.com/de/dokumentation/benachrichtigungen)
- **KI-Analyse** — eine Sofortanalyse jedes Vorfalls in jedem Tarif, im Dashboard berechnet; ab Pro eine KI-Analyse mit sicheren Korrekturen per Klick. [Ereignisse und Aktivität](https://infrafence.com/de/dokumentation/ereignisse-und-aktivitaet)
- **InfraFence-Netzwerk und Angriffskarte** — Teilen ist optional: Adressen, die mehrere Kunden angreifen, werden markiert, und Netzwerkzahlen erscheinen nur, wo 3 oder mehr Organisationen beigetragen haben. [Das InfraFence-Netzwerk](https://infrafence.com/de/dokumentation/infrafence-netzwerk) · [Angriffskarte](https://infrafence.com/de/dokumentation/angriffskarte)
- **Monitoring-Badge** — das Badge „Überwacht von InfraFence“ verlinkt auf eine öffentliche Transparenzseite mit dem Zeitpunkt der letzten Prüfung, den blockierten Angriffen der letzten 30 Tage und den aktiven Schutzfunktionen. Um zu zeigen, dass die Domain von deinem Server ausgeliefert wird, legt der Agent eine Prüfdatei, `/.well-known/infrafence-verification.txt`, im Document Root der Website ab und entfernt sie, wenn das Badge abgeschaltet wird. Es ist kein Zertifikat. [Monitoring-Badge](https://infrafence.com/de/features#trust-badge) · [Beispiel einer Transparenzseite ansehen](https://infrafence.com/de/trust/demo)
- **Schutz auch ohne erreichbares Dashboard** — Sperren, Whitelist und Ländersperren bleiben in Kraft, neue Angriffe werden weiter gesperrt, und Ereignisse warten in einer Warteschlange. [Wenn das Dashboard nicht erreichbar ist](https://infrafence.com/de/dokumentation/dashboard-nicht-erreichbar)
- **Neben CSF und anderen Tools** — InfraFence bleibt in seinen eigenen Chains und ändert nie die Dateien von CSF oder die Regeln anderer Tools; nach `csf -r` stellt es seine eigenen Regeln innerhalb von Sekunden wieder her. [Koexistenz mit anderen Sicherheitstools](https://infrafence.com/de/dokumentation/koexistenz)
- **Plugin für cPanel & WHM** (verfügbar) **und Erweiterung für Plesk** (in Entwicklung), in den Tarifen Basic, Pro und AutoMode enthalten — Schutzstatus, Sperren, Funde, Ereignisse und Scans pro Website direkt im Panel. [cPanel & WHM](https://infrafence.com/de/integrationen/cpanel-whm) · [Hosting-Panels](https://infrafence.com/de/dokumentation/hosting-panels) · [WHM-Plugin](https://infrafence.com/de/dokumentation/whm-plugin)

---

## Sicher auf Produktionsservern

- **Prüfen vor dem Ändern** — `infrafence-agent preflight` ist eine rein lesende Prüfung des Servers (Firewall und andere Sicherheitswerkzeuge, Webserver, Hosting-Panels, Konfigurationsmanagement, Paketoperationen, Ressourcen). Der Installer führt sie aus, bevor er irgendetwas ändert; der Agent beim Start und täglich.
- **Vorsichtige Voreinstellungen** — Änderungen am Webserver und eingehendes Blockieren über Bedrohungslisten bleiben aus, bis du sie aktivierst; Agent-Updates stehen auf „Nur benachrichtigen“, bis du automatische Installation wählst, und installiert werden nur mit cosign signierte Releases.
- **Eigene Firewall-Chains** — jede Regel liegt in den `INFRAFENCE`-Chains des Agenten, aufgerufen aus `INPUT` (und `DOCKER-USER`), atomar neu aufgebaut und innerhalb von Sekunden automatisch wiederhergestellt, falls ein anderes Werkzeug (ufw, firewalld, CSF) sie entfernt. Deine bestehenden Regeln werden nie verändert. IPs auf der Whitelist werden ausgenommen, nie freigeschaltet.
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
| `--dry-run` | Prüft den Server und zeigt den Plan; ändert nichts. Kein Token nötig |
| `--no-ipset` | Installiert `ipset` nicht (Sperren funktionieren weiterhin, bis zu 500; Länder-Sperre und Bedrohungslisten benötigen es) |
| `--skip-checksum` | **Unsicher.** Installiert auch dann, wenn die Prüfsumme des Releases nicht heruntergeladen werden kann (die Binärdatei wird nicht geprüft). Nur für ein Netz, das die Datei `.sha256` und sonst nichts blockiert |
| `--uninstall` | Entfernt den Agenten und alles, was er hinzugefügt hat |

Der Agent wird nur von GitHub Releases heruntergeladen, und der Installer bricht ab, wenn die Prüfsumme des Release fehlt oder nicht passt. Das Let's-Encrypt-Stammzertifikat, das er eventuell braucht (ISRG Root X1), ist mit festgelegtem Fingerabdruck im Skript enthalten, statt heruntergeladen zu werden. [Was der Installer macht](https://infrafence.com/de/dokumentation/was-der-installer-macht)

**Voraussetzungen:** x86-64 oder ARM64, root-Zugriff, `iptables`; systemd, upstart oder sysvinit. Der Installer nutzt `apt`, `dnf` oder `yum` für fehlende Abhängigkeiten und installiert `ipset` nur, wenn die Serverprüfung dies als sicher einstuft.

**Vor jedem Release getestet** auf 15 Distributionen: Ubuntu 20.04, 22.04, 24.04 und 26.04, Debian 12 und 13, Rocky Linux 8 und 9, AlmaLinux 8 und 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 und 42, Amazon Linux 2023. Auf jeder läuft der echte Installer, erkennt einen SSH-Brute-Force-Angriff, sperrt ihn in der Firewall und deinstalliert sich sauber. Andere Distributionen der Debian- und RHEL-Familie funktionieren meist: Starte den Installer zuerst mit `--dry-run`. Siehe [Unterstützte Distributionen](https://infrafence.com/de/dokumentation/unterstuetzte-distributionen).

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

### Kubernetes

Erstelle im Dashboard einen Cluster-Schlüssel (Einstellungen → Kubernetes), dann:

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Jeder Knoten registriert sich als eigener Server. Alle Werte, Upgrades und GitOps: [Kubernetes](https://infrafence.com/de/dokumentation/kubernetes) in der Dokumentation und das [Chart-README](charts/infrafence-agent/README.md).

### Deinstallation

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Konfiguration

Fast alles wird im Dashboard eingestellt und erreicht die Server in etwa einer Sekunde: Brute-Force-Schwellenwerte, Sperrdauer, Überwachungsmodus, WAF-Regeln, Bot-Entscheidungen, Whitelist, gesperrte Länder, Zeitplan der Malware-Scans, DNS-Inspektion, Webserver-Änderungen, Blockieren über Bedrohungslisten, automatische Updates. Vollständige Referenz: [Konfiguration](https://infrafence.com/de/dokumentation/konfiguration).

Auf dem Server:

| Umgebungsvariable | Wirkung |
|---|---|
| `AUTH_LOG_PATH` | SSH-Logdatei, die statt des systemd-Journals gelesen wird (Standard: das Journal auf Systemen mit systemd, sonst `/var/log/auth.log` oder `/var/log/secure`) |
| `WEB_LOG_PATH` | Web-Access-Logs, kommagetrennt (Standard: erkannt aus nginx, Apache, LiteSpeed, Panels, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Ersetzen die erkannten Mail-, Datenbank- und FTP-Logs |
| `MODSEC_AUDIT_LOG` | ModSecurity-Audit-Log |
| `GEOIP_DB_PATH` | Länderdatenbank (MaxMind-DB-Format), die statt der vom Dashboard nach `/etc/infrafence/geoip-country.mmdb` geladenen verwendet wird; ist sie gesetzt, wird nichts heruntergeladen |
| `INFRAFENCE_CONFIG` | Konfigurationsdatei des Agenten (Standard `/etc/infrafence/config.json`) |

Setze sie mit `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) und starte den Dienst neu.

**Docker-Labels** an deinen Containern: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (Pfade auf dem Host), `infrafence.domain` (Domains).

**Befehle:** `infrafence-agent preflight [--json]` (rein lesende Serverprüfung), `infrafence-agent version` (installierte Version), `infrafence-agent check`, `infrafence-agent uninstall --clean`. Alle Befehle: [Befehlsreferenz](https://infrafence.com/de/dokumentation/befehlsreferenz).

**Hosting-Panels (cPanel/WHM, Plesk):** Die Panel-Plugins führen `infrafence-agent panel <command> --json` als root aus und lesen ein JSON-Objekt von stdout (`{"ok": true, ...}` oder `{"ok": false, "error": "<code>", "message": "..."}`, Exit-Status 0 nur bei ok). Befehle: `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score`; die Befehle, die etwas ändern, brauchen `--actor <Panel-Benutzer>` und werden dem Dashboard als Ereignisse mit der Quelle `panel` gemeldet. Der Befehl spricht über `/run/infrafence/panel.sock` mit dem laufenden Agenten (nur root, Modus 0600, kein Netzwerkport); läuft kein Agent, antwortet er trotzdem, mit `"agent_running": false`. Die Plugins sind in den Tarifen Basic, Pro und AutoMode enthalten (Agent 1.0.34 oder neuer): `status` antwortet immer, mit `"entitled"` und `"entitlement"` (`ok`, `plan_required`, `unpaid`, `unknown`); jeder andere Befehl antwortet nur mit diesem Fehler und ohne Daten, wenn die Organisation keinen Anspruch hat (ein Tarif ohne die Plugins, Schutz nach 24 Stunden Ablehnung abgeschaltet, oder der Tarif ist noch nicht bekannt). Der Tarif der letzten erfolgreichen Synchronisierung bleibt über Neustarts erhalten, damit ein Ausfall des Dashboards das Plugin nicht leert. `map` (die Angriffe auf diesen Server nach Land und Kategorie) und `score` (sein Sicherheitswert und der Verlauf über 30 Tage) kommen vom Dashboard, brauchen Agent 1.0.33 oder neuer und werden vom Agenten zwischengespeichert: höchstens eine Anfrage alle 5 Minuten für die Karte und alle 15 Minuten für den Wert, mit `"stale": true`, wenn das Dashboard nicht erreichbar ist. Alle Felder jeder Antwort: [docs/panel-json.md](docs/panel-json.md) (auf Englisch).

**Offen oder behoben:** Jedes Problem-Ereignis, das der Agent meldet (ein offener Datenbank-Port, eine geänderte Systemdatei, eine riskante PHP-Einstellung, Malware...), trägt `details.subject` (`port:tcp/3306`, `file:/etc/passwd`...). Ab 1.0.34 sagen `panel events` und `panel findings`, ob jedes Problem noch `open` oder `resolved` ist (`subject`, `state`, `resolved_at`, `resolved_how`): im Dashboard behoben oder vom Agenten selbst (ein Port, den seine Firewall geschlossen hat, ein angewendeter und geprüfter Fix, eine Datei in Quarantäne, ein aktualisiertes Paket). Ein Datenbank-Port, den die Firewall des Agenten schließt, wird beim Neustart des Agenten nicht mehr als offen gemeldet. Details: [docs/panel-json.md](docs/panel-json.md#problems-and-resolution) (auf Englisch).

**Plugin-Version:** Das Panel-Plugin wird im Dashboard (Panel-Plugins) aktualisiert, nicht mit dem Agenten. Ab 1.0.35 liest der Agent die Version des installierten WHM-Plugins (nur lesend: `/usr/local/share/infrafence-whm/VERSION`, sonst das Paket `infrafence-whm`; beim Start und höchstens einmal pro Stunde) und schickt sie mit dem Heartbeat (`panel_plugin`). `panel status` zeigt sie als `plugin_installed`, neben `plugin_latest`, der neuesten Version, die das Dashboard bei der Synchronisierung schickt. So kann das Plugin dir sagen, wenn ein Update verfügbar ist. Details: [docs/panel-json.md](docs/panel-json.md#status).

---

## Noch nicht verfügbar

Eine ehrliche Liste dessen, was es heute noch nicht gibt:

- **SSH-Erkennungsmuster pro Server** aus dem Dashboard

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
| **Quelloffen einsehbar** | Der Agent steht unter der BSL 1.1: kostenlos im Produktivbetrieb auf deinen Servern und denen deiner Kunden, vollständig transparent, und du kannst jede Zeile vor der Installation prüfen. |
| **Was er liest** | System- und Webserver-Logs, die Dateien der Websites für den Malware-Scan (einschließlich `.env` und Konfigurationsdateien), WordPress-Beiträge und -Benutzer für den WordPress-Scan sowie den DNS-Verkehr und die Netzwerkverbindungen des Servers. |
| **Was er sendet** | Nur Sicherheitsereignisse: IP des Angreifers, Typ, Zeit und die zum Verständnis nötigen Details — bei einem Web-Angriff die auslösende Logzeile, bei Malware der Dateipfad und der gefundene Text. Vollständige Logs und Dateien verlassen deinen Server nie. Keine Telemetrie, keine Weitergabe an Dritte. |
| **Firewall** | Eigene `INFRAFENCE`-Chains; deine bestehenden Regeln werden nie verändert. |
| **Signierte Binaries** | Jedes Release wird von GitHub Actions gebaut, mit [Cosign](https://github.com/sigstore/cosign)-Signaturen und [Herkunftsnachweis](https://github.com/infrafence/infrafence-agent/attestations). |
| **Saubere Deinstallation** | `install.sh --uninstall` entfernt den Agenten und alles, was er hinzugefügt hat. |

Details in [SECURITY.md](SECURITY.md).

---

## Mitwirken

Beiträge sind willkommen. [Öffne ein Issue](https://github.com/infrafence/infrafence-agent/issues) vor größeren Änderungen.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Lizenz

Der Agent ist source-available unter der [Business Source License 1.1](LICENSE) (Lizenzgeber: ComCart S.r.l.). Der Produktivbetrieb ist auf beliebig vielen Servern kostenlos, auch auf denen deiner Kunden, solange du damit kein Konkurrenzprodukt baust. Vier Jahre nach jeder Veröffentlichung steht diese Version unter der Apache-Lizenz 2.0 zur Verfügung.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
