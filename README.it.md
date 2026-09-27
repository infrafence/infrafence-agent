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

<h3 align="center">Sicurezza server che si installa in 30 secondi</h3>

<p align="center">
  Agente Go leggero per server Linux che rileva gli attacchi in tempo reale e li blocca automaticamente — in entrata e in uscita.<br>
  Brute force SSH, attacchi web, bot, malware, minacce DNS e in uscita, integrità dei file, Docker — con impostazioni sicure, gestito da un'unica dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Sito</a> ·
  <a href="https://infrafence.com/pricing">Prezzi</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Segnalazioni</a>
</p>

---

## Il problema

Avvii un nuovo VPS Linux e il conto alla rovescia parte subito — bot automatici lo scansionano, tentano il brute force su SSH e cercano exploit nel giro di pochi minuti, spesso prima ancora che tu abbia finito la configurazione iniziale.

La maggior parte di questa attività passa inosservata. Nessuno guarda i log mentre succede.

Gli strumenti classici reagiscono alle righe di log un server alla volta e ti mostrano poco di ciò che è successo. Le suite di sicurezza complete danno visibilità e automazione, ma richiedono un vero lavoro di configurazione e costano di più per server.

InfraFence sta nel mezzo: **installi con un comando, guardi tutto dal vivo da una dashboard e lasci che blocchi automaticamente — a 9 €/server**.

## Avvio rapido

Crea un token di installazione nella dashboard (Server → Aggiungi server), poi sul server, come root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Vuoi prima vedere cosa farebbe? Aggiungi `--dry-run`: scarica l'agente, controlla il server in sola lettura, mostra il piano e non modifica nulla.

> **[Ottieni il tuo token su infrafence.com](https://infrafence.com)** — il piano gratuito include 1 server con protezione completa.

---

## Cosa rileva

### SSH e brute force
15 schemi di rilevamento nel log SSH: password errate, utenti inesistenti, errori PAM, scansioni prima dell'autenticazione, incompatibilità di protocollo, interruzioni dello scambio di chiavi. Gli attaccanti vengono bannati sul firewall per durate progressive — 24 ore, 7 giorni, 30 giorni, poi permanente — o per la durata che scegli nella dashboard.

### Web Application Firewall
Legge gli access log dei tuoi web server e assegna un punteggio a ogni IP visitatore:

| Tipo di attacco | Punteggio | Modalità |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | A punteggio |
| UA di scanner (sqlmap, nikto, nmap, nuclei…) | +50 | A punteggio |
| SQL injection / SSRF / Exploit web | +40 | A punteggio |
| Trappola honeypot (percorsi esca definiti come regole personalizzate) | +40 | A punteggio |
| Path traversal / Header injection | +30 | A punteggio |
| Brute force WordPress | +30 | Soglia (10 richieste / 2 min) |
| XSS / Ricerca di `.env` / XMLRPC | +25 | A punteggio |
| Ricerca di file di configurazione | +20 | A punteggio |
| Raffica di 404 | +15 | Soglia (15 richieste / 5 min) |

Il punteggio scende di 5 punti al minuto. Livelli di azione: **osserva** (30) → **rallenta** (60) → **blocca** (80) → **ban sul firewall** (100). Dalla dashboard vedi ogni regola integrata, cambi pesi, soglie e modalità per tipo, disattivi singoli schemi e aggiungi regole tue (URL, User-Agent o Referer, testo o regex). Ogni release pubblica il catalogo delle regole integrate come `waf-catalog.json`.

### Gestione dei bot
Circa 1.500 bot riconosciuti da liste pubbliche aggiornate ogni giorno ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), entrambe MIT) — motori di ricerca, crawler di IA, strumenti SEO, scanner, monitoraggio, anteprime dei link e altro. I falsi bot dei motori di ricerca vengono smascherati tramite il DNS inverso. Per ogni categoria, o singolo bot, scegli nella dashboard: **consenti**, **solo registra** o **blocca**. I bot bloccati vengono bannati sul firewall; se consenti le modifiche al web server, vengono rifiutati anche da nginx/Apache.

### Scanner malware
- **Scansione a firme** — 28 schemi integrati per web shell, backdoor, miner di criptovalute e kit di phishing
- **Motore YARA** — regole della community per le minacce web da [YARA Forge](https://github.com/YARAHQ/yara-forge), aggiornate ogni giorno, solo da fonti la cui licenza consente l'uso commerciale (signature-base, ReversingLabs). Richiede lo strumento `yara`, installabile con un clic dalla dashboard
- **Ogni rilevamento** spiega perché è stato segnalato, la gravità e lo SHA-256 del file, con link per verificarlo nei database pubblici di malware
- **Riconoscimento dei framework** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Controlli di sicurezza dei framework** — `.env` esposto, modalità DEBUG, APP_KEY, permessi troppo aperti, Telescope, wp-config
- **Euristiche** — entropia di Shannon, anomalie di data nelle cartelle di upload
- **Integrità del sistema** — binari di sistema modificati (`dpkg -V` / `rpm -Va`), indicatori di rootkit
- **Scansione delle credenziali** — file `.env` esposti, permessi delle chiavi SSH, `.git` nella cartella web, credenziali cloud
- **Scansione del database WordPress** — script iniettati in articoli e opzioni, amministratori non autorizzati
- **Rilevamento dei processi** — miner in esecuzione, reverse shell, script sospetti da `/tmp`
- **Quarantena e ignora** — con un clic sposti un file malevolo in `/var/lib/infrafence/quarantine/` (ripristinabile) o segni un falso positivo, che le scansioni successive saltano
- **Scansioni pianificate** ogni 3, 6, 12 o 24 ore, più "Scansiona ora" dalla dashboard
- **Controllo in tempo reale** — verifica ogni 30 secondi le cartelle di upload in cerca di nuovi file PHP

### WAF inline ModSecurity (opzionale)
- Solo se consenti le modifiche al web server nelle impostazioni della dashboard — disattivato per impostazione predefinita
- Mai sui server la cui configurazione è gestita da un pannello di hosting o da uno strumento di gestione della configurazione
- Per Apache con mod_security2: 13 regole (SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, blocco degli scanner), blocco alla prima richiesta
- Sicuro: se il test di configurazione di Apache fallisce, la modifica viene annullata

### Minacce in uscita e DNS
- **Connessioni in uscita** verso IP presenti in liste pubbliche di threat intelligence, scaricate da ogni server una volta al giorno (reti note per essere state dirottate, la lista di host compromessi di Emerging Threats)
- **Ispezione DNS** — ogni query e risposta DNS viene letta a livello di pacchetto (UDP 53, sola lettura, con un filtro eseguito nel kernel) e collegata al programma che l'ha fatta: query verso server DNS inattesi o malevoli, domini che puntano a IP malevoli noti, tunnel DNS e malware che genera domini casuali (DGA)
- Il servizio DNS del server e le verifiche di antivirus e antispam vengono riconosciuti e non segnalati
- Il blocco in entrata delle reti in lista è disattivato per impostazione predefinita e si attiva dalla dashboard (richiede `ipset`)

### Integrità dei file e persistenza
Hash SHA-256 di riferimento con un avviso a ogni modifica:
- File di sistema principali — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Attività pianificate — `/etc/crontab`, `/etc/cron.d/*`, crontab dei singoli utenti
- Persistenza SSH — `authorized_keys` di root e di ogni utente in `/home/*`
- `/etc/ld.so.preload` e unità systemd (`/etc/systemd/system/*.service`, `*.timer`)

### Rischio delle sessioni SSH
Segue ogni sessione SSH dall'inizio alla fine — metodo di autenticazione, reputazione dell'IP di origine, orario di accesso, comandi privilegiati (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — e le assegna un punteggio da 0 a 100 alla chiusura. **Correlazione Sigma**: se un altro rilevatore (WAF, integrità, malware, scansione porte, uscita, DNS) scatta mentre una sessione è aperta, il punteggio di rischio di quella sessione sale.

### E altro
- **Posta, database e FTP** — rilevamento del brute force per Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD e vsftpd
- **Compatibile con Docker** — trova i log dei container web e protegge le porte pubblicate (`DOCKER-USER`)
- **Blocco per paese** dalla dashboard (richiede `ipset`)
- **Pannelli di hosting riconosciuti** (24, ad es. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) e **LiteSpeed / OpenLiteSpeed** — InfraFence non modifica mai una configurazione gestita da un pannello o da LiteSpeed
- **Modalità monitor** — rileva tutto, non blocca nulla
- **Metriche di sistema** — CPU, memoria, disco e rete

---

## Sicuro sui server in produzione

- **Controlla prima di modificare** — `infrafence-agent preflight` è una scansione in sola lettura del server (firewall e altri strumenti di sicurezza, web server, pannelli di hosting, gestione della configurazione, operazioni sui pacchetti, risorse). L'installer la esegue prima di modificare qualsiasi cosa; l'agente all'avvio e ogni giorno.
- **Impostazioni prudenti** — le modifiche al web server e il blocco in entrata dalle liste di minacce restano disattivati finché non li attivi; gli aggiornamenti automatici possono essere impostati su solo notifica.
- **Catene firewall dedicate** — ogni regola sta nelle catene `INFRAFENCE` dell'agente, richiamate da `INPUT` (e `DOCKER-USER`), ricostruite in modo atomico e ripristinate automaticamente entro un minuto se un altro strumento (ufw, firewalld, CSF) le rimuove. Le tue regole esistenti non vengono mai modificate. Gli IP in whitelist vengono esclusi, mai aperti.
- **Disinstallazione pulita** — rimuove l'agente e tutto ciò che ha aggiunto: catene firewall, modifiche al web server, il servizio.

---

## Come funziona

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

L'agente **non banna mai** IP riservati o privati, gli indirizzi del server stesso, l'indirizzo della dashboard o gli IP in whitelist — anche se gli viene chiesto.

---

## Installazione

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Opzione | Effetto |
|---|---|
| `--dry-run` | Controlla il server e mostra il piano; non modifica nulla |
| `--no-ipset` | Non installa `ipset` (i ban funzionano comunque, fino a 500; il blocco per paese e dalle liste di minacce lo richiede) |
| `--uninstall` | Rimuove l'agente e tutto ciò che ha aggiunto |

**Requisiti:** x86-64 o ARM64, accesso root, `iptables`; systemd, upstart o sysvinit. L'installer usa `apt`, `dnf` o `yum` per le dipendenze mancanti e installa `ipset` solo quando il controllo del server dice che è sicuro.

**Testato finora:** Ubuntu 24.04 (in produzione) e Debian 12 (installer e firewall, su entrambi i backend di iptables, con e senza ipset). Le altre distribuzioni delle famiglie RHEL e Debian dovrebbero funzionare ma non sono ancora verificate — vedi [Non ancora disponibile](#non-ancora-disponibile).

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

Immagine multi-architettura (amd64 + arm64) pubblicata con ogni release. Uno stack per Docker Swarm è in [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Disinstallazione

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configurazione

Quasi tutto si configura dalla dashboard e arriva ai server in circa un secondo: soglie di brute force, durata dei ban, modalità monitor, regole WAF, scelte sui bot, whitelist, paesi bloccati, pianificazione delle scansioni malware, ispezione DNS, modifiche al web server, blocco dalle liste di minacce, aggiornamenti automatici.

Sul server:

| Variabile d'ambiente | Effetto |
|---|---|
| `AUTH_LOG_PATH` | Log SSH da leggere (predefinito: `/var/log/auth.log` o `/var/log/secure`) |
| `WEB_LOG_PATH` | Access log web, separati da virgola (predefinito: rilevati da nginx, Apache, LiteSpeed, pannelli, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Sostituiscono i log di posta, database e FTP rilevati |
| `MODSEC_AUDIT_LOG` | Log di audit di ModSecurity |
| `GEOIP_DB_PATH` | Database GeoIP dei paesi |
| `INFRAFENCE_CONFIG` | File di configurazione dell'agente (predefinito `/etc/infrafence/config.json`) |

Impostale con `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), poi riavvia il servizio.

**Etichette Docker** sui tuoi container: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (percorsi sull'host), `infrafence.domain` (domini).

**Comandi:** `infrafence-agent preflight [--json]` (controllo del server in sola lettura), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Non ancora disponibile

Elenco onesto di ciò che oggi non c'è:

- **Kubernetes** — il chart Helm e il DaemonSet esistono, ma la dashboard non sa ancora registrare gli agenti di un cluster
- **Propagazione dei ban** — un ban vale sul server che l'ha rilevato, non ancora su tutti i tuoi server
- **Controlli di hardening e scansione CVE** — il codice è nell'agente, ma la dashboard non li può ancora avviare
- **Punteggio di sicurezza** (0-100) — calcolato dall'agente, non ancora mostrato nella dashboard
- **Schemi di rilevamento SSH per server** dalla dashboard
- **Ban IP in ModSecurity** sincronizzati dalla dashboard
- **Log solo in journald** — il rilevamento SSH richiede `/var/log/auth.log` o `/var/log/secure`; i server senza rsyslog (Debian 12+ minimal, Fedora) non sono ancora coperti
- **Altre distribuzioni verificate** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

Ci stiamo lavorando; il [changelog](CHANGELOG.md) dice quando arrivano.

---

## Architettura

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

L'agente è un unico binario Go statico (~9 MB, senza dipendenze), in esecuzione come servizio systemd (o upstart/sysvinit) o come container Docker. Sul server demo usa circa 25 MB di memoria e meno dell'1% di CPU.

---

## Sicurezza e fiducia

| | Dettaglio |
|---|---|
| **Open source** | L'agente ha licenza MIT. Verifica ogni riga prima di installarlo. |
| **Cosa legge** | Log di sistema e del web server, i file dei siti per la scansione malware (compresi `.env` e file di configurazione), articoli e utenti di WordPress per la scansione WordPress, e il traffico DNS e le connessioni di rete del server. |
| **Cosa invia** | Solo eventi di sicurezza: IP dell'attaccante, tipo, ora e i dettagli necessari per capirli — per un attacco web la singola riga di log che l'ha fatto scattare, per un malware il percorso del file e il testo trovato. Log e file completi non lasciano mai il tuo server. Nessuna telemetria, nessuna condivisione con terzi. |
| **Firewall** | Le sue catene `INFRAFENCE`; le tue regole esistenti non vengono mai modificate. |
| **Binari firmati** | Ogni release è compilata da GitHub Actions con firme [Cosign](https://github.com/sigstore/cosign) e [attestazione di provenienza](https://github.com/infrafence/infrafence-agent/attestations). |
| **Disinstallazione pulita** | `install.sh --uninstall` rimuove l'agente e tutto ciò che ha aggiunto. |

Dettagli in [SECURITY.md](SECURITY.md).

---

## Contribuire

I contributi sono benvenuti. [Apri una segnalazione](https://github.com/infrafence/infrafence-agent/issues) prima di modifiche importanti.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Licenza

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
