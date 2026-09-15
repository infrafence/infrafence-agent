<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.it.md">Italiano</a> ·
  <a href="README.pt-br.md">Português (BR)</a>
</p>

<p align="center">
  <img src="docs/logo.png" alt="InfraFence" width="200">
</p>

<h3 align="center">Sicurezza server che si installa in 30 secondi</h3>

<p align="center">
  Agente Go leggero che rileva gli attacchi in tempo reale e li blocca automaticamente.<br>
  Brute force SSH, WAF, gestione bot, Docker e Kubernetes — zero configurazione.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://github.com/infrafence/infrafence-agent/pkgs/container/infrafence-agent"><img src="https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://artifacthub.io/packages/helm/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Helm-Artifact_Hub-0F1689?logo=helm&logoColor=white" alt="Helm"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Sito</a> ·
  <a href="https://infrafence.com/docs">Documentazione</a> ·
  <a href="https://infrafence.com/docs/installation">Guida all'installazione</a> ·
  <a href="https://infrafence.com/pricing">Prezzi</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## Il problema

Il VPS Linux medio riceve il primo attacco automatizzato **entro 4 minuti** dalla messa online. Brute force SSH, exploit web, scraping da bot, port scan.

La maggior parte degli sviluppatori se ne accorge quando è già troppo tardi — o mai.

**fail2ban** blocca a cose fatte, senza visibilità. **CrowdSec** richiede una configurazione complessa. Gli strumenti enterprise costano $20-200+/host.

InfraFence colma il vuoto: **un comando per installare, dashboard in tempo reale, blocco automatico, €9/server**.

## Avvio rapido

```bash
# Linux (one-liner)
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <IL_TUO_TOKEN>

# Docker
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e INFRAFENCE_TOKEN=<IL_TUO_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest

# Kubernetes (Helm)
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<LA_TUA_API_KEY> \
  --namespace infrafence-system --create-namespace
```

> **[Ottieni il tuo token su infrafence.com](https://infrafence.com)** — il piano gratuito include 1 server con protezione completa.

---

## Perché InfraFence

| | fail2ban | CrowdSec | BitNinja | **InfraFence** |
|---|:---:|:---:|:---:|:---:|
| Dashboard in tempo reale | — | A pagamento ($2K+/anno) | Sì | **Sì** |
| Installazione con un comando | — | — | Solo cPanel | **Sì** |
| Rilevamento SSH | Sì | Sì | Sì | **Sì (15 pattern)** |
| Punteggio di rischio sessione SSH (comportamento post-login) | — | — | — | **Sì** |
| Web Application Firewall | — | Parziale | Sì | **Sì (15 tipi OWASP)** |
| Gestione bot | — | — | Sì | **Sì (70+ fingerprint)** |
| Scansione malware | — | — | Sì | **Sì (YARA + database hash + quarantena)** |
| File integrity & monitoraggio persistenza | — | — | Solo core WP | **Sì (system-wide)** |
| Consapevolezza container Docker | — | — | — | **Sì** |
| Kubernetes / Helm | — | Sì | — | **Sì (DaemonSet)** |
| Rilevamento minacce in uscita (egress & DNS) | — | — | — | **Sì** |
| Modalità monitor (solo rilevamento) | — | — | — | **Sì** |
| Funziona su qualsiasi Linux | Sì | Sì | cPanel/Plesk | **Sì** |
| Prezzo | Gratis | Gratis / $2K+ | €14-52/srv | **€9/srv** |

---

## Cosa rileva

### SSH & brute force
15 pattern di rilevamento: password errate, utenti non validi, fallimenti PAM, scansione pre-auth, mismatch di protocollo, kex negotiation interrotte. I pattern sono sincronizzati dalla dashboard — abilita/disabilita per server senza riavviare l'agente.

### Web Application Firewall

| Tipo di attacco | Punteggio | Modalità |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | A punteggio |
| User agent scanner (sqlmap, nikto, nmap, nuclei...) | +50 | A punteggio |
| SQL injection / SSRF / Exploit web | +40 | A punteggio |
| Honeypot (50+ endpoint esca) | +40 | A punteggio |
| Path traversal / Header injection | +30 | A punteggio |
| Brute force WordPress | +30 | Soglia (10 req / 2 min) |
| XSS / probe `.env` / XMLRPC | +25 | A punteggio |
| Config probing / Pattern scanner | +20 | A punteggio |
| Flood 404 | +15 | Soglia (30 req / 5 min) |

Ogni rilevamento aggiunge punti a un punteggio per-IP. I punteggi decadono di -5 pt/min. Livelli di azione: **osserva** (30) → **rallenta** (60) → **blocca 1h** (80) → **blacklist 24h** (100+). Tutti i pesi sono configurabili per server.

### Gestione bot
70+ fingerprint di bot (motori di ricerca, crawler AI, tool SEO, scanner). Politiche per organizzazione: **consenti** / **registra** / **blocca**. I bot bloccati vengono respinti a livello nginx/Apache — connessione chiusa prima che raggiunga la tua app.

### Scanner malware
- **Scansione a firme** — 24 pattern integrati per webshell, backdoor, crypto miner, phishing kit
- **Hash matching** — oltre 64.000 hash di malware noti da MalwareBazaar e Linux Malware Detect
- **Motore YARA** — 229 regole rilevanti per il web (usa la CLI yara se installata, opzionale)
- **Rilevamento framework** — auto-rileva Laravel, WordPress, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Controlli di sicurezza sui framework** — esposizione .env, modalità DEBUG, APP_KEY, permessi troppo aperti, Telescope, wp-config
- **Analisi euristica** — rilevamento entropia di Shannon, anomalie nei timestamp nelle directory di upload
- **Integrità di sistema** — `dpkg -V` / `rpm -Va` per binari modificati, indicatori di rootkit (ld.so.preload, processi nascosti, eseguibili in /tmp)
- **Scansione credenziali** — file .env esposti, permessi delle chiavi SSH, .git nella web root, credenziali cloud
- **Scansione database WP** — script iniettati in post/opzioni, utenti admin illegittimi
- **Rilevamento processi** — crypto miner in esecuzione, reverse shell, script sospetti da /tmp
- **Punteggio di postura di sicurezza** — 0-100 (voto A-F) con dettaglio per categoria
- **Quarantena** — sposta i file malevoli in `/var/lib/infrafence/quarantine/` con possibilità di ripristino
- **Scansioni programmate** — frequenza, orario e intensità configurabili dalla dashboard
- **Watcher in tempo reale** — controlla le directory di upload ogni 30s per nuovi file PHP
- **Prevenzione falsi positivi** — checksum del core WP, severità contestuale, allowlist utente con herd immunity cross-network

### WAF inline ModSecurity
- **Auto-rilevamento** di Apache + mod_security2 all'avvio (standard su cPanel/WHM)
- **14 regole statiche** — SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, blocco scanner
- **Blocca alla prima richiesta** — ModSecurity intercetta prima che il traffico raggiunga la tua applicazione
- **Regole di ban IP** — IP bannati sincronizzati dalla dashboard a ModSecurity per il blocco a livello HTTP
- **Zero configurazione** — scrive automaticamente le regole, configura l'Include, ricarica senza downtime
- **Nessun impatto** sui server senza ModSecurity — ripiega sul blocco via iptables

### Rilevamento minacce in uscita (egress & DNS)
La maggior parte degli strumenti guarda solo il traffico in *entrata*. InfraFence osserva anche cosa fa un host già compromesso in *uscita* — la stessa threat feed usata per i ban in entrata (Spamhaus DROP, Feodo Tracker e altre) viene verificata anche sul traffico in uscita:
- **Egress threat matching** — segnala connessioni in uscita stabilite verso qualsiasi IP presente nella threat feed, individuando un host compromesso che comunica con infrastrutture C2 che le regole firewall solo-inbound non vedono
- **Monitoraggio resolver DNS** — segnala traffico DNS in uscita (UDP/53) verso IP della threat feed, verso resolver esterni al tuo `/etc/resolv.conf` configurato, e "resolver hopping" (molti resolver esterni distinti in una finestra breve) — un segnale precoce di DNS tunneling
- Basato su polling, sullo stesso ciclo degli altri monitor: intercetta in modo affidabile il traffico *sostenuto* — tunneling, beaconing ripetuto — non una singola query occasionale

### File integrity & monitoraggio persistenza
Hashing SHA-256 di baseline con avviso immediato in caso di modifica, sia sui classici bersagli "tripwire" sia sulle tecniche di persistenza più comuni:
- File di sistema principali — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Persistenza via task pianificati — `/etc/crontab`, `/etc/cron.d/*`, e **crontab per-utente** (`/var/spool/cron/crontabs/*` su Debian, `/var/spool/cron/*` su RHEL)
- Persistenza SSH — `authorized_keys` di root e di ogni utente sotto `/home/*`
- Punti di hijack / rootkit — `/etc/ld.so.preload` (classico hijack userspace via LD_PRELOAD)
- Persistenza systemd — `/etc/systemd/system/*.service` e `*.timer` (un sostituto comune di cron per piantare persistenza)

### Punteggio di rischio delle sessioni SSH
Traccia ogni sessione SSH dall'inizio alla fine — metodo di autenticazione, reputazione dell'IP sorgente, ora di login, comandi privilegiati (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — e le assegna un punteggio da 0 a 100 alla chiusura. **Correlazione Sigma**: se un altro detector (WAF, integrity, malware, port scan, egress, DNS) scatta mentre una sessione è aperta, il punteggio di rischio di quella sessione sale — trasformando segnali isolati a bassa confidenza in un unico alert ad alta confidenza collegato esattamente a chi era connesso in quel momento.

### E altro ancora
- **Protezione Mail & FTP** — rilevamento brute force su Postfix, Dovecot, Pure-FTPD, MySQL
- **Consapevolezza Docker** — auto-rileva i container web, legge i log via bind mount e volumi
- **Blocco GeoIP** — blocca interi paesi dalla dashboard
- **Propagazione dei ban in rete** — un ban su un server si applica a tutti i tuoi server
- **Security scanner** — 30+ controlli di hardening con auto-remediation
- **Vulnerability scanning** — matching CVE via NVD + Exploit-DB, scoring EPSS
- **Modalità monitor** — rileva le minacce senza bloccare (impostazione predefinita per i nuovi server)
- **Metriche di sistema** — CPU, memoria, disco riportati alla dashboard
- **Addon cPanel/WHM** — integrazione nativa nella sidebar con auto-rilevamento di cPHulk e domlog

---

## Come funziona

```
auth.log / log di accesso web / log Docker / log ingress K8s
    │
    ▼
Auto-rilevamento log
    │  nginx -T / apachectl -S / docker inspect / API K8s
    │  Risolve bind mount, volumi, symlink
    ▼
Goroutine watcher
    │  Rileva brute force, SQLi, XSS, SSRF, path traversal, web shell...
    ▼
Motore di scoring bot (per-IP, con decadimento)
    │
    ├─ < 30 pt  → osserva (solo log)
    ├─ ≥ 30 pt  → rallenta
    ├─ ≥ 80 pt  → blocca 1h
    └─ ≥ 100 pt → blacklist 24h
            │
            ▼
    ipset add infrafence-bans <IP>
            │  Ripiega su iptables -I INPUT -s <IP> -j DROP
            │  ipset: 65K+ IP  ·  fallback iptables: 500 (rotazione FIFO)
            │
            ├──► POST /api/v1/agent/bans → dashboard
            └──► WebSocket propaga il ban a tutti i tuoi server
```

L'agente **non banna mai** IP riservati, gli IP del tuo stesso server, o l'endpoint API di InfraFence — anche se il backend invia una regola errata.

---

## Installazione

### Linux (consigliato)

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <IL_TUO_TOKEN>
```

**Supportati:** Ubuntu 20+, Debian 11+, CentOS 7+, RHEL 8+, Rocky, Alma, Amazon Linux 2023, Fedora
**Richiede:** `iptables`, `systemd`, accesso root · **Consigliato:** `ipset` (aumenta la capacità di ban a 65K+)

### Docker

```bash
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrafence-config:/etc/infrafence \
  -e INFRAFENCE_TOKEN=<IL_TUO_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest
```

**Immagine:** `ghcr.io/infrafence/infrafence-agent` — multi-arch (amd64 + arm64), ~40MB

<details>
<summary>Docker Compose</summary>

```yaml
services:
  infrafence-agent:
    image: ghcr.io/infrafence/infrafence-agent:latest
    container_name: infrafence-agent
    restart: unless-stopped
    privileged: true
    network_mode: host
    pid: host
    environment:
      - INFRAFENCE_TOKEN=${INFRAFENCE_TOKEN}
    volumes:
      - /var/log:/var/log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - infrafence-config:/etc/infrafence

volumes:
  infrafence-config:
```

```bash
INFRAFENCE_TOKEN=<IL_TUO_TOKEN> docker compose up -d infrafence-agent
```

</details>

<details>
<summary>Docker Swarm (servizio globale)</summary>

```bash
# Salva il token come Docker secret
echo "<IL_TUO_TOKEN>" | docker secret create infrafence_token -

# Distribuisci 1 agente per nodo
docker stack deploy -c docker-compose.swarm.yml infrafence
```

Vedi [docker-compose.swarm.yml](docker-compose.swarm.yml) per la definizione completa dello stack.

</details>

### Kubernetes (Helm)

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<LA_TUA_API_KEY> \
  --set config.serverUrl=https://infrafence.com \
  --namespace infrafence-system --create-namespace
```

Distribuisce un **DaemonSet** — un agente per nodo (incluso il control-plane). RBAC, tolerations e limiti di risorse preconfigurati.

<details>
<summary>values.yaml personalizzato</summary>

```yaml
config:
  organizationApiKey: "la-tua-api-key-org"
  serverUrl: "https://infrafence.com"
  clusterName: "production"    # auto-rilevato se omesso

resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

tolerations:
  - operator: Exists           # esegui su tutti i nodi
```

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  -f values.yaml -n infrafence-system --create-namespace
```

</details>

**Chart:** [Artifact Hub](https://artifacthub.io/packages/helm/infrafence/infrafence-agent) · Immagini firmate con [Cosign](https://github.com/sigstore/cosign) · Helm chart con provenance GPG

### Disinstallazione

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --uninstall
```

---

## Configurazione

<details>
<summary><strong>Configurazione WAF per server</strong></summary>

Ogni tipo di attacco può essere configurato indipendentemente dalla dashboard (Server → Web Protection). Le modifiche si sincronizzano entro 60 secondi.

- **Abilita/disabilita tipi** — disattiva le regole non rilevanti per il tuo stack (es. `wp_bruteforce` su un server non-WordPress)
- **Modalità solo rilevamento** — registra gli eventi senza bannare
- **Soglie personalizzate** — sovrascrivi i default per `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`
- **Pesi punteggio personalizzati** — regola i punti per tipo di rilevamento

Config WAF `null` → tutti i 15 tipi attivi con soglie di default (piena retrocompatibilità).

</details>

<details>
<summary><strong>Label Docker</strong></summary>

Configura il monitoraggio per container tramite label Docker — nessun riavvio dell'agente necessario:

```yaml
services:
  nginx:
    image: nginx
    labels:
      infrafence.monitor: "true"
      infrafence.log-path: "/var/log/nginx/access.log"
      infrafence.domain: "example.com,api.example.com"
    volumes:
      - /var/log/nginx:/var/log/nginx
```

| Label | Valori | Effetto |
|---|---|---|
| `infrafence.monitor` | `true` / `false` | Forza l'inclusione o l'esclusione di un container |
| `infrafence.log-path` | Path host, separati da virgola | Path del log esplicito (salta l'auto-rilevamento) |
| `infrafence.domain` | Dominio/i, separati da virgola | Associa nomi di dominio ai log |
| `infrafence.waf` | `true` / `false` | Informativo (il WAF è controllato dal pannello) |

**Priorità**: label `infrafence.log-path` > auto-rilevamento `nginx -T` > scansione bind-mount > `docker logs`.

</details>

<details>
<summary><strong>Override manuale del path dei log</strong></summary>

Se l'auto-rilevamento non trova i tuoi log, imposta `WEB_LOG_PATH`:

```bash
sudo systemctl edit infrafence-agent
```

```ini
[Service]
Environment="WEB_LOG_PATH=/var/log/httpd/access_log,/var/log/nginx/custom.log"
```

```bash
sudo systemctl restart infrafence-agent
```

</details>

<details>
<summary><strong>Variabili d'ambiente</strong></summary>

Salvate in `/etc/infrafence/agent.conf`:

| Variabile | Descrizione | Default |
|---|---|---|
| `INFRAFENCE_TOKEN` | Token di autenticazione agente | *(dalla registrazione)* |
| `INFRAFENCE_SERVER` | URL del server pannello | `https://infrafence.com` |
| `INFRAFENCE_LOG_PATH` | Path del file auth log | *(auto-rilevato)* |
| `INFRAFENCE_HEARTBEAT` | Intervallo heartbeat (secondi) | `30` |
| `INFRAFENCE_BAN_THRESHOLD` | Tentativi falliti prima del ban | `5` |
| `INFRAFENCE_WS_ENABLED` | Abilita WebSocket | `true` |
| `INFRAFENCE_GEOIP_ENABLED` | Abilita lookup GeoIP | `true` |
| `WEB_LOG_PATH` | Sovrascrivi i path dei log web | *(auto-rilevato)* |

</details>

---

## Risoluzione problemi

<details>
<summary><code>"Peer's Certificate issuer is not recognized"</code> durante l'installazione</summary>

Riguarda CentOS 7, RHEL 7 e sistemi con `ca-certificates` obsoleti:

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem
export CURL_CA_BUNDLE=/tmp/isrg.pem
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <IL_TUO_TOKEN>
```

</details>

<details>
<summary>L'agente mostra <code>203/EXEC</code> — il servizio non si avvia</summary>

Binario mancante o corrotto. Ripristina dal backup:

```bash
cp /usr/local/bin/infrafence-agent.bak /usr/local/bin/infrafence-agent
chmod 755 /usr/local/bin/infrafence-agent
systemctl reset-failed infrafence-agent && systemctl start infrafence-agent
```

Se `start-limit-hit`:

```bash
systemctl reset-failed infrafence-agent
systemctl start infrafence-agent
```

</details>

<details>
<summary>Il WAF non rileva gli attacchi</summary>

Controlla quali log sta monitorando l'agente:

```bash
journalctl -u infrafence-agent | grep webwatcher
```

Se non trova log: i log del tuo web server devono essere accessibili sull'host. Per web server in Docker, monta la directory dei log:

```yaml
volumes:
  - /var/log/nginx:/var/log/nginx
```

</details>

Altra risoluzione problemi su [infrafence.com/docs/troubleshooting](https://infrafence.com/docs/troubleshooting).

---

## Architettura

```
┌─────────────────────────────────────────────────────────┐
│                    InfraFence Cloud                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Dashboard │  │ REST API │  │ WebSocket│  │ Threat │  │
│  │  (Vue 3) │  │ (Laravel)│  │ (Reverb) │  │  Intel │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS + WSS
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────────┐
   │  Agente │    │  Agente │    │Agente (K8s) │
   │  (VPS)  │    │(Docker) │    │ (DaemonSet) │
   └─────────┘    └─────────┘    └─────────────┘
   SSH + WAF      SSH + WAF +     Ingress WAF +
   + GeoIP        Docker detect   Eventi pod +
   + Metriche     + Inventario    audit API
                  container
```

L'agente è un singolo binario Go statico (~12MB). Nessuna dipendenza, nessun runtime, niente sprechi. Gira come servizio `systemd`, container Docker, o DaemonSet Kubernetes.

**Uso risorse:** <1% CPU, <30MB RAM su un server tipico.

---

## Changelog

Vedi [CHANGELOG.md](CHANGELOG.md) per lo storico completo delle versioni.

Novità recenti:

| Versione | Novità |
|---|---|
| v1.0.0 | Prima release ufficiale InfraFence — correlazione Sigma per il rischio sessione, rilevamento minacce egress/DNS, monitoraggio persistenza esteso, release firmate |
| v0.9.80+ | Supporto DaemonSet Kubernetes, Helm chart, WAF su ingress |
| v0.9.63 | Servizio globale Docker Swarm, Docker secrets |
| v0.9.62 | Label Docker (`infrafence.monitor`, `infrafence.log-path`, `infrafence.domain`) |
| v0.9.50+ | Motore di scoring WAF cumulativo per-IP con pesi configurabili |
| v0.9.44 | Regole di rilevamento dinamiche dalla dashboard (pattern SSH per server) |
| v0.9.42 | Modalità monitor (rilevamento senza blocco) |
| v0.9.40 | Gestione bot con politiche allow/log/block |
| v0.9.33 | Backend firewall ipset (capacità ban 65K+) |
| v0.9.27 | Security scanner (30+ controlli di hardening) |
| v0.9.20 | Rilevamento container Docker e discovery dei log |
| v0.9.0 | WAF iniziale: 15 tipi di attacco OWASP |

---

## Sicurezza & fiducia

Sappiamo di chiedere accesso privilegiato al tuo server. Ecco perché gli ingegneri si fidano di questo agente in produzione:

| | Dettaglio |
|---|---|
| **Open source** | Ogni riga di codice è licenziata MIT. Verificala prima di installare. |
| **Impatto minimo** | Legge gli auth log e i log di accesso web. Nessun accesso al codice applicativo, database, variabili d'ambiente, chiavi SSH o dati utente. |
| **Chain firewall dedicata** | Usa una propria chain iptables `INFRAFENCE` — le tue regole esistenti non vengono mai modificate. |
| **Trasparenza sui dati** | Solo i metadati degli attacchi vengono inviati alla dashboard (IP attaccante, tipo, timestamp). I log grezzi non lasciano mai il tuo server. Nessuna telemetria, nessuna condivisione con terze parti. |
| **Binari firmati** | Ogni release è compilata da GitHub Actions CI con firme [Cosign](https://github.com/sigstore/cosign) e [attestazione di provenance della build](https://github.com/infrafence/infrafence-agent/attestations). |
| **Modalità monitor** | Parti in modalità solo rilevamento — vedi tutto, blocca niente. Attiva la protezione quando sei pronto. |
| **Disinstallazione pulita** | `curl -fsSL https://infrafence.com/install.sh \| sudo bash -s -- --uninstall` — rimuove binario, configurazione e chain firewall. Nessuna modifica residua. |

Dettagli completi in [SECURITY.md](SECURITY.md) e su [infrafence.com/docs/trust](https://infrafence.com/docs/trust).

---

## Contribuire

I contributi sono benvenuti. [Apri una issue](https://github.com/infrafence/infrafence-agent/issues) prima di proporre modifiche importanti.

```bash
# Build
go build -o infrafence-agent ./cmd/infrafence-agent

# Esecuzione locale
./infrafence-agent start
```

---

## Blog

- [I analyzed 250,000 attacks on my Linux servers. Here's what I found.](https://dev.to/infrafence/i-analyzed-250000-attacks-on-my-linux-servers-heres-what-i-found-20o8) — Dati reali da 14 server in produzione: brute force SSH, RCE, probing di file env, path traversal e altro.

---

## Licenza

[MIT](LICENSE) — usalo come preferisci.

---

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a> · Realizzato per gli sviluppatori che gestiscono i propri server
</p>
