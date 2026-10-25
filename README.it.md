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

<h3 align="center">Ferma l'attacco. Correggi ciò che l'ha fatto entrare.</h3>

<p align="center">
  InfraFence blocca gli attacchi ai tuoi server Linux mentre accadono, in entrata e in uscita. Poi rinforza la configurazione, applica le patch e verifica il risultato, e annulla ogni correzione che rompe qualcosa.<br>
  Brute force SSH, attacchi web, bot, malware, minacce DNS e in uscita, integrità dei file, Docker — con impostazioni sicure, gestito da un'unica dashboard.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com/it/">Sito</a> ·
  <a href="https://infrafence.com/it/prezzi">Prezzi</a> ·
  <a href="https://infrafence.com/it/documentazione">Documentazione</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Segnalazioni</a>
</p>

---

## Perché InfraFence

- **Vede cosa esce dal server.** Segnala le connessioni in uscita verso IP noti come malevoli e legge ogni query DNS a livello di pacchetto, legata al programma che l'ha fatta: tunnel DNS e domini casuali (DGA) arrivano con nome del processo e pid.
- **Sa chi era collegato.** Ogni sessione SSH riceve un punteggio di rischio da 0 a 100, che sale se WAF, integrità dei file, malware, port scan, traffico in uscita o DNS scattano mentre è aperta.
- **Correzioni che non fermano la produzione.** Dopo ogni modifica (chiusura di una porta, blocco del traffico in uscita, correzione di hardening, virtual patch) controlla SSH e i siti monitorati, e annulla la modifica se smettono di rispondere.
- **Un'AI che agisce solo entro limiti fissi.** AutoMode sceglie da un catalogo fisso di azioni, non esegue mai comandi propri e non blocca mai i tuoi indirizzi né i tuoi accessi SSH. Le azioni che non sono automatiche (per esempio chiudere una porta MySQL o PostgreSQL che non è sotto attacco, alcune correzioni PHP, una patch virtuale fuori dalla regola automatica) attendono l'approvazione nella dashboard, e può deciderle solo un proprietario o un admin che ha effettuato l'accesso con l'autenticazione a due fattori. [Cosa richiede la tua approvazione](https://infrafence.com/it/documentazione/automode#what-needs-your-approval)

Starter è gratis per un server, piani a pagamento da 8,90 € per server al mese: [vedi i prezzi](https://infrafence.com/it/prezzi).

## Avvio rapido

Crea un token di installazione nella dashboard (Server → Aggiungi server), poi sul server, come root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Vuoi prima vedere cosa farebbe? Aggiungi `--dry-run` (non serve il token): scarica l'agente, controlla il server in sola lettura, mostra il piano e non modifica nulla.

> **[Ottieni il tuo token su infrafence.com](https://infrafence.com/add-server)** — il piano Starter è gratuito e include 1 server con protezione completa.

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
- **Blocco per paese** dalla dashboard (richiede `ipset`). L'agent scarica il database dei paesi dalla tua dashboard ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0) solo finché un paese è bloccato, al massimo una volta al giorno. La lista consentiti, gli indirizzi del server stesso e le sessioni SSH aperte quando un paese viene bloccato non vengono mai bloccati. [Blocco per paese](https://infrafence.com/it/documentazione/blocco-per-paese)
- **Pannelli di hosting riconosciuti** (24, ad es. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) e **LiteSpeed / OpenLiteSpeed** — InfraFence non modifica mai una configurazione gestita da un pannello o da LiteSpeed
- **Modalità monitor** — rileva tutto, non blocca nulla
- **Metriche di sistema** — CPU, memoria, disco e rete

---

## Oltre il rilevamento

Cosa aggiunge InfraFence ai rilevatori qui sopra, ognuno con la sua pagina nella [documentazione](https://infrafence.com/it/documentazione):

- **Hardening, vulnerabilità e punteggio di sicurezza** — circa 40 controlli di hardening, con correzione in un clic per quelli sicuri; le vulnerabilità note (CVE) dei pacchetti installati in ordine di rischio reale: prima quelle già sfruttate dagli attaccanti (CISA KEV), poi per probabilità di sfruttamento (EPSS); un punteggio di sicurezza da 0 a 100. [Hardening e vulnerabilità](https://infrafence.com/it/documentazione/hardening-e-vulnerabilita)
- **Hardening di PHP** — trova le impostazioni PHP rischiose in ogni runtime e pool, e corregge quelle sicure. Le correzioni vanno in un file di InfraFence (`zz-infrafence-hardening.ini`), vengono verificate e annullate se un sito smette di rispondere; `cgi.fix_pathinfo` e `disable_functions` richiedono l'approvazione. L'agente sorveglia anche la configurazione di PHP e segnala un valore rischioso appena compare. È hardening e sorveglianza della configurazione: in PHP non viene caricato nulla, e non è una protezione che gira dentro le tue applicazioni. [Hardening di PHP](https://infrafence.com/it/documentazione/hardening-e-vulnerabilita#php-hardening)
- **Chiudi le porte esposte, blocca le destinazioni pericolose** (Pro · AutoMode) — ogni modifica viene verificata e annullata se rompe qualcosa. [Porte e blocco in uscita](https://infrafence.com/it/documentazione/porte-e-blocco-in-uscita)
- **Patch virtuali per le vulnerabilità sfruttate** (Pro · AutoMode) — una regola ModSecurity mirata protegge il software vulnerabile finché non installi l'aggiornamento; Apache con ModSecurity. [Patch virtuali](https://infrafence.com/it/documentazione/patch-virtuali)
- **Modalità emergenza** — un pulsante rosso: per 24 ore InfraFence risponde da solo all'attacco, con lo stesso catalogo sicuro e gli stessi limiti di AutoMode (da Basic in su). [Modalità emergenza](https://infrafence.com/it/documentazione/modalita-emergenza)
- **Avvisi** via email, Slack, Discord, Telegram o webhook, più un riepilogo settimanale via email. [Avvisi](https://infrafence.com/it/documentazione/avvisi)
- **Analisi AI** — un'analisi immediata di ogni incidente su tutti i piani, calcolata nella dashboard; un'analisi con l'AI e correzioni sicure in un clic da Pro in su. [Eventi e attività](https://infrafence.com/it/documentazione/eventi-e-attivita)
- **Rete InfraFence e mappa degli attacchi** — condivisione facoltativa: vengono segnalati gli indirizzi che attaccano più clienti, e i dati della rete compaiono solo dove hanno contribuito 3 o più organizzazioni. [La rete InfraFence](https://infrafence.com/it/documentazione/rete-infrafence) · [Mappa degli attacchi](https://infrafence.com/it/documentazione/mappa-degli-attacchi)
- **Badge di monitoraggio** — il badge «Monitorato da InfraFence» rimanda a una pagina di trasparenza pubblica con l'ora dell'ultimo controllo, gli attacchi bloccati negli ultimi 30 giorni e le protezioni attive. Per dimostrare che il dominio è servito dal tuo server, l'agente mette un file di verifica, `/.well-known/infrafence-verification.txt`, nella document root del sito, e lo rimuove quando il badge viene disattivato. Non è un certificato. [Badge di monitoraggio](https://infrafence.com/it/funzionalita#trust-badge) · [Guarda un esempio di pagina di trasparenza](https://infrafence.com/it/trust/demo)
- **Protezione anche quando la dashboard non risponde** — ban, whitelist e blocchi per paese restano attivi, i nuovi attacchi vengono comunque bannati e gli eventi aspettano in coda. [Quando la dashboard non è raggiungibile](https://infrafence.com/it/documentazione/dashboard-non-raggiungibile)
- **Accanto a CSF e agli altri strumenti** — InfraFence usa solo le proprie catene e non modifica mai i file di CSF né le regole di altri strumenti; dopo `csf -r` rimette le proprie regole in pochi secondi. [Coesistenza con altri strumenti di sicurezza](https://infrafence.com/it/documentazione/coesistenza)
- **Plugin per cPanel & WHM** (disponibile) **ed estensione per Plesk** (in sviluppo) — stato della protezione, ban, rilevamenti, eventi e scansioni per sito dentro il pannello. [cPanel & WHM](https://infrafence.com/it/integrazioni/cpanel-whm) · [Pannelli di hosting](https://infrafence.com/it/documentazione/pannelli-di-hosting) · [Plugin WHM](https://infrafence.com/it/documentazione/plugin-whm)

---

## Sicuro sui server in produzione

- **Controlla prima di modificare** — `infrafence-agent preflight` è una scansione in sola lettura del server (firewall e altri strumenti di sicurezza, web server, pannelli di hosting, gestione della configurazione, operazioni sui pacchetti, risorse). L'installer la esegue prima di modificare qualsiasi cosa; l'agente all'avvio e ogni giorno.
- **Impostazioni prudenti** — le modifiche al web server e il blocco in entrata dalle liste di minacce restano disattivati finché non li attivi; gli aggiornamenti dell'agente sono su «Solo notifica» finché non scegli l'installazione automatica, e vengono installate solo release firmate con cosign.
- **Catene firewall dedicate** — ogni regola sta nelle catene `INFRAFENCE` dell'agente, richiamate da `INPUT` (e `DOCKER-USER`), ricostruite in modo atomico e ripristinate automaticamente entro pochi secondi se un altro strumento (ufw, firewalld, CSF) le rimuove. Le tue regole esistenti non vengono mai modificate. Gli IP in whitelist vengono esclusi, mai aperti.
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
| `--dry-run` | Controlla il server e mostra il piano; non modifica nulla. Non serve il token |
| `--no-ipset` | Non installa `ipset` (i ban funzionano comunque, fino a 500; il blocco per paese e dalle liste di minacce lo richiede) |
| `--skip-checksum` | **Non sicuro.** Installa anche quando il checksum della release non si può scaricare (il binario non viene verificato). Solo per una rete che blocca il file `.sha256` e nient'altro |
| `--uninstall` | Rimuove l'agente e tutto ciò che ha aggiunto |

L'agente viene scaricato solo da GitHub Releases, e l'installer si ferma se il checksum della release manca o non corrisponde. Il certificato radice di Let's Encrypt che può servire (ISRG Root X1) è incluso nello script, con un'impronta fissata, invece di essere scaricato. [Cosa fa l'installer](https://infrafence.com/it/documentazione/cosa-fa-l-installer)

**Requisiti:** x86-64 o ARM64, accesso root, `iptables`; systemd, upstart o sysvinit. L'installer usa `apt`, `dnf` o `yum` per le dipendenze mancanti e installa `ipset` solo quando il controllo del server dice che è sicuro.

**Testato prima di ogni release** su 14 distribuzioni: Ubuntu 20.04, 22.04 e 24.04, Debian 12 e 13, Rocky Linux 8 e 9, AlmaLinux 8 e 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 e 42, Amazon Linux 2023. Su ognuna gira il vero installer, rileva un attacco brute force SSH, lo banna nel firewall e si disinstalla in modo pulito. Le altre distribuzioni delle famiglie Debian e RHEL di solito funzionano: esegui prima l'installer con `--dry-run`. Vedi [Distribuzioni supportate](https://infrafence.com/it/documentazione/distribuzioni-supportate).

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

### Kubernetes

Crea una chiave di cluster nella dashboard (Impostazioni → Kubernetes), poi:

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Ogni nodo si registra come un server. Tutti i valori, gli aggiornamenti e GitOps: [Kubernetes](https://infrafence.com/it/documentazione/kubernetes) nella documentazione, e il [README del chart](charts/infrafence-agent/README.md).

### Disinstallazione

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configurazione

Quasi tutto si configura dalla dashboard e arriva ai server in circa un secondo: soglie di brute force, durata dei ban, modalità monitor, regole WAF, scelte sui bot, whitelist, paesi bloccati, pianificazione delle scansioni malware, ispezione DNS, modifiche al web server, blocco dalle liste di minacce, aggiornamenti automatici. Riferimento completo: [Configurazione](https://infrafence.com/it/documentazione/configurazione).

Sul server:

| Variabile d'ambiente | Effetto |
|---|---|
| `AUTH_LOG_PATH` | File di log SSH da leggere al posto del journal di systemd (predefinito: il journal sui sistemi con systemd, altrimenti `/var/log/auth.log` o `/var/log/secure`) |
| `WEB_LOG_PATH` | Access log web, separati da virgola (predefinito: rilevati da nginx, Apache, LiteSpeed, pannelli, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Sostituiscono i log di posta, database e FTP rilevati |
| `MODSEC_AUDIT_LOG` | Log di audit di ModSecurity |
| `GEOIP_DB_PATH` | Database dei paesi (formato MaxMind DB) da usare al posto di quello scaricato dalla dashboard in `/etc/infrafence/geoip-country.mmdb`; se impostato, non viene scaricato nulla |
| `INFRAFENCE_CONFIG` | File di configurazione dell'agente (predefinito `/etc/infrafence/config.json`) |

Impostale con `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`), poi riavvia il servizio.

**Etichette Docker** sui tuoi container: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (percorsi sull'host), `infrafence.domain` (domini).

**Comandi:** `infrafence-agent preflight [--json]` (controllo del server in sola lettura), `infrafence-agent version` (versione installata), `infrafence-agent check`, `infrafence-agent uninstall --clean`. Tutti i comandi: [Riferimento dei comandi](https://infrafence.com/it/documentazione/riferimento-comandi).

**Pannelli di hosting (cPanel/WHM, Plesk):** i plugin dei pannelli eseguono `infrafence-agent panel <command> --json` come root e leggono un oggetto JSON da stdout (`{"ok": true, ...}` oppure `{"ok": false, "error": "<code>", "message": "..."}`, stato di uscita 0 solo se ok). Comandi: `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score`; quelli che modificano qualcosa richiedono `--actor <utente del pannello>` e vengono riportati alla dashboard come eventi con origine `panel`. Il comando parla con l'agente in esecuzione tramite `/run/infrafence/panel.sock` (solo root, permessi 0600, nessuna porta di rete); se l'agente non è in esecuzione risponde comunque, con `"agent_running": false`. `map` (gli attacchi a questo server per paese e categoria) e `score` (il suo punteggio di sicurezza e l'andamento di 30 giorni) arrivano dalla dashboard, richiedono l'agente 1.0.33 o successivo e l'agente li tiene in cache: al massimo una richiesta ogni 5 minuti per la mappa e ogni 15 minuti per il punteggio, con `"stale": true` quando la dashboard non è raggiungibile. Tutti i campi di ogni risposta: [docs/panel-json.md](docs/panel-json.md) (in inglese).

---

## Non ancora disponibile

Elenco onesto di ciò che oggi non c'è:

- **Schemi di rilevamento SSH per server** dalla dashboard

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
| **Codice consultabile** | L'agente è distribuito con licenza BSL 1.1: gratuito in produzione sui tuoi server e su quelli dei tuoi clienti, completamente trasparente, e puoi verificare ogni riga prima di installarlo. |
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

L'agente è source-available con la [Business Source License 1.1](LICENSE) (licenziante: ComCart S.r.l.). L'uso in produzione è gratuito su qualsiasi numero di server, compresi quelli dei tuoi clienti, purché non lo usi per creare un prodotto concorrente. Quattro anni dopo ogni rilascio, quella versione diventa disponibile con licenza Apache 2.0.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
