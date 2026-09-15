<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.it.md">Italiano</a> ·
  <a href="README.pt-br.md">Português (BR)</a>
</p>

<p align="center">
  <img src="docs/logo.png" alt="InfraFence" width="200">
</p>

<h3 align="center">Segurança de servidor que se instala em 30 segundos</h3>

<p align="center">
  Agente Go leve que detecta ataques em tempo real e os bloqueia automaticamente.<br>
  Força bruta SSH, WAF, gestão de bots, Docker e Kubernetes — zero configuração.
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
  <a href="https://infrafence.com">Site</a> ·
  <a href="https://infrafence.com/docs">Documentação</a> ·
  <a href="https://infrafence.com/docs/installation">Guia de instalação</a> ·
  <a href="https://infrafence.com/pricing">Preços</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## O problema

O VPS Linux médio recebe seu primeiro ataque automatizado **em até 4 minutos** depois de entrar no ar. Força bruta SSH, exploits web, scraping por bots, varreduras de porta.

A maioria dos desenvolvedores só descobre quando já é tarde demais — ou nunca descobre.

O **fail2ban** bloqueia depois do fato, sem visibilidade. O **CrowdSec** exige configuração complexa. Ferramentas enterprise custam $20-200+/host.

O InfraFence preenche essa lacuna: **um comando para instalar, dashboard em tempo real, bloqueio automático, €9/servidor**.

## Início rápido

```bash
# Linux (comando único)
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <SEU_TOKEN>

# Docker
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e INFRAFENCE_TOKEN=<SEU_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest

# Kubernetes (Helm)
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<SUA_API_KEY> \
  --namespace infrafence-system --create-namespace
```

> **[Obtenha seu token em infrafence.com](https://infrafence.com)** — o plano gratuito inclui 1 servidor com proteção completa.

---

## Por que InfraFence

| | fail2ban | CrowdSec | BitNinja | **InfraFence** |
|---|:---:|:---:|:---:|:---:|
| Dashboard em tempo real | — | Pago ($2K+/ano) | Sim | **Sim** |
| Instalação com um comando | — | — | Só cPanel | **Sim** |
| Detecção SSH | Sim | Sim | Sim | **Sim (15 padrões)** |
| Web Application Firewall | — | Parcial | Sim | **Sim (15 tipos OWASP)** |
| Gestão de bots | — | — | Sim | **Sim (70+ fingerprints)** |
| Varredura de malware | — | — | Sim | **Sim (YARA + banco de hashes + quarentena)** |
| Reconhecimento de containers Docker | — | — | — | **Sim** |
| Kubernetes / Helm | — | Sim | — | **Sim (DaemonSet)** |
| Detecção de ameaças de saída (egress & DNS) | — | — | — | **Sim** |
| Modo monitor (apenas detecção) | — | — | — | **Sim** |
| Funciona em qualquer Linux | Sim | Sim | cPanel/Plesk | **Sim** |
| Preço | Grátis | Grátis / $2K+ | €14-52/srv | **€9/srv** |

---

## O que ele detecta

### SSH & força bruta
15 padrões de detecção: senhas incorretas, usuários inválidos, falhas de PAM, varredura pré-autenticação, incompatibilidade de protocolo, quedas na negociação kex. Os padrões são sincronizados a partir do dashboard — ative/desative por servidor sem reiniciar o agente.

### Web Application Firewall

| Tipo de ataque | Pontuação | Modo |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Por pontuação |
| User agent de scanner (sqlmap, nikto, nmap, nuclei...) | +50 | Por pontuação |
| SQL injection / SSRF / Exploit web | +40 | Por pontuação |
| Honeypot (50+ endpoints isca) | +40 | Por pontuação |
| Path traversal / Header injection | +30 | Por pontuação |
| Força bruta WordPress | +30 | Limite (10 req / 2 min) |
| XSS / sondagem `.env` / XMLRPC | +25 | Por pontuação |
| Sondagem de config / Padrão de scanner | +20 | Por pontuação |
| Flood 404 | +15 | Limite (30 req / 5 min) |

Cada detecção soma pontos a uma pontuação por IP. As pontuações decaem -5 pts/min. Níveis de ação: **observar** (30) → **conter** (60) → **bloquear 1h** (80) → **lista negra 24h** (100+). Todos os pesos são configuráveis por servidor.

### Gestão de bots
70+ fingerprints de bots (motores de busca, crawlers de IA, ferramentas de SEO, scanners). Políticas por organização: **permitir** / **registrar** / **bloquear**. Bots bloqueados são rejeitados no nível do nginx/Apache — conexão encerrada antes de chegar à sua aplicação.

### Scanner de malware
- **Varredura por assinatura** — 24 padrões integrados para webshells, backdoors, mineradores de cripto, kits de phishing
- **Correspondência de hash** — mais de 64.000 hashes de malware conhecidos do MalwareBazaar e Linux Malware Detect
- **Motor YARA** — 229 regras relevantes para web (usa a CLI yara se instalada, opcional)
- **Detecção de framework** — detecta automaticamente Laravel, WordPress, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Verificações de segurança de framework** — exposição de .env, modo DEBUG, APP_KEY, permissões abertas demais, Telescope, wp-config
- **Análise heurística** — detecção de entropia de Shannon, anomalias de timestamp em diretórios de upload
- **Integridade do sistema** — `dpkg -V` / `rpm -Va` para binários modificados, indicadores de rootkit (ld.so.preload, processos ocultos, executáveis em /tmp)
- **Varredura de credenciais** — arquivos .env expostos, permissões de chaves SSH, .git na raiz web, credenciais de provedores de nuvem
- **Varredura de banco de dados WP** — scripts injetados em posts/opções, usuários admin fraudulentos
- **Detecção de processos** — mineradores de cripto em execução, reverse shells, scripts suspeitos rodando de /tmp
- **Pontuação de postura de segurança** — 0-100 (nota A-F) com detalhamento por categoria
- **Quarentena** — move arquivos maliciosos para `/var/lib/infrafence/quarantine/` com possibilidade de restauração
- **Varreduras agendadas** — frequência, horário e intensidade configuráveis pelo dashboard
- **Watcher em tempo real** — verifica diretórios de upload a cada 30s em busca de novos arquivos PHP
- **Prevenção de falsos positivos** — checksums do núcleo do WP, severidade contextual, allowlist de usuário com herd immunity entre redes

### WAF inline ModSecurity
- **Detecta automaticamente** Apache + mod_security2 na inicialização (padrão em cPanel/WHM)
- **14 regras estáticas** — SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, bloqueio de scanners
- **Bloqueia na primeira requisição** — o ModSecurity intercepta antes de o tráfego chegar à sua aplicação
- **Regras de ban de IP** — IPs banidos sincronizados do dashboard para o ModSecurity, bloqueio em nível HTTP
- **Zero configuração** — escreve regras automaticamente, configura o Include, recarrega sem downtime
- **Sem impacto** em servidores sem ModSecurity — usa bloqueio via iptables como alternativa

### Detecção de ameaças de saída (egress & DNS)
A maioria das ferramentas só observa o tráfego de *entrada*. O InfraFence também observa o que um host já comprometido faz na *saída* — a mesma threat feed usada para os bans de entrada (Spamhaus DROP, Feodo Tracker e outras) também é verificada contra a atividade de saída:
- **Correspondência de ameaças de saída (egress)** — sinaliza conexões de saída estabelecidas para qualquer IP presente na sua threat feed, capturando um host comprometido se comunicando com infraestrutura C2 que regras de firewall apenas de entrada nunca veem
- **Monitoramento de resolvedores DNS** — sinaliza tráfego DNS de saída (UDP/53) para IPs da threat feed, para resolvedores fora do seu `/etc/resolv.conf` configurado, e "resolver hopping" (muitos resolvedores externos distintos em uma janela curta de tempo) — um sinal precoce de DNS tunneling
- Baseado em polling, no mesmo ciclo dos outros monitores: captura de forma confiável tráfego *sustentado* — tunneling, beaconing repetido — não uma única consulta isolada

### Integridade de arquivos & monitoramento de persistência
Hashing SHA-256 de baseline com alerta instantâneo em caso de alteração, cobrindo tanto os alvos clássicos de "tripwire" quanto técnicas comuns de persistência:
- Arquivos centrais do sistema — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Persistência via tarefas agendadas — `/etc/crontab`, `/etc/cron.d/*`, e **crontabs por usuário** (`/var/spool/cron/crontabs/*` no Debian, `/var/spool/cron/*` no RHEL)
- Persistência via SSH — `authorized_keys` do root e de todo usuário em `/home/*`
- Pontos de rootkit / hijack — `/etc/ld.so.preload` (hijack clássico em userspace via LD_PRELOAD)
- Persistência via systemd — `/etc/systemd/system/*.service` e `*.timer` (um substituto comum do cron para plantar persistência)

### Pontuação de risco de sessões SSH
Acompanha cada sessão SSH do login ao logout — método de autenticação, reputação do IP de origem, horário do login, comandos privilegiados (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — e atribui uma pontuação de 0 a 100 ao encerrar. **Correlação Sigma**: se qualquer outro detector (WAF, integridade, malware, varredura de portas, egress, DNS) disparar enquanto uma sessão está aberta, a pontuação de risco dessa sessão sobe — transformando sinais isolados de baixa confiança em um único alerta de alta confiança vinculado exatamente a quem estava logado naquele momento.

### E mais
- **Proteção de Mail & FTP** — detecção de força bruta em Postfix, Dovecot, Pure-FTPD, MySQL
- **Reconhecimento de Docker** — detecta automaticamente containers web, lê logs via bind mounts e volumes
- **Bloqueio GeoIP** — bloqueia países inteiros pelo dashboard
- **Propagação de bans na rede** — um ban em um servidor se aplica a todos os seus servidores
- **Security scanner** — 30+ verificações de hardening com auto-remediação
- **Varredura de vulnerabilidades** — correspondência de CVE via NVD + Exploit-DB, pontuação EPSS
- **Modo monitor** — detecta ameaças sem bloquear (padrão para novos servidores)
- **Métricas do sistema** — CPU, memória, disco reportados ao dashboard
- **Addon cPanel/WHM** — integração nativa na barra lateral com auto-detecção de cPHulk e domlog

---

## Como funciona

```
auth.log / logs de acesso web / logs Docker / logs ingress K8s
    │
    ▼
Auto-detecção de logs
    │  nginx -T / apachectl -S / docker inspect / API K8s
    │  Resolve bind mounts, volumes, symlinks
    ▼
Goroutines watcher
    │  Detecta força bruta, SQLi, XSS, SSRF, path traversal, web shells...
    ▼
Motor de pontuação de bots (por IP, com decaimento)
    │
    ├─ < 30 pts  → observar (apenas log)
    ├─ ≥ 30 pts  → conter
    ├─ ≥ 80 pts  → bloquear 1h
    └─ ≥ 100 pts → lista negra 24h
            │
            ▼
    ipset add infrafence-bans <IP>
            │  Usa iptables -I INPUT -s <IP> -j DROP como alternativa
            │  ipset: 65K+ IPs  ·  fallback iptables: 500 (rotação FIFO)
            │
            ├──► POST /api/v1/agent/bans → dashboard
            └──► WebSocket propaga o ban para todos os seus servidores
```

O agente **nunca bane** IPs reservados, os próprios IPs do seu servidor, ou o endpoint da API do InfraFence — mesmo que o backend envie uma regra incorreta.

---

## Instalação

### Linux (recomendado)

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <SEU_TOKEN>
```

**Suportados:** Ubuntu 20+, Debian 11+, CentOS 7+, RHEL 8+, Rocky, Alma, Amazon Linux 2023, Fedora
**Requer:** `iptables`, `systemd`, acesso root · **Recomendado:** `ipset` (aumenta a capacidade de ban para 65K+)

### Docker

```bash
docker run -d --name infrafence-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrafence-config:/etc/infrafence \
  -e INFRAFENCE_TOKEN=<SEU_TOKEN> \
  ghcr.io/infrafence/infrafence-agent:latest
```

**Imagem:** `ghcr.io/infrafence/infrafence-agent` — multi-arch (amd64 + arm64), ~40MB

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
INFRAFENCE_TOKEN=<SEU_TOKEN> docker compose up -d infrafence-agent
```

</details>

<details>
<summary>Docker Swarm (serviço global)</summary>

```bash
# Armazene o token como um Docker secret
echo "<SEU_TOKEN>" | docker secret create infrafence_token -

# Implante 1 agente por nó
docker stack deploy -c docker-compose.swarm.yml infrafence
```

Veja [docker-compose.swarm.yml](docker-compose.swarm.yml) para a definição completa da stack.

</details>

### Kubernetes (Helm)

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  --set config.organizationApiKey=<SUA_API_KEY> \
  --set config.serverUrl=https://infrafence.com \
  --namespace infrafence-system --create-namespace
```

Implanta um **DaemonSet** — um agente por nó (incluindo control-plane). RBAC, tolerations e limites de recursos já pré-configurados.

<details>
<summary>values.yaml personalizado</summary>

```yaml
config:
  organizationApiKey: "sua-api-key-da-organizacao"
  serverUrl: "https://infrafence.com"
  clusterName: "production"    # auto-detectado se omitido

resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

tolerations:
  - operator: Exists           # executa em todos os nós
```

```bash
helm install infrafence-agent \
  oci://ghcr.io/infrafence/charts/infrafence-agent \
  -f values.yaml -n infrafence-system --create-namespace
```

</details>

**Chart:** [Artifact Hub](https://artifacthub.io/packages/helm/infrafence/infrafence-agent) · Imagens assinadas com [Cosign](https://github.com/sigstore/cosign) · Helm chart com procedência GPG

### Desinstalação

```bash
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --uninstall
```

---

## Configuração

<details>
<summary><strong>Configuração de WAF por servidor</strong></summary>

Cada tipo de ataque pode ser configurado independentemente pelo dashboard (Server → Web Protection). As alterações sincronizam em até 60 segundos.

- **Ativar/desativar tipos** — desative regras irrelevantes para sua stack (ex.: `wp_bruteforce` em um servidor que não é WordPress)
- **Modo apenas detecção** — registra eventos sem banir
- **Limites personalizados** — sobrescreva os padrões de `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`
- **Pesos de pontuação personalizados** — ajuste os pontos por tipo de detecção

Configuração de WAF `null` → todos os 15 tipos ativos com limites padrão (totalmente retrocompatível).

</details>

<details>
<summary><strong>Labels do Docker</strong></summary>

Configure o monitoramento por container via labels do Docker — sem precisar reiniciar o agente:

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

| Label | Valores | Efeito |
|---|---|---|
| `infrafence.monitor` | `true` / `false` | Força inclusão ou exclusão de um container |
| `infrafence.log-path` | Caminho(s) no host, separados por vírgula | Caminho de log explícito (pula a auto-detecção) |
| `infrafence.domain` | Domínio(s), separados por vírgula | Associa nomes de domínio aos logs |
| `infrafence.waf` | `true` / `false` | Informativo (o WAF é controlado pelo painel) |

**Prioridade**: label `infrafence.log-path` > auto-detecção `nginx -T` > varredura de bind-mount > `docker logs`.

</details>

<details>
<summary><strong>Sobrescrever manualmente o caminho dos logs</strong></summary>

Se a auto-detecção não encontrar seus logs, defina `WEB_LOG_PATH`:

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
<summary><strong>Variáveis de ambiente</strong></summary>

Armazenadas em `/etc/infrafence/agent.conf`:

| Variável | Descrição | Padrão |
|---|---|---|
| `INFRAFENCE_TOKEN` | Token de autenticação do agente | *(do registro)* |
| `INFRAFENCE_SERVER` | URL do servidor do painel | `https://infrafence.com` |
| `INFRAFENCE_LOG_PATH` | Caminho do arquivo de auth log | *(auto-detectado)* |
| `INFRAFENCE_HEARTBEAT` | Intervalo de heartbeat (segundos) | `30` |
| `INFRAFENCE_BAN_THRESHOLD` | Tentativas falhas antes do ban | `5` |
| `INFRAFENCE_WS_ENABLED` | Habilita WebSocket | `true` |
| `INFRAFENCE_GEOIP_ENABLED` | Habilita consultas GeoIP | `true` |
| `WEB_LOG_PATH` | Sobrescreve os caminhos dos logs web | *(auto-detectado)* |

</details>

---

## Solução de problemas

<details>
<summary><code>"Peer's Certificate issuer is not recognized"</code> durante a instalação</summary>

Afeta CentOS 7, RHEL 7 e sistemas com `ca-certificates` desatualizados:

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem
export CURL_CA_BUNDLE=/tmp/isrg.pem
curl -fsSL https://infrafence.com/install.sh | sudo bash -s -- --token <SEU_TOKEN>
```

</details>

<details>
<summary>O agente mostra <code>203/EXEC</code> — o serviço não inicia</summary>

Binário ausente ou corrompido. Restaure do backup:

```bash
cp /usr/local/bin/infrafence-agent.bak /usr/local/bin/infrafence-agent
chmod 755 /usr/local/bin/infrafence-agent
systemctl reset-failed infrafence-agent && systemctl start infrafence-agent
```

Se aparecer `start-limit-hit`:

```bash
systemctl reset-failed infrafence-agent
systemctl start infrafence-agent
```

</details>

<details>
<summary>O WAF não está detectando ataques</summary>

Verifique quais logs o agente está monitorando:

```bash
journalctl -u infrafence-agent | grep webwatcher
```

Se nenhum log for encontrado: os logs do seu servidor web precisam estar acessíveis no host. Para servidores web em Docker, monte o diretório de logs:

```yaml
volumes:
  - /var/log/nginx:/var/log/nginx
```

</details>

Mais soluções de problemas em [infrafence.com/docs/troubleshooting](https://infrafence.com/docs/troubleshooting).

---

## Arquitetura

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
   │ Agente  │    │ Agente  │    │Agente (K8s) │
   │  (VPS)  │    │(Docker) │    │ (DaemonSet) │
   └─────────┘    └─────────┘    └─────────────┘
   SSH + WAF      SSH + WAF +     WAF no Ingress +
   + GeoIP        Detecção Docker Eventos de pod +
   + Métricas     + Inventário    auditoria de API
                  de containers
```

O agente é um único binário Go estático (~12MB). Sem dependências, sem runtime, sem desperdício. Roda como serviço `systemd`, container Docker, ou DaemonSet Kubernetes.

**Uso de recursos:** <1% CPU, <30MB RAM em um servidor típico.

---

## Changelog

Veja [CHANGELOG.md](CHANGELOG.md) para o histórico completo de versões.

Destaques recentes:

| Versão | Destaque |
|---|---|
| v1.0.0 | Primeiro release oficial do InfraFence — correlação Sigma para risco de sessão, detecção de ameaças egress/DNS, monitoramento de persistência estendido, releases assinados |
| v0.9.80+ | Suporte a DaemonSet Kubernetes, Helm chart, WAF no ingress |
| v0.9.63 | Serviço global Docker Swarm, Docker secrets |
| v0.9.62 | Labels do Docker (`infrafence.monitor`, `infrafence.log-path`, `infrafence.domain`) |
| v0.9.50+ | Motor de pontuação WAF cumulativa por IP com pesos configuráveis |
| v0.9.44 | Regras de detecção dinâmicas a partir do dashboard (padrões SSH por servidor) |
| v0.9.42 | Modo monitor (detecção sem bloqueio) |
| v0.9.40 | Gestão de bots com políticas allow/log/block |
| v0.9.33 | Backend de firewall ipset (capacidade de ban 65K+) |
| v0.9.27 | Security scanner (30+ verificações de hardening) |
| v0.9.20 | Detecção de containers Docker e descoberta de logs |
| v0.9.0 | WAF inicial: 15 tipos de ataque OWASP |

---

## Segurança & confiança

Sabemos que estamos pedindo acesso privilegiado ao seu servidor. Veja por que engenheiros confiam neste agente em produção:

| | Detalhe |
|---|---|
| **Código aberto** | Cada linha de código tem licença MIT. Audite antes de instalar. |
| **Footprint mínimo** | Lê auth logs e logs de acesso web. Sem acesso ao código da aplicação, bancos de dados, variáveis de ambiente, chaves SSH ou dados de usuário. |
| **Chain de firewall dedicada** | Usa sua própria chain do iptables chamada `INFRAFENCE` — suas regras existentes nunca são modificadas. |
| **Transparência de dados** | Apenas metadados de ataques são enviados ao seu dashboard (IP do atacante, tipo, timestamp). Os logs brutos nunca saem do seu servidor. Sem telemetria, sem compartilhamento com terceiros. |
| **Binários assinados** | Cada release é compilada pelo GitHub Actions CI com assinaturas [Cosign](https://github.com/sigstore/cosign) e [atestado de procedência do build](https://github.com/infrafence/infrafence-agent/attestations). |
| **Modo monitor** | Comece em modo apenas detecção — veja tudo, bloqueie nada. Ative a proteção quando estiver pronto. |
| **Desinstalação limpa** | `curl -fsSL https://infrafence.com/install.sh \| sudo bash -s -- --uninstall` — remove binário, configuração e chain de firewall. Sem alterações residuais. |

Detalhes completos em [SECURITY.md](SECURITY.md) e em [infrafence.com/docs/trust](https://infrafence.com/docs/trust).

---

## Contribuindo

Contribuições são bem-vindas. [Abra uma issue](https://github.com/infrafence/infrafence-agent/issues) antes de enviar mudanças grandes.

```bash
# Build
go build -o infrafence-agent ./cmd/infrafence-agent

# Executar localmente
./infrafence-agent start
```

---

## Blog

- [I analyzed 250,000 attacks on my Linux servers. Here's what I found.](https://dev.to/infrafence/i-analyzed-250000-attacks-on-my-linux-servers-heres-what-i-found-20o8) — Dados reais de 14 servidores em produção: força bruta SSH, RCE, sondagem de arquivos env, path traversal e mais.

---

## Licença

[MIT](LICENSE) — use como quiser.

---

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a> · Feito para desenvolvedores que administram seus próprios servidores
</p>
