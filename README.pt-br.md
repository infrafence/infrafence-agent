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

<h3 align="center">Segurança de servidor que se instala em 30 segundos</h3>

<p align="center">
  Agente Go leve para servidores Linux que detecta ataques em tempo real e os bloqueia automaticamente — na entrada e na saída.<br>
  Força bruta SSH, ataques web, bots, malware, ameaças DNS e de saída, integridade de arquivos, Docker — com padrões seguros, gerenciado a partir de um único painel.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Site</a> ·
  <a href="https://infrafence.com/pricing">Preços</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## O problema

Você sobe um novo VPS Linux e a contagem regressiva começa na hora — bots automatizados o escaneiam, tentam força bruta no SSH e procuram exploits em poucos minutos, muitas vezes antes de você terminar a configuração inicial.

A maior parte dessa atividade passa despercebida. Ninguém está olhando os logs enquanto acontece.

As ferramentas clássicas reagem a linhas de log um servidor por vez e mostram pouco do que aconteceu. As suítes de segurança completas dão visibilidade e automação, mas exigem um trabalho real de configuração e custam mais por servidor.

O InfraFence fica no meio: **instale com um comando, acompanhe tudo ao vivo em um painel e deixe-o bloquear automaticamente — por 9 €/servidor**.

## Início rápido

Crie um token de instalação no painel (Servidores → Adicionar servidor) e depois, no servidor, como root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Quer ver antes o que ele faria? Adicione `--dry-run`: ele baixa o agente, verifica o servidor em modo somente leitura, mostra o plano e não altera nada.

> **[Obtenha seu token em infrafence.com](https://infrafence.com)** — o plano gratuito inclui 1 servidor com proteção completa.

---

## O que ele detecta

### SSH e força bruta
15 padrões de detecção no log do SSH: senhas erradas, usuários inexistentes, falhas de PAM, varreduras antes da autenticação, incompatibilidades de protocolo, trocas de chave interrompidas. Os atacantes são banidos no firewall por períodos progressivos — 24 horas, 7 dias, 30 dias e depois permanente — ou pela duração que você escolher no painel.

### Web Application Firewall
Lê os logs de acesso dos seus servidores web e atribui uma pontuação a cada IP visitante:

| Tipo de ataque | Pontuação | Modo |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Por pontuação |
| UA de scanner (sqlmap, nikto, nmap, nuclei…) | +50 | Por pontuação |
| SQL injection / SSRF / Exploits web | +40 | Por pontuação |
| Armadilha honeypot (caminhos isca definidos como regras personalizadas) | +40 | Por pontuação |
| Path traversal / Header injection | +30 | Por pontuação |
| Força bruta WordPress | +30 | Limite (10 requisições / 2 min) |
| XSS / Busca por `.env` / XMLRPC | +25 | Por pontuação |
| Busca por arquivos de configuração | +20 | Por pontuação |
| Rajada de 404 | +15 | Limite (15 requisições / 5 min) |

A pontuação cai 5 pontos por minuto. Níveis de ação: **observar** (30) → **desacelerar** (60) → **bloquear** (80) → **ban no firewall** (100). No painel você vê cada regra embutida, altera pesos, limites e modo por tipo, desativa padrões individuais e adiciona regras próprias (URL, User-Agent ou Referer, texto ou regex). Cada release publica o catálogo de regras embutidas como `waf-catalog.json`.

### Gestão de bots
Cerca de 1.500 bots conhecidos, a partir de listas públicas atualizadas diariamente ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), ambas MIT) — buscadores, crawlers de IA, ferramentas de SEO, scanners, monitoramento, prévias de links e outros. Bots falsos de buscadores são desmascarados pelo DNS reverso. Para cada categoria, ou bot individual, escolha no painel: **permitir**, **apenas registrar** ou **bloquear**. Bots bloqueados são banidos no firewall; se você permitir alterações no servidor web, também são recusados pelo nginx/Apache.

### Scanner de malware
- **Varredura por assinaturas** — 28 padrões embutidos para web shells, backdoors, mineradores de criptomoedas e kits de phishing
- **Motor YARA** — regras da comunidade para ameaças web do [YARA Forge](https://github.com/YARAHQ/yara-forge), atualizadas diariamente, apenas de fontes cuja licença permite uso comercial (signature-base, ReversingLabs). Requer a ferramenta `yara`, instalável com um clique no painel
- **Cada detecção** explica por que foi sinalizada, a gravidade e o SHA-256 do arquivo, com links para verificá-lo em bancos públicos de malware
- **Reconhecimento de frameworks** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Verificações de segurança dos frameworks** — `.env` exposto, modo DEBUG, APP_KEY, permissões abertas demais, Telescope, wp-config
- **Heurísticas** — entropia de Shannon, anomalias de data em pastas de upload
- **Integridade do sistema** — binários do sistema modificados (`dpkg -V` / `rpm -Va`), indicadores de rootkit
- **Varredura de credenciais** — arquivos `.env` expostos, permissões de chaves SSH, `.git` na pasta web, credenciais de nuvem
- **Varredura do banco WordPress** — scripts injetados em posts e opções, administradores não autorizados
- **Detecção de processos** — mineradores em execução, reverse shells, scripts suspeitos a partir de `/tmp`
- **Quarentena e ignorar** — com um clique, mova um arquivo malicioso para `/var/lib/infrafence/quarantine/` (restaurável) ou marque um falso positivo, que as próximas varreduras ignoram
- **Varreduras agendadas** a cada 3, 6, 12 ou 24 horas, além de "Verificar agora" no painel
- **Verificação em tempo real** — a cada 30 segundos verifica as pastas de upload em busca de novos arquivos PHP

### WAF inline ModSecurity (opcional)
- Apenas se você permitir alterações no servidor web nas configurações do painel — desativado por padrão
- Nunca em servidores cuja configuração é gerenciada por um painel de hospedagem ou ferramenta de gerência de configuração
- Para Apache com mod_security2: 13 regras (SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, bloqueio de scanners), bloqueio na primeira requisição
- Seguro: se o teste de configuração do Apache falhar, a alteração é desfeita

### Ameaças de saída e DNS
- **Conexões de saída** para IPs de listas públicas de threat intelligence, baixadas por cada servidor uma vez por dia (redes sabidamente sequestradas, a lista de hosts comprometidos da Emerging Threats)
- **Inspeção DNS** — cada consulta e resposta DNS é lida no nível do pacote (UDP 53, somente leitura, com um filtro executado no kernel) e ligada ao programa que a fez: consultas a servidores DNS inesperados ou maliciosos, domínios que apontam para IPs maliciosos conhecidos, túneis DNS e malware que gera domínios aleatórios (DGA)
- O serviço DNS do próprio servidor e as consultas de antivírus e antispam são reconhecidos e não sinalizados
- O bloqueio de entrada das redes listadas vem desativado por padrão e é ativado no painel (requer `ipset`)

### Integridade de arquivos e persistência
Hashes SHA-256 de referência, com alerta a cada alteração:
- Arquivos centrais do sistema — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Tarefas agendadas — `/etc/crontab`, `/etc/cron.d/*`, crontabs de cada usuário
- Persistência SSH — `authorized_keys` do root e de cada usuário em `/home/*`
- `/etc/ld.so.preload` e unidades systemd (`/etc/systemd/system/*.service`, `*.timer`)

### Risco das sessões SSH
Acompanha cada sessão SSH do início ao fim — método de autenticação, reputação do IP de origem, horário de login, comandos privilegiados (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — e lhe dá uma pontuação de 0 a 100 ao fechar. **Correlação Sigma**: se outro detector (WAF, integridade, malware, varredura de portas, saída, DNS) disparar enquanto uma sessão está aberta, o risco dessa sessão sobe.

### E mais
- **E-mail, banco de dados e FTP** — detecção de força bruta para Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD e vsftpd
- **Compatível com Docker** — encontra os logs dos containers web e protege as portas publicadas (`DOCKER-USER`)
- **Bloqueio por país** no painel (requer `ipset`)
- **Painéis de hospedagem reconhecidos** (24, por ex. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) e **LiteSpeed / OpenLiteSpeed** — o InfraFence nunca altera uma configuração gerenciada por um painel ou pelo LiteSpeed
- **Modo monitor** — detecta tudo, não bloqueia nada
- **Métricas do sistema** — CPU, memória, disco e rede

---

## Seguro em servidores de produção

- **Verifica antes de alterar** — `infrafence-agent preflight` é uma verificação somente leitura do servidor (firewall e outras ferramentas de segurança, servidores web, painéis de hospedagem, gerência de configuração, operações de pacotes, recursos). O instalador a executa antes de alterar qualquer coisa; o agente, ao iniciar e diariamente.
- **Padrões conservadores** — alterações no servidor web e bloqueio de entrada por listas de ameaças ficam desligados até você ativá-los; as atualizações automáticas podem ser configuradas para apenas notificar.
- **Chains de firewall próprias** — cada regra fica nas chains `INFRAFENCE` do agente, chamadas a partir de `INPUT` (e `DOCKER-USER`), reconstruídas de forma atômica e restauradas automaticamente em até um minuto se outra ferramenta (ufw, firewalld, CSF) as remover. Suas regras existentes nunca são alteradas. IPs na whitelist são isentos, nunca liberados.
- **Desinstalação limpa** — remove o agente e tudo o que ele adicionou: chains de firewall, alterações no servidor web, o serviço.

---

## Como funciona

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

O agente **nunca bane** IPs reservados ou privados, os endereços do próprio servidor, o endereço do painel ou IPs na whitelist — mesmo que seja solicitado.

---

## Instalação

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Opção | Efeito |
|---|---|
| `--dry-run` | Verifica o servidor e mostra o plano; não altera nada |
| `--no-ipset` | Não instala o `ipset` (os bans continuam funcionando, até 500; o bloqueio por país e por listas de ameaças precisa dele) |
| `--uninstall` | Remove o agente e tudo o que ele adicionou |

**Requisitos:** x86-64 ou ARM64, acesso root, `iptables`; systemd, upstart ou sysvinit. O instalador usa `apt`, `dnf` ou `yum` para dependências ausentes e instala o `ipset` apenas quando a verificação do servidor diz que é seguro.

**Testado até agora:** Ubuntu 24.04 (em produção) e Debian 12 (instalador e firewall, nos dois backends do iptables, com e sem ipset). Outras distribuições das famílias RHEL e Debian devem funcionar, mas ainda não foram verificadas — veja [Ainda não disponível](#ainda-não-disponível).

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

Imagem multiarquitetura (amd64 + arm64) publicada a cada release. Um stack para Docker Swarm está em [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Kubernetes

Crie uma chave de cluster no dashboard (Configurações → Kubernetes) e depois:

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Cada nó se registra como um servidor. As opções estão no [README do chart](charts/infrafence-agent/README.md).

### Desinstalação

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuração

Quase tudo é configurado no painel e chega aos servidores em cerca de um segundo: limites de força bruta, duração dos bans, modo monitor, regras do WAF, escolhas de bots, whitelist, países bloqueados, agenda das varreduras de malware, inspeção DNS, alterações no servidor web, bloqueio por listas de ameaças, atualizações automáticas.

No servidor:

| Variável de ambiente | Efeito |
|---|---|
| `AUTH_LOG_PATH` | Log do SSH a ser lido (padrão: `/var/log/auth.log` ou `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs de acesso web, separados por vírgula (padrão: detectados a partir de nginx, Apache, LiteSpeed, painéis, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Substituem os logs de e-mail, banco de dados e FTP detectados |
| `MODSEC_AUDIT_LOG` | Log de auditoria do ModSecurity |
| `GEOIP_DB_PATH` | Banco GeoIP de países |
| `INFRAFENCE_CONFIG` | Arquivo de configuração do agente (padrão `/etc/infrafence/config.json`) |

Defina-as com `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) e reinicie o serviço.

**Labels do Docker** nos seus containers: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (caminhos no host), `infrafence.domain` (domínios).

**Comandos:** `infrafence-agent preflight [--json]` (verificação do servidor somente leitura), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Ainda não disponível

Lista honesta do que ainda não existe:

- **Padrões de detecção SSH por servidor** a partir do painel
- **Bans de IP no ModSecurity** sincronizados a partir do painel
- **Logs apenas no journald** — a detecção de SSH requer `/var/log/auth.log` ou `/var/log/secure`; servidores sem rsyslog (Debian 12+ minimal, Fedora) ainda não são cobertos
- **Mais distribuições verificadas** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

Estamos trabalhando nisso; o [changelog](CHANGELOG.md) informa quando chegam.

---

## Arquitetura

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

O agente é um único binário Go estático (~9 MB, sem dependências), executado como serviço systemd (ou upstart/sysvinit) ou como container Docker. No servidor de demonstração usa cerca de 25 MB de memória e menos de 1% de CPU.

---

## Segurança e confiança

| | Detalhe |
|---|---|
| **Código aberto** | O agente tem licença MIT. Revise cada linha antes de instalar. |
| **O que ele lê** | Logs do sistema e do servidor web, os arquivos dos sites para a varredura de malware (incluindo `.env` e arquivos de configuração), posts e usuários do WordPress para a varredura WordPress, e o tráfego DNS e as conexões de rede do servidor. |
| **O que ele envia** | Apenas eventos de segurança: IP do atacante, tipo, horário e os detalhes necessários para entendê-los — para um ataque web, a linha de log que o disparou; para um malware, o caminho do arquivo e o texto encontrado. Logs e arquivos completos nunca saem do seu servidor. Sem telemetria, sem compartilhamento com terceiros. |
| **Firewall** | Suas próprias chains `INFRAFENCE`; suas regras existentes nunca são alteradas. |
| **Binários assinados** | Cada release é compilado pelo GitHub Actions com assinaturas [Cosign](https://github.com/sigstore/cosign) e [atestado de proveniência](https://github.com/infrafence/infrafence-agent/attestations). |
| **Desinstalação limpa** | `install.sh --uninstall` remove o agente e tudo o que ele adicionou. |

Detalhes em [SECURITY.md](SECURITY.md).

---

## Contribuindo

Contribuições são bem-vindas. [Abra uma issue](https://github.com/infrafence/infrafence-agent/issues) antes de mudanças grandes.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Licença

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
