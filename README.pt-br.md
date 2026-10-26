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

<h3 align="center">Pare o ataque. Corrija o que o deixou entrar.</h3>

<p align="center">
  O InfraFence bloqueia ataques aos seus servidores Linux na hora, na entrada e na saída. Depois reforça a configuração, aplica os patches e confere o resultado, e desfaz qualquer correção que quebre algo.<br>
  Força bruta SSH, ataques web, bots, malware, ameaças DNS e de saída, integridade de arquivos, Docker — com padrões seguros, gerenciado a partir de um único painel.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com/pt-br/">Site</a> ·
  <a href="https://infrafence.com/pt-br/pricing">Preços</a> ·
  <a href="https://infrafence.com/pt-br/documentacao">Documentação</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Issues</a>
</p>

---

## Por que InfraFence

- **Ele vê o que sai do servidor.** Ele reporta as conexões de saída para IPs maliciosos conhecidos e lê cada consulta DNS no nível de pacote, ligada ao programa que a fez: túneis DNS e domínios aleatórios (DGA) chegam com o nome do processo e o pid.
- **Ele sabe quem estava logado.** Cada sessão SSH recebe uma pontuação de risco de 0 a 100, que sobe se o WAF, a integridade de arquivos, o malware, uma varredura de portas, o tráfego de saída ou o DNS dispararem enquanto ela está aberta.
- **Correções que não derrubam a produção.** Depois de cada mudança (fechar uma porta, bloquear tráfego de saída, uma correção de hardening, um patch virtual), ele verifica o SSH e os sites monitorados e desfaz a mudança se eles pararem de responder.
- **Uma IA que age só dentro de limites fixos.** O AutoMode escolhe de um catálogo fixo de ações, nunca executa comandos próprios e nunca bloqueia seus próprios endereços nem seus logins SSH. As ações que não são automáticas (por exemplo fechar uma porta MySQL ou PostgreSQL que não está sob ataque, algumas correções de PHP, um patch virtual fora da regra automática) aguardam aprovação no painel, e só um proprietário ou admin conectado com autenticação de dois fatores pode decidi-las. [O que precisa da sua aprovação](https://infrafence.com/pt-br/documentacao/automode#what-needs-your-approval)

O Starter é grátis para um servidor, planos pagos a partir de €8,90 por servidor por mês: [ver preços](https://infrafence.com/pt-br/pricing).

## Início rápido

Crie um token de instalação no painel (Servidores → Adicionar servidor) e depois, no servidor, como root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Quer ver antes o que ele faria? Adicione `--dry-run` (não precisa de token): ele baixa o agente, verifica o servidor em modo somente leitura, mostra o plano e não altera nada.

> **[Obtenha seu token em infrafence.com](https://infrafence.com/add-server)** — o plano Starter é grátis e inclui 1 servidor com proteção completa.

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
- **Bloqueio por país** no painel (requer `ipset`). O agente baixa o banco de países do seu painel ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0) só enquanto houver um país bloqueado, no máximo uma vez por dia. A lista de permitidos, os endereços do próprio servidor e as sessões SSH abertas quando um país é bloqueado nunca são bloqueados. [Bloqueio por país](https://infrafence.com/pt-br/documentacao/bloqueio-por-pais)
- **Painéis de hospedagem reconhecidos** (24, por ex. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) e **LiteSpeed / OpenLiteSpeed** — o InfraFence nunca altera uma configuração gerenciada por um painel ou pelo LiteSpeed
- **Modo monitor** — detecta tudo, não bloqueia nada
- **Métricas do sistema** — CPU, memória, disco e rede

---

## Além da detecção

O que o InfraFence acrescenta aos detectores acima, cada um com sua página na [documentação](https://infrafence.com/pt-br/documentacao):

- **Hardening, vulnerabilidades e pontuação de segurança** — cerca de 40 verificações de hardening, com correção em um clique para as seguras; as vulnerabilidades conhecidas (CVE) dos pacotes instalados por risco real: primeiro as já exploradas por atacantes (CISA KEV), depois pela probabilidade de exploração (EPSS); uma pontuação de segurança de 0 a 100. [Hardening e vulnerabilidades](https://infrafence.com/pt-br/documentacao/hardening-e-vulnerabilidades)
- **Hardening do PHP** — encontra configurações arriscadas do PHP em cada runtime e pool, e corrige as seguras. As correções vão num arquivo do próprio InfraFence (`zz-infrafence-hardening.ini`), são verificadas e desfeitas se um site parar de responder; `cgi.fix_pathinfo` e `disable_functions` precisam de aprovação. O agente também vigia a configuração do PHP e informa um valor arriscado assim que ele aparece. É hardening e vigilância da configuração: nada é carregado no PHP, e não é uma proteção que roda dentro das suas aplicações. [Hardening do PHP](https://infrafence.com/pt-br/documentacao/hardening-e-vulnerabilidades#php-hardening)
- **Feche portas expostas, bloqueie destinos perigosos** (Pro · AutoMode) — cada mudança é verificada e desfeita se quebrar algo. [Portas e bloqueio de saída](https://infrafence.com/pt-br/documentacao/portas-e-bloqueio-de-saida)
- **Patches virtuais para vulnerabilidades exploradas** (Pro · AutoMode) — uma regra ModSecurity específica protege o software vulnerável até você instalar a atualização; Apache com ModSecurity. [Patches virtuais](https://infrafence.com/pt-br/documentacao/patches-virtuais)
- **Modo de emergência** — um botão vermelho: por 24 horas o InfraFence responde sozinho ao ataque, com o mesmo catálogo seguro e os mesmos limites do AutoMode (a partir do Basic). [Modo de emergência](https://infrafence.com/pt-br/documentacao/modo-de-emergencia)
- **Alertas** por e-mail, Slack, Discord, Telegram ou webhook, mais um resumo semanal por e-mail. [Alertas](https://infrafence.com/pt-br/documentacao/alertas)
- **Análise com IA** — uma análise instantânea de cada incidente em todos os planos, calculada no painel; uma análise com IA e correções seguras em um clique a partir do Pro. [Eventos e atividade](https://infrafence.com/pt-br/documentacao/eventos-e-atividade)
- **Rede InfraFence e mapa de ataques** — compartilhar é opcional: endereços que atacam vários clientes são sinalizados, e os números da rede só aparecem onde 3 ou mais organizações contribuíram. [A rede InfraFence](https://infrafence.com/pt-br/documentacao/rede-infrafence) · [Mapa de ataques](https://infrafence.com/pt-br/documentacao/mapa-de-ataques)
- **Selo de monitoramento** — o selo “Monitorado pelo InfraFence” leva a uma página de transparência pública com o horário da última verificação, os ataques bloqueados nos últimos 30 dias e as proteções ativas. Para provar que o domínio é servido pelo seu servidor, o agente coloca um arquivo de verificação, `/.well-known/infrafence-verification.txt`, na raiz de documentos do site, e o remove quando o selo é desativado. Não é um certificado. [Selo de monitoramento](https://infrafence.com/pt-br/features#trust-badge) · [Ver um exemplo de página de transparência](https://infrafence.com/pt-br/trust/demo)
- **Proteção mesmo com o painel inacessível** — bans, whitelist e bloqueios por país continuam valendo, novos ataques continuam sendo banidos e os eventos esperam numa fila. [Quando o painel está inacessível](https://infrafence.com/pt-br/documentacao/painel-inacessivel)
- **Ao lado do CSF e de outras ferramentas** — o InfraFence fica nas próprias chains e nunca altera os arquivos do CSF nem as regras de outra ferramenta; depois de um `csf -r` ele recoloca as próprias regras em poucos segundos. [Coexistência com outras ferramentas de segurança](https://infrafence.com/pt-br/documentacao/coexistencia)
- **Plugin para cPanel & WHM** (disponível) **e extensão para Plesk** (em desenvolvimento), incluídos nos planos Basic, Pro e AutoMode — status da proteção, bans, achados, eventos e varreduras por site dentro do painel de hospedagem. [cPanel & WHM](https://infrafence.com/pt-br/integracoes/cpanel-whm) · [Painéis de hospedagem](https://infrafence.com/pt-br/documentacao/paineis-de-hospedagem) · [Plugin WHM](https://infrafence.com/pt-br/documentacao/plugin-whm)

---

## Seguro em servidores de produção

- **Verifica antes de alterar** — `infrafence-agent preflight` é uma verificação somente leitura do servidor (firewall e outras ferramentas de segurança, servidores web, painéis de hospedagem, gerência de configuração, operações de pacotes, recursos). O instalador a executa antes de alterar qualquer coisa; o agente, ao iniciar e diariamente.
- **Padrões conservadores** — alterações no servidor web e bloqueio de entrada por listas de ameaças ficam desligados até você ativá-los; as atualizações do agente ficam em “Apenas notificar” até você escolher a instalação automática, e só são instaladas versões assinadas com cosign.
- **Chains de firewall próprias** — cada regra fica nas chains `INFRAFENCE` do agente, chamadas a partir de `INPUT` (e `DOCKER-USER`), reconstruídas de forma atômica e restauradas automaticamente em poucos segundos se outra ferramenta (ufw, firewalld, CSF) as remover. Suas regras existentes nunca são alteradas. IPs na whitelist são isentos, nunca liberados.
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
| `--dry-run` | Verifica o servidor e mostra o plano; não altera nada. Não precisa de token |
| `--no-ipset` | Não instala o `ipset` (os bans continuam funcionando, até 500; o bloqueio por país e por listas de ameaças precisa dele) |
| `--skip-checksum` | **Inseguro.** Instala mesmo quando o checksum da release não pode ser baixado (o binário não é verificado). Só para uma rede que bloqueia o arquivo `.sha256` e nada mais |
| `--uninstall` | Remove o agente e tudo o que ele adicionou |

O agente é baixado só do GitHub Releases, e o instalador para se o checksum da versão estiver faltando ou não bater. O certificado raiz do Let's Encrypt que pode ser necessário (ISRG Root X1) vem embutido no script, com uma impressão digital fixa, em vez de ser baixado. [O que o instalador faz](https://infrafence.com/pt-br/documentacao/o-que-o-instalador-faz)

**Requisitos:** x86-64 ou ARM64, acesso root, `iptables`; systemd, upstart ou sysvinit. O instalador usa `apt`, `dnf` ou `yum` para dependências ausentes e instala o `ipset` apenas quando a verificação do servidor diz que é seguro.

**Testado antes de cada versão** em 14 distribuições: Ubuntu 20.04, 22.04 e 24.04, Debian 12 e 13, Rocky Linux 8 e 9, AlmaLinux 8 e 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 e 42, Amazon Linux 2023. Em cada uma roda o instalador real, detecta um ataque de força bruta SSH, bane o endereço no firewall e desinstala sem deixar rastros. Outras distribuições das famílias Debian e RHEL costumam funcionar: rode antes o instalador com `--dry-run`. Veja [Distribuições suportadas](https://infrafence.com/pt-br/documentacao/distribuicoes-suportadas).

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

Cada nó se registra como um servidor. Todos os valores, atualizações e GitOps: [Kubernetes](https://infrafence.com/pt-br/documentacao/kubernetes) na documentação, e o [README do chart](charts/infrafence-agent/README.md).

### Desinstalação

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuração

Quase tudo é configurado no painel e chega aos servidores em cerca de um segundo: limites de força bruta, duração dos bans, modo monitor, regras do WAF, escolhas de bots, whitelist, países bloqueados, agenda das varreduras de malware, inspeção DNS, alterações no servidor web, bloqueio por listas de ameaças, atualizações automáticas. Referência completa: [Configuração](https://infrafence.com/pt-br/documentacao/configuracao).

No servidor:

| Variável de ambiente | Efeito |
|---|---|
| `AUTH_LOG_PATH` | Arquivo de log do SSH lido no lugar do journal do systemd (padrão: o journal em sistemas com systemd; senão, `/var/log/auth.log` ou `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs de acesso web, separados por vírgula (padrão: detectados a partir de nginx, Apache, LiteSpeed, painéis, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Substituem os logs de e-mail, banco de dados e FTP detectados |
| `MODSEC_AUDIT_LOG` | Log de auditoria do ModSecurity |
| `GEOIP_DB_PATH` | Banco de países (formato MaxMind DB) usado no lugar do baixado do painel em `/etc/infrafence/geoip-country.mmdb`; se definido, nada é baixado |
| `INFRAFENCE_CONFIG` | Arquivo de configuração do agente (padrão `/etc/infrafence/config.json`) |

Defina-as com `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) e reinicie o serviço.

**Labels do Docker** nos seus containers: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (caminhos no host), `infrafence.domain` (domínios).

**Comandos:** `infrafence-agent preflight [--json]` (verificação do servidor somente leitura), `infrafence-agent version` (versão instalada), `infrafence-agent check`, `infrafence-agent uninstall --clean`. Todos os comandos: [Referência de comandos](https://infrafence.com/pt-br/documentacao/referencia-de-comandos).

**Painéis de hospedagem (cPanel/WHM, Plesk):** os plugins dos painéis executam `infrafence-agent panel <command> --json` como root e leem um objeto JSON do stdout (`{"ok": true, ...}` ou `{"ok": false, "error": "<code>", "message": "..."}`, código de saída 0 só quando ok). Comandos: `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score`; os que alteram algo exigem `--actor <usuário do painel>` e são informados ao painel do InfraFence como eventos com origem `panel`. O comando fala com o agente em execução por `/run/infrafence/panel.sock` (só root, modo 0600, nenhuma porta de rede); sem o agente em execução ele responde mesmo assim, com `"agent_running": false`. Os plugins são para os planos Basic, Pro e AutoMode (agente 1.0.34 ou mais recente): `status` sempre responde, com `"entitled"` e `"entitlement"` (`ok`, `plan_required`, `unpaid`, `unknown`); qualquer outro comando responde só esse erro, sem dados, quando a organização não tem direito (um plano sem os plugins, a proteção desligada após 24 horas de recusa, ou um plano ainda desconhecido). O plano da última sincronização bem-sucedida é mantido entre reinícios, então uma queda do painel do InfraFence não esvazia o plugin. `map` (os ataques a este servidor por país e categoria) e `score` (sua pontuação de segurança e a tendência de 30 dias) vêm do painel do InfraFence, exigem o agente 1.0.33 ou mais recente e ficam em cache no agente: no máximo uma requisição a cada 5 minutos para o mapa e a cada 15 minutos para a pontuação, com `"stale": true` quando o painel não pode ser alcançado. Todos os campos de cada resposta: [docs/panel-json.md](docs/panel-json.md) (em inglês).

**Aberto ou resolvido:** cada evento de problema que o agente informa (uma porta de banco de dados exposta, um arquivo de sistema alterado, uma configuração de PHP arriscada, malware...) traz `details.subject` (`port:tcp/3306`, `file:/etc/passwd`...). A partir da 1.0.34, `panel events` e `panel findings` dizem se cada problema ainda está `open` ou `resolved` (`subject`, `state`, `resolved_at`, `resolved_how`): resolvido no painel do InfraFence, ou corrigido pelo próprio agente (uma porta fechada pelo firewall dele, uma correção aplicada e verificada, um arquivo em quarentena, um pacote atualizado). Uma porta de banco de dados que o firewall do agente fecha não é mais informada como exposta quando o agente reinicia. Detalhes: [docs/panel-json.md](docs/panel-json.md#problems-and-resolution) (em inglês).

**Versão do plugin:** o plugin do painel é atualizado pelo dashboard (Plugins de painéis), não junto com o agente. A partir da 1.0.35 o agente lê a versão do plugin do WHM instalado (somente leitura: `/usr/local/share/infrafence-whm/VERSION`, senão o pacote `infrafence-whm`; na inicialização e no máximo uma vez por hora) e a envia com o heartbeat (`panel_plugin`). `panel status` a mostra como `plugin_installed`, ao lado de `plugin_latest`, a versão mais recente que o dashboard envia na sincronização, para que o plugin possa avisar quando há uma atualização. Detalhes: [docs/panel-json.md](docs/panel-json.md#status).

---

## Ainda não disponível

Lista honesta do que ainda não existe:

- **Padrões de detecção SSH por servidor** a partir do painel

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
| **Código disponível** | O agente tem licença BSL 1.1: gratuito em produção nos seus servidores e nos dos seus clientes, totalmente transparente, e você pode revisar cada linha antes de instalar. |
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

O agente é source-available sob a [Business Source License 1.1](LICENSE) (licenciante: ComCart S.r.l.). O uso em produção é gratuito em qualquer número de servidores, inclusive nos dos seus clientes, desde que você não o use para criar um produto concorrente. Quatro anos após cada versão, ela passa a estar disponível sob a licença Apache 2.0.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
