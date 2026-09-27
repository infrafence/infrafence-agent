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

<h3 align="center">Seguridad de servidores que se instala en 30 segundos</h3>

<p align="center">
  Agente Go ligero para servidores Linux que detecta ataques en tiempo real y los bloquea automáticamente — de entrada y de salida.<br>
  Fuerza bruta SSH, ataques web, bots, malware, amenazas DNS y de salida, integridad de archivos, Docker — con valores por defecto seguros, gestionado desde un único panel.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com">Sitio web</a> ·
  <a href="https://infrafence.com/pricing">Precios</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Incidencias</a>
</p>

---

## El problema

Levantas un VPS Linux nuevo y la cuenta atrás empieza al instante — bots automatizados lo escanean, intentan fuerza bruta contra SSH y buscan exploits en pocos minutos, a menudo antes de que termines la configuración inicial.

La mayor parte de esta actividad pasa desapercibida. Nadie mira los logs mientras ocurre.

Las herramientas clásicas reaccionan a líneas de log servidor por servidor y te muestran poco de lo que pasó. Las suites de seguridad completas dan visibilidad y automatización, pero requieren un trabajo real de configuración y cuestan más por servidor.

InfraFence está en medio: **instálalo con un comando, míralo todo en directo desde un panel y deja que bloquee automáticamente — por 9 €/servidor**.

## Inicio rápido

Crea un token de instalación en el panel (Servidores → Añadir servidor) y después, en el servidor, como root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

¿Quieres ver antes lo que haría? Añade `--dry-run`: descarga el agente, revisa el servidor en solo lectura, muestra el plan y no cambia nada.

> **[Consigue tu token en infrafence.com](https://infrafence.com)** — el plan gratuito incluye 1 servidor con protección completa.

---

## Qué detecta

### SSH y fuerza bruta
15 patrones de detección en el log de SSH: contraseñas incorrectas, usuarios inexistentes, fallos de PAM, escaneos previos a la autenticación, incompatibilidades de protocolo, intercambios de claves interrumpidos. Los atacantes se banean en el firewall durante periodos crecientes — 24 horas, 7 días, 30 días y luego permanente — o durante el tiempo que elijas en el panel.

### Web Application Firewall
Lee los logs de acceso de tus servidores web y puntúa cada IP visitante:

| Tipo de ataque | Puntuación | Modo |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Por puntuación |
| UA de escáner (sqlmap, nikto, nmap, nuclei…) | +50 | Por puntuación |
| SQL injection / SSRF / Exploits web | +40 | Por puntuación |
| Trampa honeypot (rutas señuelo definidas como reglas propias) | +40 | Por puntuación |
| Path traversal / Header injection | +30 | Por puntuación |
| Fuerza bruta WordPress | +30 | Umbral (10 peticiones / 2 min) |
| XSS / Búsqueda de `.env` / XMLRPC | +25 | Por puntuación |
| Búsqueda de archivos de configuración | +20 | Por puntuación |
| Ráfaga de 404 | +15 | Umbral (15 peticiones / 5 min) |

La puntuación baja 5 puntos por minuto. Niveles de acción: **observar** (30) → **frenar** (60) → **bloquear** (80) → **ban en el firewall** (100). En el panel ves cada regla integrada, cambias pesos, umbrales y modo por tipo, desactivas patrones concretos y añades reglas propias (URL, User-Agent o Referer, texto o regex). Cada release publica el catálogo de reglas integradas como `waf-catalog.json`.

### Gestión de bots
Unos 1.500 bots conocidos, a partir de listas públicas actualizadas a diario ([crawler-user-agents](https://github.com/monperrus/crawler-user-agents), [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt), ambas MIT) — buscadores, crawlers de IA, herramientas SEO, escáneres, monitorización, vistas previas de enlaces y más. Los bots falsos de buscadores se desenmascaran mediante DNS inverso. Para cada categoría, o bot concreto, elige en el panel: **permitir**, **solo registrar** o **bloquear**. Los bots bloqueados se banean en el firewall; si permites cambios en el servidor web, también los rechaza nginx/Apache.

### Escáner de malware
- **Escaneo por firmas** — 28 patrones integrados para web shells, backdoors, mineros de criptomonedas y kits de phishing
- **Motor YARA** — reglas de la comunidad para amenazas web de [YARA Forge](https://github.com/YARAHQ/yara-forge), actualizadas a diario, solo de fuentes cuya licencia permite el uso comercial (signature-base, ReversingLabs). Requiere la herramienta `yara`, instalable con un clic desde el panel
- **Cada detección** explica por qué se marcó, la gravedad y el SHA-256 del archivo, con enlaces para comprobarlo en bases de datos públicas de malware
- **Reconocimiento de frameworks** — WordPress, Laravel, Django, Symfony, CakePHP, CodeIgniter, Node/Express, Rails, Joomla, Drupal
- **Comprobaciones de seguridad de frameworks** — `.env` expuesto, modo DEBUG, APP_KEY, permisos demasiado abiertos, Telescope, wp-config
- **Heurísticas** — entropía de Shannon, anomalías de fecha en carpetas de subida
- **Integridad del sistema** — binarios del sistema modificados (`dpkg -V` / `rpm -Va`), indicadores de rootkit
- **Escaneo de credenciales** — archivos `.env` expuestos, permisos de claves SSH, `.git` en la carpeta web, credenciales de la nube
- **Escaneo de la base de datos de WordPress** — scripts inyectados en entradas y opciones, administradores no autorizados
- **Detección de procesos** — mineros en ejecución, reverse shells, scripts sospechosos desde `/tmp`
- **Cuarentena e ignorar** — con un clic mueves un archivo malicioso a `/var/lib/infrafence/quarantine/` (restaurable) o marcas un falso positivo, que los siguientes escaneos omiten
- **Escaneos programados** cada 3, 6, 12 o 24 horas, además de "Escanear ahora" desde el panel
- **Comprobación en tiempo real** — revisa cada 30 segundos las carpetas de subida en busca de nuevos archivos PHP

### WAF en línea ModSecurity (opcional)
- Solo si permites cambios en el servidor web en los ajustes del panel — desactivado por defecto
- Nunca en servidores cuya configuración gestiona un panel de hosting o una herramienta de gestión de configuración
- Para Apache con mod_security2: 13 reglas (SQL injection, XSS, RCE, SSRF, path traversal, Shellshock, Log4Shell, Spring4Shell, bloqueo de escáneres), bloqueo en la primera petición
- Seguro: si la prueba de configuración de Apache falla, el cambio se deshace

### Amenazas de salida y DNS
- **Conexiones de salida** hacia IPs de listas públicas de threat intelligence, que cada servidor descarga una vez al día (redes conocidas como secuestradas, la lista de hosts comprometidos de Emerging Threats)
- **Inspección DNS** — cada consulta y respuesta DNS se lee a nivel de paquete (UDP 53, solo lectura, con un filtro que se ejecuta en el kernel) y se vincula al programa que la hizo: consultas a servidores DNS inesperados o maliciosos, dominios que apuntan a IPs maliciosas conocidas, túneles DNS y malware que genera dominios aleatorios (DGA)
- El servicio DNS del propio servidor y las consultas de antivirus y antispam se reconocen y no se marcan
- El bloqueo de entrada de las redes listadas está desactivado por defecto y se activa desde el panel (requiere `ipset`)

### Integridad de archivos y persistencia
Hashes SHA-256 de referencia, con alerta ante cualquier cambio:
- Archivos centrales del sistema — `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` (+ `sudoers.d/*`), `/etc/ssh/sshd_config`, `/etc/hosts`, `/etc/resolv.conf`
- Tareas programadas — `/etc/crontab`, `/etc/cron.d/*`, crontabs de cada usuario
- Persistencia SSH — `authorized_keys` de root y de cada usuario en `/home/*`
- `/etc/ld.so.preload` y unidades systemd (`/etc/systemd/system/*.service`, `*.timer`)

### Riesgo de las sesiones SSH
Sigue cada sesión SSH de principio a fin — método de autenticación, reputación de la IP de origen, hora de acceso, comandos privilegiados (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — y le asigna una puntuación de 0 a 100 al cerrarse. **Correlación Sigma**: si otro detector (WAF, integridad, malware, escaneo de puertos, salida, DNS) salta mientras una sesión está abierta, el riesgo de esa sesión sube.

### Y más
- **Correo, bases de datos y FTP** — detección de fuerza bruta para Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD y vsftpd
- **Compatible con Docker** — encuentra los logs de los contenedores web y protege los puertos publicados (`DOCKER-USER`)
- **Bloqueo por país** desde el panel (requiere `ipset`)
- **Paneles de hosting reconocidos** (24, p. ej. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) y **LiteSpeed / OpenLiteSpeed** — InfraFence nunca modifica una configuración gestionada por un panel o por LiteSpeed
- **Modo monitor** — lo detecta todo, no bloquea nada
- **Métricas del sistema** — CPU, memoria, disco y red

---

## Seguro en servidores de producción

- **Revisa antes de cambiar** — `infrafence-agent preflight` es una revisión del servidor en solo lectura (firewall y otras herramientas de seguridad, servidores web, paneles de hosting, gestión de configuración, operaciones de paquetes, recursos). El instalador la ejecuta antes de cambiar nada; el agente, al arrancar y cada día.
- **Valores por defecto prudentes** — los cambios en el servidor web y el bloqueo de entrada por listas de amenazas están apagados hasta que los activas; las actualizaciones automáticas pueden configurarse como solo aviso.
- **Cadenas de firewall propias** — cada regla vive en las cadenas `INFRAFENCE` del agente, llamadas desde `INPUT` (y `DOCKER-USER`), reconstruidas de forma atómica y restauradas automáticamente en menos de un minuto si otra herramienta (ufw, firewalld, CSF) las elimina. Tus reglas existentes nunca se modifican. Las IPs en la lista blanca quedan exentas, nunca abiertas.
- **Desinstalación limpia** — elimina el agente y todo lo que añadió: cadenas de firewall, cambios en el servidor web, el servicio.

---

## Cómo funciona

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

El agente **nunca banea** IPs reservadas o privadas, las direcciones del propio servidor, la dirección del panel ni las IPs de la lista blanca — aunque se le pida.

---

## Instalación

### Linux

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

| Opción | Efecto |
|---|---|
| `--dry-run` | Revisa el servidor y muestra el plan; no cambia nada |
| `--no-ipset` | No instala `ipset` (los baneos siguen funcionando, hasta 500; el bloqueo por país y por listas de amenazas lo necesita) |
| `--uninstall` | Elimina el agente y todo lo que añadió |

**Requisitos:** x86-64 o ARM64, acceso root, `iptables`; systemd, upstart o sysvinit. El instalador usa `apt`, `dnf` o `yum` para las dependencias que falten e instala `ipset` solo cuando la revisión del servidor indica que es seguro.

**Probado hasta ahora:** Ubuntu 24.04 (en producción) y Debian 12 (instalador y firewall, en ambos backends de iptables, con y sin ipset). Otras distribuciones de las familias RHEL y Debian deberían funcionar, pero aún no están verificadas — ver [Aún no disponible](#aún-no-disponible).

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

Imagen multiarquitectura (amd64 + arm64) publicada con cada release. Un stack para Docker Swarm está en [docker-compose.swarm.yml](docker-compose.swarm.yml).

### Desinstalación

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuración

Casi todo se configura desde el panel y llega a los servidores en aproximadamente un segundo: umbrales de fuerza bruta, duración de los baneos, modo monitor, reglas del WAF, decisiones sobre bots, lista blanca, países bloqueados, programación de los escaneos de malware, inspección DNS, cambios en el servidor web, bloqueo por listas de amenazas, actualizaciones automáticas.

En el servidor:

| Variable de entorno | Efecto |
|---|---|
| `AUTH_LOG_PATH` | Log de SSH que se lee (por defecto: `/var/log/auth.log` o `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs de acceso web, separados por comas (por defecto: detectados a partir de nginx, Apache, LiteSpeed, paneles, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Sustituyen los logs de correo, base de datos y FTP detectados |
| `MODSEC_AUDIT_LOG` | Log de auditoría de ModSecurity |
| `GEOIP_DB_PATH` | Base de datos GeoIP de países |
| `INFRAFENCE_CONFIG` | Archivo de configuración del agente (por defecto `/etc/infrafence/config.json`) |

Defínelas con `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) y reinicia el servicio.

**Etiquetas de Docker** en tus contenedores: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (rutas en el host), `infrafence.domain` (dominios).

**Comandos:** `infrafence-agent preflight [--json]` (revisión del servidor en solo lectura), `infrafence-agent check`, `infrafence-agent uninstall --clean`.

---

## Aún no disponible

Lista honesta de lo que todavía no existe:

- **Kubernetes** — el chart de Helm y el DaemonSet existen, pero el panel aún no registra agentes de un clúster
- **Propagación de baneos** — un baneo se aplica en el servidor que lo detectó, todavía no en todos tus servidores
- **Comprobaciones de hardening y escaneo de CVE** — el código está en el agente, pero el panel aún no puede lanzarlos
- **Puntuación de seguridad** (0-100) — la calcula el agente, pero aún no se muestra en el panel
- **Patrones de detección SSH por servidor** desde el panel
- **Baneos de IP en ModSecurity** sincronizados desde el panel
- **Logs solo en journald** — la detección SSH requiere `/var/log/auth.log` o `/var/log/secure`; los servidores sin rsyslog (Debian 12+ minimal, Fedora) aún no están cubiertos
- **Más distribuciones verificadas** (Rocky, AlmaLinux, CentOS Stream, Fedora, Amazon Linux)

Estamos trabajando en ello; el [changelog](CHANGELOG.md) indica cuándo llegan.

---

## Arquitectura

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

El agente es un único binario Go estático (~9 MB, sin dependencias), que se ejecuta como servicio systemd (o upstart/sysvinit) o como contenedor Docker. En el servidor de demostración usa unos 25 MB de memoria y menos del 1 % de CPU.

---

## Seguridad y confianza

| | Detalle |
|---|---|
| **Código abierto** | El agente tiene licencia MIT. Revisa cada línea antes de instalarlo. |
| **Qué lee** | Logs del sistema y del servidor web, los archivos de los sitios para el escaneo de malware (incluidos `.env` y archivos de configuración), entradas y usuarios de WordPress para el escaneo de WordPress, y el tráfico DNS y las conexiones de red del servidor. |
| **Qué envía** | Solo eventos de seguridad: IP del atacante, tipo, hora y los detalles necesarios para entenderlos — para un ataque web, la línea de log que lo disparó; para un malware, la ruta del archivo y el texto encontrado. Los logs y archivos completos nunca salen de tu servidor. Sin telemetría, sin compartir con terceros. |
| **Firewall** | Sus propias cadenas `INFRAFENCE`; tus reglas existentes nunca se modifican. |
| **Binarios firmados** | Cada release se compila con GitHub Actions con firmas [Cosign](https://github.com/sigstore/cosign) y [atestación de procedencia](https://github.com/infrafence/infrafence-agent/attestations). |
| **Desinstalación limpia** | `install.sh --uninstall` elimina el agente y todo lo que añadió. |

Detalles en [SECURITY.md](SECURITY.md).

---

## Contribuir

Las contribuciones son bienvenidas. [Abre una incidencia](https://github.com/infrafence/infrafence-agent/issues) antes de cambios grandes.

```bash
go build -o infrafence-agent ./cmd/infrafence-agent
go test ./...
bash scripts/firewall-integration.sh   # real firewall tests in Docker
```

## Licencia

[MIT](LICENSE)

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
