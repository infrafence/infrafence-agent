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

<h3 align="center">Detén el ataque. Corrige lo que lo dejó entrar.</h3>

<p align="center">
  InfraFence bloquea los ataques a tus servidores Linux en el momento, de entrada y de salida. Después refuerza la configuración, aplica los parches y comprueba el resultado, y deshace cualquier corrección que rompa algo.<br>
  Fuerza bruta SSH, ataques web, bots, malware, amenazas DNS y de salida, integridad de archivos, Docker — con valores por defecto seguros, gestionado desde un único panel.
</p>

<p align="center">
  <a href="https://github.com/infrafence/infrafence-agent/releases"><img src="https://img.shields.io/github/v/release/infrafence/infrafence-agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License: BSL 1.1"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/infrafence/infrafence-agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/infrafence/infrafence-agent"><img src="https://api.securityscorecards.dev/projects/github.com/infrafence/infrafence-agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://infrafence.com/es/">Sitio web</a> ·
  <a href="https://infrafence.com/es/pricing">Precios</a> ·
  <a href="https://infrafence.com/es/documentacion">Documentación</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://github.com/infrafence/infrafence-agent/issues">Incidencias</a>
</p>

---

## Por qué InfraFence

- **Ve lo que sale del servidor.** Informa de las conexiones de salida hacia IP maliciosas conocidas y lee cada consulta DNS a nivel de paquete, ligada al programa que la hizo: los túneles DNS y los dominios aleatorios (DGA) llegan con el nombre del proceso y su pid.
- **Sabe quién estaba conectado.** Cada sesión SSH recibe una puntuación de riesgo de 0 a 100, que sube si el WAF, la integridad de archivos, el malware, un escaneo de puertos, el tráfico de salida o el DNS saltan mientras está abierta.
- **Correcciones que no tumban producción.** Tras cada cambio (cerrar un puerto, bloquear tráfico de salida, una corrección de hardening, un parche virtual) comprueba SSH y los sitios monitorizados, y deshace el cambio si dejan de responder.
- **Una IA que actúa solo dentro de límites fijos.** AutoMode elige de un catálogo fijo de acciones, nunca ejecuta comandos propios y nunca bloquea tus propias direcciones ni tus accesos SSH. Las acciones que no son automáticas (por ejemplo cerrar un puerto de MySQL o PostgreSQL que no está bajo ataque, algunas correcciones de PHP, un parche virtual fuera de la regla automática) esperan la aprobación en el panel, y solo puede decidirlas un propietario o administrador que haya iniciado sesión con la autenticación en dos pasos. [Qué necesita tu aprobación](https://infrafence.com/es/documentacion/automode#what-needs-your-approval)

Starter es gratis para un servidor, planes de pago desde 8,90 € por servidor al mes: [ver precios](https://infrafence.com/es/pricing).

## Inicio rápido

Crea un token de instalación en el panel (Servidores → Añadir servidor) y después, en el servidor, como root:

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

¿Quieres ver antes lo que haría? Añade `--dry-run` (no hace falta token): descarga el agente, revisa el servidor en solo lectura, muestra el plan y no cambia nada.

> **[Consigue tu token en infrafence.com](https://infrafence.com/add-server)** — el plan Starter es gratuito e incluye 1 servidor con protección completa.

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
Sigue cada sesión SSH de principio a fin — método de autenticación, reputación de la IP de origen, hora de acceso, comandos privilegiados (`sudo`, `useradd`, `passwd`, `crontab`, `su`) — y le asigna una puntuación de 0 a 100 al cerrarse. **Correlación Sigma**: si otro detector (WAF, integridad, malware, escaneo de puertos, salida, DNS) salta mientras una sesión está abierta, el riesgo de esa sesión sube. **Automatizaciones recurrentes**: la misma clave desde la misma dirección a intervalos regulares (un panel de despliegue como Coolify que entra como root cada pocos minutos, una tarea de copia de seguridad) se reconoce; sus sesiones se siguen registrando, puntuadas solo por sus comandos (factor `recurring_automation`, gravedad info). Una clave nueva o una dirección nueva mantienen la puntuación normal.

### Y más
- **Escaneos de puertos** — se ve cada intento de conexión entrante (TCP SYN, filtro de solo lectura en el kernel): 15 o más puertos desde una dirección en 10 minutos, o 30 o más desde 3 o más direcciones de una misma red, es un escaneo de puertos. Solo cuentan los puertos a los que nada respondió: nunca los servicios abiertos, ni las conexiones de datos de un cliente FTP en modo pasivo (FileZilla) al rango pasivo de Pure-FTPd, ProFTPD o vsftpd, leído de su configuración (cPanel incluido); el mismo cliente probando otros puertos se sigue reportando. El bloqueo de los escáneres de puertos está desactivado por defecto
- **Correo, bases de datos y FTP** — detección de fuerza bruta para Postfix, Dovecot, MySQL, PostgreSQL, MongoDB, Pure-FTPd, ProFTPD y vsftpd
- **Compatible con Docker** — encuentra los logs de los contenedores web y protege los puertos publicados (`DOCKER-USER`)
- **Bloqueo por país** desde el panel (requiere `ipset`). El agente descarga la base de datos de países desde tu panel ([DB-IP](https://db-ip.com) IP to Country Lite, CC BY 4.0) solo mientras haya un país bloqueado, como máximo una vez al día. La lista de permitidos, las direcciones del propio servidor y las sesiones SSH con acceso iniciado cuando se bloquea un país nunca se bloquean (una conexión que todavía intenta iniciar sesión, como un ataque de fuerza bruta, no cuenta). [Bloqueo por país](https://infrafence.com/es/documentacion/bloqueo-por-pais)
- **Paneles de hosting reconocidos** (24, p. ej. cPanel/WHM, Plesk, DirectAdmin, CyberPanel, HestiaCP, Coolify, Easypanel) y **LiteSpeed / OpenLiteSpeed** — InfraFence nunca modifica una configuración gestionada por un panel o por LiteSpeed
- **Modo monitor** — lo detecta todo, no bloquea nada
- **Métricas del sistema** — CPU, memoria, disco y red

---

## Más allá de la detección

Lo que InfraFence añade a los detectores anteriores, cada uno con su página en la [documentación](https://infrafence.com/es/documentacion):

- **Hardening, vulnerabilidades y puntuación de seguridad** — unos 40 controles de hardening, con corrección en un clic para los seguros; las vulnerabilidades conocidas (CVE) de los paquetes instalados por riesgo real: primero las ya explotadas por atacantes (CISA KEV), luego por probabilidad de explotación (EPSS); una puntuación de seguridad de 0 a 100. Los controles SSH leen la configuración que sshd usa de verdad (`sshd -T`, o los archivos en el orden de sshd) e indican el archivo y la línea que fijan cada valor: un archivo en `sshd_config.d`, como `50-cloud-init.conf` de cloud-init, prevalece sobre `sshd_config`. Las correcciones SSH nunca modifican `sshd_config`: van en un archivo que se lee primero y se deshacen si sshd sigue usando otro valor. [Hardening y vulnerabilidades](https://infrafence.com/es/documentacion/hardening-y-vulnerabilidades)
- **Hardening de PHP** — encuentra los ajustes de PHP arriesgados en cada runtime y pool, y corrige los seguros. Las correcciones van en un archivo propio de InfraFence (`zz-infrafence-hardening.ini`), se comprueban y se deshacen si un sitio deja de responder; `cgi.fix_pathinfo` y `disable_functions` necesitan aprobación. El agente también vigila la configuración de PHP y avisa de un valor arriesgado en cuanto aparece. Es hardening y vigilancia de la configuración: no se carga nada en PHP, y no es una protección que se ejecute dentro de tus aplicaciones. [Hardening de PHP](https://infrafence.com/es/documentacion/hardening-y-vulnerabilidades#php-hardening)
- **Cierra puertos expuestos, bloquea destinos peligrosos** (Pro · AutoMode) — cada cambio se comprueba y se deshace si rompe algo. El tráfico de salida nunca se bloquea hacia una dirección con una sesión SSH iniciada; una conexión SSH que no ha iniciado sesión no protege a nadie. Un destino con el que el servidor habla con regularidad (en 3 de los últimos 7 días, como la API de un cliente) nunca se bloquea automáticamente cuando aparece en una lista de amenazas: el bloqueo espera tu aprobación. [Puertos y bloqueo saliente](https://infrafence.com/es/documentacion/puertos-y-bloqueo-saliente)
- **Parches virtuales para vulnerabilidades explotadas** (Pro · AutoMode) — una regla de ModSecurity específica protege el software vulnerable hasta que instales la actualización; Apache con ModSecurity. [Parches virtuales](https://infrafence.com/es/documentacion/parches-virtuales)
- **Modo de emergencia** — un botón rojo: durante 24 horas InfraFence responde al ataque por sí solo, con el mismo catálogo seguro y los mismos límites que AutoMode (desde Basic). [Modo de emergencia](https://infrafence.com/es/documentacion/modo-de-emergencia)
- **Alertas** por correo, Slack, Discord, Telegram o webhook, y un resumen semanal por correo. [Alertas](https://infrafence.com/es/documentacion/alertas)
- **Análisis con IA** — un análisis instantáneo de cada incidente en todos los planes, calculado en el panel; un análisis con IA y correcciones seguras en un clic desde Pro. [Eventos y actividad](https://infrafence.com/es/documentacion/eventos-y-actividad)
- **Red InfraFence y mapa de ataques** — compartir es opcional: se señalan las direcciones que atacan a varios clientes, y las cifras de la red solo aparecen donde han contribuido 3 o más organizaciones. [La red InfraFence](https://infrafence.com/es/documentacion/red-infrafence) · [Mapa de ataques](https://infrafence.com/es/documentacion/mapa-de-ataques)
- **Distintivo de monitorización** — el distintivo «Monitorizado por InfraFence» enlaza a una página de transparencia pública con la hora de la última comprobación, los ataques bloqueados en los últimos 30 días y las protecciones activas. Para demostrar que el dominio lo sirve tu servidor, el agente coloca un archivo de verificación, `/.well-known/infrafence-verification.txt`, en la raíz de documentos del sitio, y lo elimina cuando se desactiva el distintivo. Un sitio en un contenedor detrás de un proxy inverso (Coolify, Traefik, Caddy) no tiene raíz de documentos en el host: el agente no escribe nada allí y el panel verifica el dominio con un registro DNS TXT, `_infrafence.<dominio>`. No es un certificado. [Distintivo de monitorización](https://infrafence.com/es/features#trust-badge) · [Ver un ejemplo de página de transparencia](https://infrafence.com/es/trust/demo)
- **Protección aunque el panel no esté disponible** — los baneos, la lista blanca y los bloqueos por país siguen vigentes, los nuevos ataques se siguen baneando y los eventos esperan en una cola. [Cuando el panel no está disponible](https://infrafence.com/es/documentacion/panel-no-disponible)
- **Junto a CSF y otras herramientas** — InfraFence se limita a sus propias cadenas y nunca modifica los archivos de CSF ni las reglas de otras herramientas; después de `csf -r` vuelve a poner sus propias reglas en cuestión de segundos. [Coexistencia con otras herramientas de seguridad](https://infrafence.com/es/documentacion/coexistencia)
- **Plugin para cPanel & WHM** (disponible) **y extensión para Plesk** (en desarrollo), incluidos en los planes Basic, Pro y AutoMode — estado de la protección, baneos, hallazgos, eventos y escaneos por sitio dentro del panel de hosting. [cPanel & WHM](https://infrafence.com/es/integraciones/cpanel-whm) · [Paneles de hosting](https://infrafence.com/es/documentacion/paneles-de-hosting) · [Plugin WHM](https://infrafence.com/es/documentacion/plugin-whm)

---

## Seguro en servidores de producción

- **Revisa antes de cambiar** — `infrafence-agent preflight` es una revisión del servidor en solo lectura (firewall y otras herramientas de seguridad, servidores web, paneles de hosting, gestión de configuración, operaciones de paquetes, recursos). El instalador la ejecuta antes de cambiar nada; el agente, al arrancar y cada día.
- **Valores por defecto prudentes** — los cambios en el servidor web y el bloqueo de entrada por listas de amenazas están apagados hasta que los activas; las actualizaciones del agente están en «Solo avisar» hasta que eliges la instalación automática, y solo se instalan versiones firmadas con cosign.
- **Cadenas de firewall propias** — cada regla vive en las cadenas `INFRAFENCE` del agente, llamadas desde `INPUT` (y `DOCKER-USER`), reconstruidas de forma atómica y restauradas automáticamente en cuestión de segundos si otra herramienta (ufw, firewalld, CSF) las elimina. Tus reglas existentes nunca se modifican. Las IPs en la lista blanca quedan exentas, nunca abiertas.
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
| `--dry-run` | Revisa el servidor y muestra el plan; no cambia nada. No hace falta token |
| `--no-ipset` | No instala `ipset` (los baneos siguen funcionando, hasta 500; el bloqueo por país y por listas de amenazas lo necesita) |
| `--skip-checksum` | **Inseguro.** Instala aunque no se pueda descargar el checksum de la release (el binario no se verifica). Solo para una red que bloquea el archivo `.sha256` y nada más |
| `--uninstall` | Elimina el agente y todo lo que añadió |

El agente se descarga solo de GitHub Releases, y el instalador se detiene si falta el checksum de la versión o no coincide. El certificado raíz de Let's Encrypt que puede necesitar (ISRG Root X1) va incluido en el script, con una huella fijada, en lugar de descargarse. [Qué hace el instalador](https://infrafence.com/es/documentacion/que-hace-el-instalador)

**Requisitos:** x86-64 o ARM64, acceso root, `iptables`; systemd, upstart o sysvinit. El instalador usa `apt`, `dnf` o `yum` para las dependencias que falten e instala `ipset` solo cuando la revisión del servidor indica que es seguro.

**Probado antes de cada versión** en 15 distribuciones: Ubuntu 20.04, 22.04, 24.04 y 26.04, Debian 12 y 13, Rocky Linux 8 y 9, AlmaLinux 8 y 9, CentOS Stream 9, Oracle Linux 9, Fedora 41 y 42, Amazon Linux 2023. En cada una se ejecuta el instalador real, detecta un ataque de fuerza bruta SSH, lo banea en el firewall y se desinstala sin dejar rastro. Otras distribuciones de las familias Debian y RHEL suelen funcionar: ejecuta antes el instalador con `--dry-run`. Ver [Distribuciones compatibles](https://infrafence.com/es/documentacion/distribuciones-compatibles).

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

### Kubernetes

Crea una clave de clúster en el dashboard (Ajustes → Kubernetes) y luego:

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." --set clusterName="production"
```

Cada nodo se registra como un servidor. Todos los valores, las actualizaciones y GitOps: [Kubernetes](https://infrafence.com/es/documentacion/kubernetes) en la documentación, y el [README del chart](charts/infrafence-agent/README.md).

### Desinstalación

```bash
curl -fsSL https://github.com/infrafence/infrafence-agent/releases/latest/download/install.sh | sudo bash -s -- --uninstall
```

---

## Configuración

Casi todo se configura desde el panel y llega a los servidores en aproximadamente un segundo: umbrales de fuerza bruta, duración de los baneos, modo monitor, reglas del WAF, decisiones sobre bots, lista blanca, países bloqueados, programación de los escaneos de malware, inspección DNS, cambios en el servidor web, bloqueo por listas de amenazas, actualizaciones automáticas. Referencia completa: [Configuración](https://infrafence.com/es/documentacion/configuracion).

En el servidor:

| Variable de entorno | Efecto |
|---|---|
| `AUTH_LOG_PATH` | Archivo de log de SSH que se lee en lugar del journal de systemd (por defecto: el journal en sistemas con systemd; si no, `/var/log/auth.log` o `/var/log/secure`) |
| `WEB_LOG_PATH` | Logs de acceso web, separados por comas (por defecto: detectados a partir de nginx, Apache, LiteSpeed, paneles, Docker) |
| `MAIL_LOG_PATH`, `DB_LOG_PATH`, `FTP_LOG_PATH` | Sustituyen los logs de correo, base de datos y FTP detectados |
| `MODSEC_AUDIT_LOG` | Log de auditoría de ModSecurity |
| `GEOIP_DB_PATH` | Base de datos de países (formato MaxMind DB) que se usa en lugar de la descargada del panel en `/etc/infrafence/geoip-country.mmdb`; si está definida, no se descarga nada |
| `INFRAFENCE_CONFIG` | Archivo de configuración del agente (por defecto `/etc/infrafence/config.json`) |

Defínelas con `sudo systemctl edit infrafence-agent` (`[Service]` → `Environment=...`) y reinicia el servicio.

**Etiquetas de Docker** en tus contenedores: `infrafence.monitor` (`true`/`false`), `infrafence.log-path` (rutas en el host), `infrafence.domain` (dominios). Desde la 1.0.35 el agente también lista los dominios de los contenedores detrás de un proxy inverso, solo leyendo las etiquetas que lee el propio proxy: `traefik.http.routers.<nombre>.rule` de Traefik (`Host(...)`; `HostRegexp` se omite) y las direcciones de sitio `caddy` / `caddy_<n>` de Caddy. Así Coolify (`coolify-proxy`, Traefik o Caddy) funciona sin añadir etiquetas. Se actualizan cada 2 minutos y se envían con el heartbeat; el agente nunca ejecuta nada dentro del contenedor del proxy.

**Comandos:** `infrafence-agent preflight [--json]` (revisión del servidor en solo lectura), `infrafence-agent version` (versión instalada), `infrafence-agent check`, `infrafence-agent uninstall --clean`. Todos los comandos: [Referencia de comandos](https://infrafence.com/es/documentacion/referencia-de-comandos).

**Paneles de hosting (cPanel/WHM, Plesk):** los plugins de los paneles ejecutan `infrafence-agent panel <command> --json` como root y leen un objeto JSON de stdout (`{"ok": true, ...}` o `{"ok": false, "error": "<code>", "message": "..."}`, código de salida 0 solo si ok). Comandos: `status`, `bans [--limit N]`, `unban <ip>`, `allow <ip> [--note ...]`, `allowlist`, `disallow <ip>`, `findings [--limit N]`, `events [--limit N] [--since 24h]`, `coexistence`, `sites`, `scan <document root>`, `map [--hours 24|168]`, `score`; los que cambian algo necesitan `--actor <usuario del panel>` y se envían al panel de InfraFence como eventos con origen `panel`. El comando habla con el agente en ejecución a través de `/run/infrafence/panel.sock` (solo root, permisos 0600, sin puerto de red); si el agente no está en ejecución responde igualmente, con `"agent_running": false`. Los plugins son para los planes Basic, Pro y AutoMode (agente 1.0.34 o posterior): `status` responde siempre, con `"entitled"` y `"entitlement"` (`ok`, `plan_required`, `unpaid`, `unknown`); cualquier otro comando responde solo ese error, sin datos, cuando la organización no tiene derecho (un plan sin los plugins, la protección desactivada tras 24 horas de rechazo, o un plan aún desconocido). El plan de la última sincronización correcta se conserva entre reinicios, así una caída del panel de InfraFence no vacía el plugin. `map` (los ataques a este servidor por país y categoría) y `score` (su puntuación de seguridad y la tendencia de 30 días) vienen del panel de InfraFence, necesitan el agente 1.0.33 o posterior y el agente los guarda en caché: como máximo una petición cada 5 minutos para el mapa y cada 15 minutos para la puntuación, con `"stale": true` cuando no se puede llegar al panel. Todos los campos de cada respuesta: [docs/panel-json.md](docs/panel-json.md) (en inglés).

**Abierto o resuelto:** cada evento de problema que informa el agente (un puerto de base de datos expuesto, un archivo del sistema modificado, un ajuste de PHP arriesgado, malware...) lleva `details.subject` (`port:tcp/3306`, `file:/etc/passwd`...). Desde la 1.0.34, `panel events` y `panel findings` indican si cada problema sigue `open` o está `resolved` (`subject`, `state`, `resolved_at`, `resolved_how`): resuelto en el panel de InfraFence, o corregido por el propio agente (un puerto que cerró su firewall, una corrección aplicada y verificada, un archivo en cuarentena, un paquete actualizado). Un puerto de base de datos que cierra el firewall del agente ya no se informa como expuesto cuando el agente se reinicia. Detalles: [docs/panel-json.md](docs/panel-json.md#problems-and-resolution) (en inglés).

**Versión del plugin:** el plugin del panel se actualiza desde el panel de InfraFence (Plugins de paneles), no con el agente. Desde la 1.0.35 el agente lee la versión del plugin de WHM instalado (solo lectura: `/usr/local/share/infrafence-whm/VERSION`, o si no el paquete `infrafence-whm`; al arrancar y como mucho una vez por hora) y la envía con el heartbeat (`panel_plugin`). `panel status` la muestra como `plugin_installed`, junto a `plugin_latest`, la última versión que el panel envía en la sincronización, para que el plugin pueda avisar cuando hay una actualización. Detalles: [docs/panel-json.md](docs/panel-json.md#status).

---

## Aún no disponible

Lista honesta de lo que todavía no existe:

- **Patrones de detección SSH por servidor** desde el panel

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
| **Código disponible** | El agente tiene licencia BSL 1.1: gratis en producción en tus servidores y en los de tus clientes, totalmente transparente, y puedes revisar cada línea antes de instalarlo. |
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

El agente es source-available bajo la [Business Source License 1.1](LICENSE) (licenciante: ComCart S.r.l.). El uso en producción es gratuito en cualquier número de servidores, incluidos los de tus clientes, siempre que no lo uses para crear un producto competidor. Cuatro años después de cada versión, esa versión pasa a estar disponible bajo la licencia Apache 2.0.

<p align="center">
  <a href="https://infrafence.com">infrafence.com</a>
</p>
