# InfraFence Agent — Helm Chart

Deploy the [InfraFence](https://infrafence.com) security agent as a DaemonSet on your Kubernetes cluster. Each node gets an agent that provides brute-force protection, WAF, bot detection, vulnerability scanning, malware scanning, and real-time firewall management.

## Prerequisites

- Kubernetes 1.22+
- Helm 3+
- An InfraFence account and a **cluster key**: dashboard → Settings → Kubernetes → "Create cluster key". One key registers every node; each node shows up as its own server. Starter (free) covers one server, so only one node can register; Basic and higher have no limit and bill one server per node.

## Install

```bash
helm install infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --create-namespace \
  --set apiKey="IFK-..." \
  --set clusterName="production"
```

## Upgrade

```bash
helm upgrade infrafence-agent oci://ghcr.io/infrafence/charts/infrafence-agent \
  --namespace infrafence --reuse-values
```

A node that registers again (rebuilt node, wiped `/etc/infrafence`) keeps its server in the dashboard and gets a new token; revoking a cluster key stops new nodes from joining but leaves registered nodes running.

## Uninstall

```bash
helm uninstall infrafence-agent --namespace infrafence
```

## Configuration

| Parameter | Description | Default |
|---|---|---|
| `apiKey` | Cluster key from the dashboard (Settings → Kubernetes) | `""` (required) |
| `serverUrl` | InfraFence panel URL | `https://infrafence.com` |
| `clusterName` | Cluster name; nodes are grouped by it in the dashboard (auto-detected if not set) | `""` |
| `image.repository` | Container image | `ghcr.io/infrafence/infrafence-agent` |
| `image.tag` | Image tag (defaults to chart `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `Always` |
| `autoUpdate.enabled` | Lets the agent move its own DaemonSet to a new release image when an update is allowed (dashboard → Settings → Agent → Agent updates set to Install automatically, or Install now). **Disable if using GitOps (ArgoCD, Flux).** | `true` |
| `ingressFirewall.enabled` | Create nginx-ingress RBAC for ConfigMap-level IP blocking. **Disable if not using nginx-ingress.** | `false` |
| `ingressFirewall.namespace` | Namespace where nginx-ingress runs | `ingress-nginx` |
| `ingressFirewall.configMapName` | nginx-ingress ConfigMap name | `ingress-nginx-controller` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `50m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `tolerations` | Node tolerations | `[{operator: Exists}]` (all nodes) |
| `nodeSelector` | Node selector | `{}` |
| `priorityClassName` | Priority class | `""` |
| `extraEnv` | Additional environment variables | `[]` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name override | `""` |
| `serviceAccount.annotations` | Service account annotations | `{}` |

### GitOps / ArgoCD setup

If you manage deployments via ArgoCD or Flux, disable the built-in auto-update to avoid conflicts:

```yaml
autoUpdate:
  enabled: false
```

The agent will not modify K8s resources. You control updates by bumping the image tag in your GitOps repo.

### Traefik / non-nginx ingress

The chart works with any ingress controller. By default, no nginx-specific RBAC is created. IP blocking works at the **iptables/host level** regardless of ingress controller.

If you use Traefik, enable access logs so the agent can detect web attacks:

```yaml
# In your Traefik Helm values
logs:
  access:
    enabled: true
```

### Extra environment variables

```yaml
extraEnv:
  - name: WEB_LOG_PATH
    value: "/var/log/nginx/access.log"
  - name: GEOIP_DB_PATH # your own country database: nothing is downloaded
    value: "/usr/share/GeoIP/GeoLite2-Country.mmdb"
  - name: DISABLE_K8S_AUTO_UPDATE
    value: "true"
```

## What gets deployed

- **DaemonSet**: One agent pod per node (including control-plane via tolerations)
- **ServiceAccount + ClusterRole + ClusterRoleBinding**: Read-only K8s API access (pods, nodes, events, ingresses, networkpolicies) + DaemonSet patch for auto-updates
- **Secret**: Stores the cluster key (`apiKey`)
- **Role + RoleBinding** (optional): Only when `ingressFirewall.enabled: true` — grants ConfigMap write access in the ingress namespace

### Host mounts

| Mount | Path | Mode |
|---|---|---|
| Logs | `/var/log` | read-only |
| Docker socket | `/var/run/docker.sock` | read-only |
| Containerd socket | `/run/containerd/containerd.sock` | read-only |
| Agent config | `/etc/infrafence` | read-write |

## Agent capabilities

- SSH brute-force detection and auto-banning via iptables/ipset
- Web attack detection (SQL injection, XSS, path traversal, RCE, SSRF)
- Log parsing: **nginx, Apache, Traefik (JSON), Caddy, LiteSpeed, uvicorn, gunicorn**
- Country-based geoblocking (the DB-IP country database, CC BY 4.0, downloaded from the dashboard while a country is blocked)
- Bot fingerprint detection with configurable actions
- Malware scanning with real-time progress (YARA, signature matching, heuristics)
- Known vulnerabilities (CVE) of the installed packages, checked against the OSV database (Debian, Ubuntu, AlmaLinux, Rocky Linux) and ranked by real risk: exploited in the wild (CISA KEV) first, then exploit probability (EPSS)
- System metrics (CPU, memory, disk, load, network I/O)
- Kubernetes: pod inventory, NetworkPolicy audit, event monitoring
- Real-time firewall rule management via WebSocket
- Updates: notify-only by default; when you allow them, the agent verifies the cosign signature of the new release image and pins its DaemonSet to that image digest

## Links

- [InfraFence Dashboard](https://infrafence.com)
- [Kubernetes documentation](https://infrafence.com/docs/kubernetes)
- [Agent README](https://github.com/infrafence/infrafence-agent#readme)
- [Report Issues](https://github.com/infrafence/infrafence-agent/issues)
