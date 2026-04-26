# NetPilot — Design Spec
**Date:** 2026-04-25  
**Status:** Approved

---

## Overview

NetPilot is an enterprise-grade network monitoring, config management, and inventory tool — a lightweight SolarWinds alternative. It targets departments managing up to 2000 multi-vendor devices. The frontend is smooth and modern (Vue 3 SPA); the backend is a single Python process (FastAPI modular monolith) deployable via Docker Compose.

---

## Goals

- Real-time and streaming visibility into device health across a multi-vendor fleet
- Full config lifecycle: scheduled backup, version diff, compliance enforcement, push/rollback, and Jinja2 templating
- Searchable, tagged device inventory with grouping and attribute management
- Flexible alerting to Email, Slack, Teams, PagerDuty, and generic webhooks
- Role-based access control with full audit trail

---

## Non-Goals

- Replacing a full NMS for flow analysis (NetFlow/sFlow) — out of scope for v1
- SD-WAN or cloud-native network management
- Wireless / RF monitoring

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | Vue 3 + Vite + Pinia + Vue Router + TailwindCSS + Chart.js |
| Backend | FastAPI (Python 3.12), async, SQLAlchemy 2 (async) |
| Background jobs | APScheduler (in-process) |
| Primary DB | PostgreSQL 16 |
| Time-series | TimescaleDB extension on the same PostgreSQL instance |
| Config storage | Local Git repo managed via GitPython |
| SNMP | pysnmp (async) |
| SSH / CLI | Netmiko (thread-pool executor) |
| gNMI telemetry | pygnmi (gRPC, persistent async subscriptions) |
| HTTP streaming | httpx (RESTCONF SSE) |
| Auth | JWT (python-jose) + bcrypt, refresh tokens |
| Credential encryption | AES-256-GCM (AESGCM + Argon2id key derivation) for all stored secrets |
| PAM integration | CyberArk AIM CCP, HashiCorp Vault KV v2 + SSH dynamic secrets |
| Connection pool | PgBouncer (transaction-mode pooling, TLS both sides) |
| DB backup / PITR | pgBackRest (WAL archiving, incremental backups, PITR) |
| DB HA | Patroni (automatic failover, etcd for consensus) |
| DB audit | pgaudit extension (DDL + DML logging independent of app) |
| Cache / Pub-Sub | Redis 7 (aioredis async — last-value cache, event bus, rate limit store) |
| Distributed tracing | OpenTelemetry SDK + OTLP exporter (Jaeger / Grafana Tempo) |
| Image signing | Sigstore cosign (keyless, OIDC-backed) |
| SBOM | Syft (SPDX 2.3 / CycloneDX 1.5, attached as OCI attestation) |
| Runtime security | Falco (eBPF syscall monitoring, custom rules per container) |
| NL query / AI | Anthropic Claude API (haiku model — query parsing only, optional) |
| Containers | Docker Compose (dev) · Kubernetes + Helm chart (prod) · Rootless Podman (air-gapped RHEL) |

---

## Architecture

### Overview

```
Devices
  ├── SNMP v2c/v3          →  Poller fleet (SNMPEngine, async)
  ├── gNMI/gRPC            →  Poller fleet (gNMIEngine, async gRPC)
  ├── HTTP/2 SSE           →  Poller fleet (SSEEngine, httpx)
  └── SSH / Netmiko        →  Poller fleet (SSHEngine, thread pool)

Poller fleet  (1..N netpilot-poller containers — horizontally scalable)
  Each poller owns a consistent-hash partition of the device inventory
  ├── SNMPEngine     asyncio event loop + semaphore, batch TimescaleDB writes
  ├── SSHEngine      ThreadPoolExecutor, config backup + on-demand ops
  ├── gNMIEngine     async gRPC persistent subscriptions, auto-reconnect
  └── SSEEngine      httpx RESTCONF event streams

API container  (single FastAPI process — REST + WebSocket only, no polling)
  ├── modules/monitor/       Metrics API, WebSocket broadcaster, alert evaluation
  ├── modules/config_mgmt/   Git storage, diff, compliance push, templates
  ├── modules/compliance/    Regex rules engine, scan job, built-in rule packs
  ├── modules/inventory/     Device CRUD, groups, tags, standard attributes
  ├── modules/alerting/      Rules engine, notification dispatchers
  ├── modules/cve/           CVE scan, dashboard, waivers, self-healing
  ├── modules/poller_coord/  Poller registration, heartbeat, partition assignment
  └── modules/auth/          JWT, RBAC, audit log

  drivers/  (shared lib imported by poller containers)
    snmp.py          pysnmp async wrapper
    ssh.py           Netmiko wrapper (thread-pool)
    gnmi.py          pygnmi gRPC subscriber with auto-reconnect
    http_stream.py   httpx RESTCONF SSE listener
    vendors/
      cisco_ios.py   NTC-Templates + custom TextFSM parsers
      cisco_nxos.py  NX-API JSON + SSH fallback
      cisco_xr.py    gNMI-first, SSH fallback
      arista.py      eAPI (JSON over HTTP)
      juniper.py     PyEZ XML
      gigamon.py     SSH (gigamon_gigavue) + GigaVUE-FM REST API
      opengear.py    SSH (opengear) + Opengear REST API v2
      bluecat.py     SSH (linux) + BlueCat REST API v1

Storage
  ├── PostgreSQL + TimescaleDB   hypertables for metrics (90d) and telemetry (7d)
  └── configs/ (git)             device running configs, full history
```

### Redis — Event Bus + Real-Time Cache

With multiple pollers writing to TimescaleDB and the API container serving WebSocket streams, the API needs a way to receive metric updates from pollers without querying the DB on every push. Redis fills two distinct roles:

**Role 1 — Last-value cache:**
Each poller publishes fresh metric values to a Redis Hash after each successful poll:
```
HSET device:{device_id}:metrics  cpu_util 72.4  mem_util 45.1  if_oper_status 1  ...
EXPIRE device:{device_id}:metrics 300    ← TTL = 5× poll interval, auto-evicts stale devices
```
The API dashboard endpoint reads from Redis (sub-millisecond) instead of TimescaleDB (10–50ms query). **No DB hit for "current value" dashboard tiles.**

**Role 2 — Pub/Sub event bus (poller → API → WebSocket clients):**
After writing to Redis hash, each poller publishes a notification:
```
PUBLISH metric_updates  '{"device_id":"uuid","metrics":{...},"ts":"..."}'
```
The API container subscribes to `metric_updates` and fans out to all WebSocket clients watching that device. This replaces DB polling for real-time telemetry updates — the WebSocket push latency drops from 1–2 seconds (DB poll interval) to under 100ms.

**Role 3 — Distributed coordination:**
- Poller leader election: the coordinator uses a Redis lock (`SET coord_leader <api_pod_id> NX EX 30`) to ensure only one API pod runs the rebalancing logic when multiple API replicas are running in K8s
- Rate limit counters: `slowapi` can use Redis as a shared backend so rate limits apply across all API replicas (not per-pod)
- Session revocation fast-path: the `user_revoked_at` check (currently described as "LRU cache with 1-minute TTL") uses Redis `SET user:{id}:revoked_at {timestamp}` for instant cross-replica propagation

**Redis security:**
- TLS 1.3 + AUTH password required; no public exposure (internal Docker/K8s network only)
- `requirepass` set; ACL rules restrict which commands each service can execute
- Persistence: `appendonly yes` (AOF) — survive restarts without losing last-value cache

**Stack addition:**
```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes --tls-port 6380
  volumes: [redis-data:/data]
  networks: [netpilot-internal]
```

```
Stack | Technology | Now includes
------+------------+--------------
Cache / Pub-Sub | Redis 7 (aioredis / redis-py async) | NEW
```

---

### Design principles

- **Polling is separated from serving**: the `api` container serves REST/WebSocket only; all device I/O runs in dedicated `poller` containers. API latency is never affected by a slow SNMP poll or blocked SSH session.
- **Pollers are horizontally scalable**: add capacity with `docker compose scale poller=N` — the coordinator distributes devices automatically via consistent hashing.
- **Each device poll runs independently**: one device failure never blocks others; failures are isolated per device, logged, and surfaced as alerts.
- gNMI subscriptions run as persistent async coroutines; they reconnect with exponential backoff on disconnect.
- All background job exceptions are caught, logged, and surfaced as system alerts in the UI (no silent failures).
- Credentials are stored as references to a secrets backend (Vault / CyberArk) or AES-256-GCM encrypted in DB — never plaintext.

---

## Vendor Support

| Vendor / OS | Primary protocol | Fallback |
|---|---|---|
| Cisco IOS / IOS-XE | SNMP + SSH (Netmiko + NTC-Templates) | — |
| Cisco NX-OS | NX-API (JSON) | SSH |
| Cisco IOS-XR | gNMI/gRPC | SSH |
| Arista EOS | eAPI (JSON over HTTP) | SNMP + SSH |
| Juniper JunOS | PyEZ (XML) | SSH |
| Gigamon GigaVUE OS | SSH (Netmiko `gigamon_gigavue`) + GigaVUE-FM REST API | SNMP |
| Opengear OM/CM (Linux) | SSH (Netmiko `opengear`) + Opengear REST API | SNMP |
| BlueCat BDDS (Linux) | SSH (generic Linux — `linux`) + BlueCat REST API | SNMP |
| Generic / any Netmiko | SNMP + SSH | — |

**Gigamon GigaVUE OS** — visibility fabric / packet broker devices. NetPilot polls TAP port status, flow policy state, inline bypass health, and interface utilization via SSH CLI and the GigaVUE-FM REST API (`/api/v1/`). Backup retrieves the running configuration snapshot (`show running-config`). SNMP v3 polls interface counters.

**Opengear OM/CM (console servers)** — out-of-band management infrastructure. NetPilot monitors serial port status, connected-device reachability, cellular failover state, and firmware version via SSH and the Opengear REST API v2. Key use: verify OOB path is healthy before production devices become unreachable. Netmiko device type: `opengear`.

**BlueCat BDDS / Address Manager (Linux DDI servers)** — DNS, DHCP, and IPAM appliances. NetPilot connects via SSH as a standard Linux host (Netmiko device type: `linux`) and via the BlueCat REST API v1 for service-health checks (DNS zone count, DHCP lease utilization, server status). SNMP polls process health and interface counters. Config backup captures `/etc/named.conf` and DHCP scope snapshots via the REST API.

---

## Directory Structure

```
netpilot/
├── backend/
│   ├── main.py
│   ├── core/
│   │   ├── config.py            # pydantic-settings (env vars)
│   │   ├── database.py          # SQLAlchemy async engine + session factory
│   │   ├── scheduler.py         # APScheduler singleton
│   │   ├── security.py          # JWT encode/decode, RBAC FastAPI dependency
│   │   ├── crypto.py            # Fernet wrapper + key version rotation
│   │   ├── logging.py           # Structured logger + security event emitter + redaction filter
│   │   ├── config_scrubber.py   # Vendor-aware credential scrubber (applied at API read time)
│   │   └── auth_provider.py     # AuthProvider protocol + AuthResult dataclass
│   ├── providers/               # Identity providers (user login)
│   │   ├── local.py             # bcrypt + TOTP + WebAuthn
│   │   ├── oidc.py              # Generic OIDC (Okta, Azure AD, Google)
│   │   ├── saml.py              # SAML 2.0 SP (AD FS, on-prem AD)
│   │   └── ldap.py              # Direct LDAP/LDAPS
│   ├── credential_providers/    # Device credential backends (PAM)
│   │   ├── __init__.py          # CredentialProvider protocol + SecureString
│   │   ├── vault.py             # HashiCorp Vault KV v2 + SSH dynamic secrets
│   │   ├── cyberark.py          # CyberArk AIM CCP REST API (mTLS)
│   │   ├── env_var.py           # Environment variable (dev/lab only)
│   │   └── encrypted_db.py      # AES-256-GCM fallback (Argon2id key derivation)
│   ├── modules/
│   │   ├── monitor/
│   │   │   ├── router.py        # /api/monitor/* endpoints
│   │   │   ├── service.py       # poll orchestration, websocket broadcaster
│   │   │   ├── jobs.py          # APScheduler job definitions
│   │   │   └── schemas.py
│   │   ├── config_mgmt/
│   │   │   ├── router.py        # /api/config/* endpoints
│   │   │   ├── service.py       # backup, diff, push, compliance logic
│   │   │   ├── jobs.py
│   │   │   ├── templates/       # Jinja2 config templates
│   │   │   └── schemas.py
│   │   ├── inventory/
│   │   │   ├── router.py              # /api/inventory/devices/* endpoints
│   │   │   ├── attributes_router.py   # /api/inventory/attribute-definitions/* endpoints
│   │   │   ├── service.py             # Device CRUD + custom attribute validation
│   │   │   ├── attribute_service.py   # Attribute definition CRUD + schema registry
│   │   │   └── schemas.py             # DeviceSchema dynamically includes custom fields
│   │   └── alerting/
│   │       ├── router.py        # /api/alerts/* endpoints
│   │       ├── service.py       # rules evaluation engine
│   │       ├── channels/
│   │       │   ├── email.py
│   │       │   ├── slack.py
│   │       │   ├── teams.py
│   │       │   ├── pagerduty.py
│   │       │   └── webhook.py
│   │       └── schemas.py
│   │   ├── compliance/
│   │   │   ├── router.py        # /api/v1/compliance/* endpoints
│   │   │   ├── service.py       # rule evaluation engine, re2-based pattern matching
│   │   │   ├── jobs.py          # hourly compliance scan APScheduler job
│   │   │   ├── builtins/        # built-in rule packs (security baseline, CIS L1, SNMP hardening)
│   │   │   └── schemas.py
│   │   ├── cve/
│   │   │   ├── router.py        # /api/v1/cve/* endpoints
│   │   │   ├── service.py       # scan orchestration, result storage, alert evaluation
│   │   │   ├── jobs.py          # nightly CVE scan APScheduler job
│   │   │   ├── scanners/
│   │   │   │   ├── pip_audit.py
│   │   │   │   ├── npm_audit.py
│   │   │   │   └── trivy.py
│   │   │   └── schemas.py
│   │   ├── reporting/
│   │   │   ├── router.py        # /api/reports/* endpoints
│   │   │   ├── service.py       # PDF/CSV generation, scheduled delivery
│   │   │   └── jobs.py
│   │   └── discovery/
│   │       ├── router.py        # /api/discovery/* endpoints
│   │       └── service.py       # SNMP subnet sweep, device fingerprinting
│   ├── drivers/
│   │   ├── snmp.py
│   │   ├── ssh.py
│   │   ├── gnmi.py
│   │   ├── http_stream.py
│   │   └── vendors/
│   │       ├── cisco_ios.py
│   │       ├── cisco_nxos.py
│   │       ├── cisco_xr.py
│   │       ├── arista.py
│   │       ├── juniper.py
│   │       ├── gigamon.py
│   │       ├── opengear.py
│   │       └── bluecat.py
│   └── alembic/
├── frontend/
│   ├── src/
│   │   ├── views/
│   │   │   ├── Dashboard.vue    # Overview: device health heatmap, active alerts
│   │   │   ├── Monitor.vue      # Per-device metrics and live telemetry charts
│   │   │   ├── Config.vue       # Backup list, diff viewer, push form, change requests
│   │   │   ├── Inventory.vue    # Device table (virtual scroll), add/edit/bulk ops
│   │   │   ├── Alerts.vue       # Alert history, incidents, maintenance windows
│   │   │   ├── Discovery.vue          # Subnet sweep, review found devices
│   │   │   ├── Compliance.vue         # Compliance rules list, scan results, rule editor
│   │   │   ├── Topology.vue           # D3.js force-directed device graph
│   │   │   ├── Reports.vue            # Compliance reports, scheduled delivery
│   │   │   ├── CVE.vue                # CVE dashboard — open CVEs, waivers, remediation
│   │   │   └── Settings.vue           # Users, roles, notification channels, IdP config
│   │   │       # Settings sub-views (routed tabs):
│   │   │       # /settings/device-attributes  — attribute definition manager
│   │   │       # /settings/users              — user + role management
│   │   │       # /settings/idp                — OIDC/SAML/LDAP configuration
│   │   │       # /settings/notifications      — alert channels
│   │   │       # /settings/api-keys           — API key management
│   │   │       # /settings/developer          — developer mode toggle, API explorer
│   │   ├── components/
│   │   │   │   ├── Sidebar.vue           # Collapsible left nav (icon strip → full labels)
│   │   │   ├── MetricChart.vue       # Chart.js time-series wrapper
│   │   │   ├── ConfigDiff.vue        # Side-by-side + inline diff, syntax highlighted
│   │   │   ├── StatusBadge.vue       # UP / DOWN / DEGRADED pill
│   │   │   ├── AlertBanner.vue       # Top-of-page critical alert strip
│   │   │   ├── MaintenanceWindow.vue # Create/edit maintenance window modal
│   │   │   ├── IncidentGroup.vue     # Grouped alert incident card
│   │   │   ├── GlobalSearch.vue      # Cmd+K global search overlay
│   │   │   ├── EmptyState.vue        # Reusable empty state with CTA
│   │   │   ├── BulkActionBar.vue     # Floating bar when rows are selected
│   │   │   ├── OnboardingWizard.vue  # First-run setup steps
│   │   │   ├── VirtualTable.vue      # Virtual-scrolling table for large lists
│   │   │   ├── DynamicForm.vue       # Schema-driven device form (reads attribute-definitions API)
│   │   │   ├── FieldDefinitionPopover.vue  # Inline "Add missing field" popover
│   │   │   ├── TestConnectionBadge.vue     # Live SNMP/SSH test result inline
│   │   │   ├── NCMPropertiesTab.vue         # SSH/REST/gNMI connection test + history
│   │   │   ├── SNMPTestTab.vue              # SNMP v2c/v3 test + OID walk preview
│   │   │   ├── TopologyGraph.vue            # D3.js force-directed + hierarchical graph
│   │   │   ├── CVEDetailPanel.vue           # CVE detail slide-in panel
│   │   │   ├── CVESeverityBadge.vue         # Critical/High/Medium/Low badge
│   │   │   ├── ComplianceRuleEditor.vue     # Rule create/edit with live test pane
│   │   │   └── DevRequestLog.vue            # Developer mode: API call drawer
│   │   ├── stores/              # Pinia: devices, alerts, auth, telemetry
│   │   └── api/                 # axios client with JWT interceptor + auto-refresh
│   └── vite.config.ts
├── configs/                     # GitPython-managed device config repo
├── docker-compose.yml
├── .env.example
└── pyproject.toml
```

---

## Data Model

| Table | Key columns |
|---|---|
| `devices` | id, hostname, ip, vendor, device_type, snmp_community_enc (AES-256-GCM), credentials_ref (URI pointer — never the password), credential_provider (vault/cyberark/env/db), group_id, tags (JSON), custom_attributes (JSONB) — standard attribute fields pre-populated at schema init; see Standard Device Attributes below |
| `device_attribute_definitions` | id, name, label, field_type (text/number/select/boolean/date/url/ip_address/user_ref/multi_select/textarea), required, default_value, options (JSON array for select types), display_order, show_in_table (bool), archived_at |
| `device_groups` | id, name, description |
| `metrics` | device_id, metric_name, value, timestamp — TimescaleDB hypertable, 90-day retention |
| `telemetry_stream` | device_id, gnmi_path, value, timestamp — TimescaleDB hypertable, 7-day retention |
| `config_backups` | id, device_id, git_commit_sha, backed_up_at, triggered_by |
| `alerts` | id, device_id, severity, message, source, status, fired_at, resolved_at |
| `alert_rules` | id, name, metric, condition, threshold, channels (JSON), enabled |
| `users` | id, email, hashed_password (nullable for SSO-only), role_id, is_active, auth_provider (local/oidc/saml/ldap), external_id, mfa_totp_secret_enc, mfa_webauthn_credentials (JSON) |
| `roles` | id, name, permissions (JSON array) |
| `idp_group_mappings` | id, provider_name, external_group_name, netpilot_role_id |
| `refresh_tokens` | id, user_id, token_hash, expires_at, revoked_at |
| `api_keys` | id, user_id, name, key_hash, key_prefix, scopes (JSON), expires_at, last_used_at, revoked_at |
| `oauth2_clients` | id, client_id, client_secret_hash, name, scopes (JSON), owner_user_id |
| `audit_log` | id, user_id, auth_provider, action, resource_type, resource_id, detail, ip_address, timestamp |
| `security_events` | id, event_type, user_id, ip_address, user_agent, detail (JSON), timestamp — append-only, never deleted |
| `maintenance_windows` | id, name, device_ids (JSON), group_id, start_at, end_at, suppress_alerts (bool), created_by, reason |
| `incidents` | id, title, severity, alert_ids (JSON), device_ids (JSON), status, created_at, resolved_at, acknowledged_by |
| `user_preferences` | user_id (PK), theme (dark/light), timezone, notification_filters (JSON), dashboard_layout (JSON) |
| `scheduled_reports` | id, name, report_type, schedule_cron, recipients (JSON), format (pdf/csv), filters (JSON), last_run_at |
| `change_requests` | id, device_id, config_snippet, template_id, requested_by, status (pending/approved/rejected/applied), reviewer_id, external_ticket_id, created_at |
| `discovery_jobs` | id, subnet_cidr, snmp_community, status, found_devices (JSON), created_by, started_at, completed_at |
| `encryption_key_versions` | id, key_version, created_at, retired_at — tracks Fernet key rotation state |
| `compliance_rules` | id, name, description, pattern, rule_type, expected_value, line_count_min, flags (JSON), severity, category, remediation_hint, applies_to_device_types (JSON), applies_to_groups (JSON), applies_to_tags (JSON), applies_to_compliance_category, enabled, is_builtin, created_by, created_at |
| `compliance_results` | id, device_id, rule_id, status (pass/fail/skip/error), detail (JSON — matched lines, captured groups), config_backup_sha, checked_at |
| `connection_test_history` | id, device_id, protocol (ssh/rest/gnmi/snmp), status, result_detail (JSON), tested_by, tested_at |
| `cve_scan_results` | id, scan_at, scanner, cve_id, package_name, installed_version, fixed_version, cvss_score, severity, status (open/waived/remediated), detail (JSON) |
| `cve_waivers` | id, cve_id, justification, approved_by, expires_at, created_at |
| `cve_remediations` | id, cve_id, remediation_type, status, pr_url, triggered_by, started_at, completed_at |
| `poller_nodes` | poller_id (PK), hostname, version, capabilities (JSON), status (healthy/degraded/dead), devices_assigned, last_heartbeat_at, registered_at, metrics_snapshot (JSON) |
| `device_poller_assignments` | device_id (FK), poller_id (FK), assigned_at, is_active — tracks current partition and reassignment history |
| `device_neighbors` | id, source_device_id, neighbor_device_id, local_interface, remote_interface, protocol (cdp/lldp), last_seen — topology graph data |
| `jit_access_grants` | id, user_id, scope (JSON), device_ids (JSON), group_id, expires_at, reason, ticket_id, approved_by, created_at, revoked_at |
| `metric_baselines` | device_id, metric_name, n, mean, m2 (Welford accumulators), last_updated — stored in Redis; this table is a fallback snapshot |
| `scim_tokens` | id, token_hash, provider (okta/azure), scopes (JSON), created_at, expires_at, revoked_at |
| `breakglass_tokens` | id, token_hmac, used_at, used_by_ip, created_at — append-only, single-use |

---

## Data Schema Optimization

### Corrected & Completed Table Definitions

The table summary above is a reference index. This section is the canonical schema — it supersedes the summary where they conflict, fixes all identified issues, and adds the tables required by features described in later sections.

---

#### `devices`
```sql
CREATE TABLE devices (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname             TEXT NOT NULL,
  ip                   INET NOT NULL,
  vendor               TEXT NOT NULL,
  device_type          TEXT NOT NULL,             -- standard attribute; also in custom_attributes
  snmp_version         TEXT NOT NULL DEFAULT 'v2c',
  snmp_community_enc   BYTEA,                     -- AES-256-GCM; NULL for v3-only devices
  credentials_ref      TEXT,                      -- URI: vault://... cyberark://... db://... env://...
  credential_provider  TEXT NOT NULL DEFAULT 'db',
  group_id             UUID REFERENCES device_groups(id) ON DELETE SET NULL,
  tags                 TEXT[] NOT NULL DEFAULT '{}', -- native array; GIN-indexed; supports @> queries
  custom_attributes    JSONB NOT NULL DEFAULT '{}',  -- GIN-indexed; schema-validated at app layer
  status               TEXT NOT NULL DEFAULT 'unknown', -- UP | DOWN | DEGRADED | UNKNOWN
  last_polled_at       TIMESTAMPTZ,               -- set by SNMP poller after each successful poll
  last_seen_at         TIMESTAMPTZ,               -- last successful contact (any protocol)
  is_active            BOOLEAN NOT NULL DEFAULT true,
  archived_at          TIMESTAMPTZ,               -- soft-delete; archived devices excluded from polls
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT devices_ip_unique UNIQUE (ip),
  CONSTRAINT devices_hostname_group_unique UNIQUE (hostname, group_id)
);
-- Indexes
CREATE INDEX idx_devices_group      ON devices (group_id);
CREATE INDEX idx_devices_status     ON devices (status) WHERE is_active = true;
CREATE INDEX idx_devices_tags       ON devices USING GIN (tags);
CREATE INDEX idx_devices_attrs      ON devices USING GIN (custom_attributes jsonb_path_ops);
CREATE INDEX idx_devices_search_vec ON devices USING GIN (search_vector); -- tsvector trigger column
```

**Changes vs summary:** added `status`, `last_polled_at`, `last_seen_at`, `is_active`, `archived_at`, `created_at`, `updated_at`; changed `tags JSON` → `tags TEXT[]` (native array operators + efficient GIN index); added UNIQUE constraints on `ip` and `(hostname, group_id)`.

---

#### `device_status_current` *(new — high-write, poller-owned)*
One row per device, upserted by pollers after every poll. Separating status from `devices` prevents write contention (pollers write every 60s; inventory edits write occasionally).

```sql
CREATE TABLE device_status_current (
  device_id              UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  status                 TEXT NOT NULL DEFAULT 'unknown',
  since                  TIMESTAMPTZ NOT NULL DEFAULT now(), -- when current status began
  last_snmp_ok_at        TIMESTAMPTZ,
  last_ssh_ok_at         TIMESTAMPTZ,
  last_gnmi_ok_at        TIMESTAMPTZ,
  consecutive_failures   INT NOT NULL DEFAULT 0,
  failure_reason         TEXT,                               -- last error message
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Pollers write: `INSERT ... ON CONFLICT (device_id) DO UPDATE SET status=..., updated_at=now()`. No read-modify-write cycle; single-row upsert is lock-free.

---

#### `metrics` *(TimescaleDB hypertable)*
```sql
CREATE TABLE metrics (
  time        TIMESTAMPTZ NOT NULL,
  device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  metric_id   SMALLINT    NOT NULL REFERENCES metric_types(id), -- normalized (not text)
  value       DOUBLE PRECISION NOT NULL,
  -- No surrogate PK — hypertable primary key is (time, device_id, metric_id)
  CONSTRAINT metrics_pk PRIMARY KEY (time, device_id, metric_id)
);
SELECT create_hypertable('metrics', 'time', chunk_time_interval => INTERVAL '1 day');
SELECT add_retention_policy('metrics', INTERVAL '90 days');
SELECT add_compression_policy('metrics', compress_after => INTERVAL '7 days');
ALTER TABLE metrics SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'device_id, metric_id',
  timescaledb.compress_orderby   = 'time DESC'
);
CREATE INDEX idx_metrics_device_time ON metrics (device_id, time DESC);
```

**Changes vs summary:** normalized `metric_name TEXT` → `metric_id SMALLINT FK metric_types` (saves ~20 bytes per row × 259M rows = ~5 GB); explicit `PRIMARY KEY (time, device_id, metric_id)` prevents duplicate metric writes; compression `segmentby = device_id, metric_id` groups same-device same-metric data contiguously for 90%+ compression ratio.

---

#### `metric_types` *(new — normalization table)*
```sql
CREATE TABLE metric_types (
  id      SERIAL PRIMARY KEY,
  name    TEXT NOT NULL UNIQUE,   -- e.g. 'cpu_util', 'mem_util', 'if_in_octets'
  unit    TEXT,                   -- '%', 'bytes', 'bps', 'ms' — for display
  description TEXT
);
```

---

#### `telemetry_stream` *(TimescaleDB hypertable)*
```sql
CREATE TABLE telemetry_stream (
  time        TIMESTAMPTZ  NOT NULL,
  device_id   UUID         NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  path_id     INT          NOT NULL REFERENCES gnmi_paths(id), -- normalized (not text)
  value_num   DOUBLE PRECISION,        -- numeric value (NULL if string)
  value_str   TEXT,                    -- string value (NULL if numeric)
  value_type  TEXT NOT NULL,           -- 'int' | 'float' | 'string' | 'bool'
  labels      JSONB,                   -- additional gNMI metadata key/value pairs
  CONSTRAINT telemetry_pk PRIMARY KEY (time, device_id, path_id)
);
SELECT create_hypertable('telemetry_stream', 'time', chunk_time_interval => INTERVAL '1 hour');
SELECT add_retention_policy('telemetry_stream', INTERVAL '7 days');
SELECT add_compression_policy('telemetry_stream', compress_after => INTERVAL '1 hour');
ALTER TABLE telemetry_stream SET (
  timescaledb.compress,
  timescaledb.compress_segmentby = 'device_id, path_id',
  timescaledb.compress_orderby   = 'time DESC'
);
```

**Changes:** normalized `gnmi_path TEXT` → `path_id INT FK gnmi_paths`; added `value_type`, `value_str` columns (gNMI paths can return string values, not just numerics); added `labels JSONB`.

---

#### `gnmi_paths` *(new — normalization table)*
```sql
CREATE TABLE gnmi_paths (
  id          SERIAL PRIMARY KEY,
  path        TEXT NOT NULL UNIQUE,  -- e.g. 'openconfig-interfaces:interfaces/interface/state/counters'
  description TEXT,
  vendor      TEXT                   -- NULL = all vendors
);
```

---

#### `continuous_aggregates` *(TimescaleDB — required for dashboard performance)*
```sql
-- Hourly rollup — dashboard sparklines query this, never the raw table
CREATE MATERIALIZED VIEW metrics_hourly
WITH (timescaledb.continuous) AS
SELECT
  time_bucket('1 hour', time) AS bucket,
  device_id,
  metric_id,
  avg(value) AS avg_val,
  max(value) AS max_val,
  min(value) AS min_val,
  count(*)   AS sample_count
FROM metrics
GROUP BY bucket, device_id, metric_id
WITH NO DATA;
SELECT add_continuous_aggregate_policy('metrics_hourly',
  start_offset => INTERVAL '3 hours', end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '1 hour');

-- Daily rollup — trend charts and reports query this
CREATE MATERIALIZED VIEW metrics_daily
WITH (timescaledb.continuous) AS
SELECT
  time_bucket('1 day', time) AS bucket,
  device_id, metric_id,
  avg(value) AS avg_val, max(value) AS max_val, min(value) AS min_val, count(*) AS sample_count
FROM metrics GROUP BY bucket, device_id, metric_id WITH NO DATA;
SELECT add_continuous_aggregate_policy('metrics_daily',
  start_offset => INTERVAL '2 days', end_offset => INTERVAL '1 day', schedule_interval => INTERVAL '1 day');
```

---

#### `alerts`
```sql
CREATE TABLE alerts (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  alert_rule_id        UUID REFERENCES alert_rules(id) ON DELETE SET NULL,  -- NEW FK
  severity             TEXT NOT NULL,   -- critical | warning | info
  message              TEXT NOT NULL,
  source               TEXT NOT NULL,   -- snmp | gnmi | anomaly | manual
  status               TEXT NOT NULL DEFAULT 'active',  -- active | acknowledged | resolved | suppressed
  acknowledged_by      UUID REFERENCES users(id),
  acknowledged_at      TIMESTAMPTZ,
  suppression_reason   TEXT,            -- maintenance_window | snooze | jit | predictive
  last_notification_at TIMESTAMPTZ,     -- for dedup / re-notification logic
  parent_incident_id   UUID REFERENCES incidents(id) ON DELETE SET NULL,
  fired_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at          TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_device_status ON alerts (device_id, status, fired_at DESC);
CREATE INDEX idx_alerts_severity_status ON alerts (severity, status);
CREATE INDEX idx_alerts_active ON alerts (fired_at DESC) WHERE status = 'active'; -- partial index
```

**Changes:** added `alert_rule_id FK`, `acknowledged_by/at`, `suppression_reason`, `last_notification_at`, `parent_incident_id`, `updated_at`; added partial index on active alerts only (most queries).

---

#### `alert_rules`
```sql
CREATE TABLE alert_rules (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name                     TEXT NOT NULL,
  metric_id                INT REFERENCES metric_types(id),  -- normalized
  condition                TEXT NOT NULL,  -- gt | lt | eq | ne | anomaly
  threshold                DOUBLE PRECISION,
  evaluation_window_secs   INT NOT NULL DEFAULT 60,   -- "CPU > 90 for N seconds"
  cooldown_secs            INT NOT NULL DEFAULT 300,  -- min time before re-firing same rule+device
  channels                 JSONB NOT NULL DEFAULT '[]', -- references notification_channel IDs
  severity                 TEXT NOT NULL DEFAULT 'warning',
  enabled                  BOOLEAN NOT NULL DEFAULT true,
  last_evaluated_at        TIMESTAMPTZ,
  last_fired_at            TIMESTAMPTZ,
  created_by               UUID REFERENCES users(id),
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

#### `incidents` + junction tables *(normalized)*
```sql
CREATE TABLE incidents (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title            TEXT NOT NULL,
  severity         TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'open', -- open | acknowledged | resolved
  acknowledged_by  UUID REFERENCES users(id),
  acknowledged_at  TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at      TIMESTAMPTZ
);
-- Junction tables replace alert_ids JSON and device_ids JSON
CREATE TABLE incident_alerts (
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  alert_id    UUID NOT NULL REFERENCES alerts(id)    ON DELETE CASCADE,
  PRIMARY KEY (incident_id, alert_id)
);
CREATE TABLE incident_devices (
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  device_id   UUID NOT NULL REFERENCES devices(id)   ON DELETE CASCADE,
  PRIMARY KEY (incident_id, device_id)
);
```

**Why junction tables over JSON arrays:** `SELECT * FROM incidents WHERE device_id = ?` requires a JSON parse and sequential scan with JSON arrays; with a junction table it's an indexed join. Reports like "how many incidents affected device X in Q2?" become a 5ms query instead of a 500ms full-table scan.

---

#### `maintenance_windows` + junction table
```sql
CREATE TABLE maintenance_windows (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  group_id         UUID REFERENCES device_groups(id),  -- entire group OR specific devices
  recurrence_rule  TEXT,            -- null = one-time; cron expr = recurring (e.g. "0 2 * * 0")
  start_at         TIMESTAMPTZ NOT NULL,
  end_at           TIMESTAMPTZ NOT NULL,
  suppress_alerts  BOOLEAN NOT NULL DEFAULT true,
  created_by       UUID NOT NULL REFERENCES users(id),
  reason           TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE maintenance_window_devices (
  window_id UUID NOT NULL REFERENCES maintenance_windows(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  PRIMARY KEY (window_id, device_id)
);
CREATE INDEX idx_mw_time ON maintenance_windows (start_at, end_at);  -- active window lookup
```

---

#### `config_backups`
```sql
CREATE TABLE config_backups (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  git_commit_sha   TEXT,                   -- NULL while in_progress
  status           TEXT NOT NULL DEFAULT 'pending',  -- pending | in_progress | success | failed
  error_message    TEXT,                   -- populated on failure
  backup_size_bytes INT,                   -- for anomaly detection (config grew by 50KB?)
  duration_ms      INT,                    -- SSH session duration
  triggered_by     TEXT NOT NULL,          -- scheduled | manual | <user_id>
  backed_up_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_backup_success CHECK (
    status != 'success' OR git_commit_sha IS NOT NULL
  )
);
CREATE INDEX idx_config_backups_device ON config_backups (device_id, backed_up_at DESC);
CREATE INDEX idx_config_backups_failed ON config_backups (device_id) WHERE status = 'failed';
```

---

#### `change_requests`
```sql
CREATE TABLE change_requests (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  template_id          UUID REFERENCES config_templates(id),
  template_variables   JSONB,              -- values substituted into Jinja2 template
  config_snippet       TEXT NOT NULL,      -- rendered config to push
  dry_run_output       TEXT,               -- device response to dry-run check
  dry_run_passed       BOOLEAN,            -- explicit pass/fail flag
  rollback_commit_sha  TEXT,               -- git SHA to revert to on rollback
  status               TEXT NOT NULL DEFAULT 'pending',
  requested_by         UUID NOT NULL REFERENCES users(id),
  reviewer_id          UUID REFERENCES users(id),
  reviewer_comment     TEXT,
  external_ticket_id   TEXT,
  applied_at           TIMESTAMPTZ,        -- when the push actually executed
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

#### `users` *(corrected)*
```sql
ALTER TABLE users ADD COLUMN scim_external_id  TEXT;          -- IdP user ID for SCIM sync
ALTER TABLE users ADD COLUMN last_login_at     TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN login_count       INT DEFAULT 0;
ALTER TABLE users ADD COLUMN deactivated_at    TIMESTAMPTZ;   -- records WHEN deactivated
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMPTZ; -- for password expiry policy
ALTER TABLE users ADD COLUMN created_at        TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN updated_at        TIMESTAMPTZ NOT NULL DEFAULT now();

-- Separate table for WebAuthn credentials (one user can have multiple YubiKeys/passkeys)
CREATE TABLE webauthn_credentials (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id     BYTEA NOT NULL UNIQUE,      -- WebAuthn credential ID
  public_key        BYTEA NOT NULL,             -- COSE public key
  sign_count        BIGINT NOT NULL DEFAULT 0,  -- anti-replay counter
  aaguid            UUID,                       -- authenticator model identifier
  display_name      TEXT,                       -- user-set: "Work YubiKey", "MacBook Touch ID"
  last_used_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webauthn_user ON webauthn_credentials (user_id);
```

---

#### `audit_log` *(corrected)*
```sql
ALTER TABLE audit_log ADD COLUMN session_id   UUID;   -- groups all actions in one browser session
ALTER TABLE audit_log ADD COLUMN jit_grant_id UUID REFERENCES jit_access_grants(id);
CREATE INDEX idx_audit_resource  ON audit_log (resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_user_time ON audit_log (user_id, timestamp DESC);
CREATE INDEX idx_audit_detail    ON audit_log USING GIN (detail);  -- JSON search
```

---

#### `discovery_jobs` *(encryption fix)*
```sql
-- snmp_community was plaintext — fix:
ALTER TABLE discovery_jobs RENAME COLUMN snmp_community TO snmp_community_enc;
-- Column now stores AES-256-GCM ciphertext, decrypted only at job execution time
```

---

#### `device_poller_assignments` *(end-dating fix)*
```sql
CREATE TABLE device_poller_assignments (
  device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  poller_id     TEXT NOT NULL REFERENCES poller_nodes(poller_id),
  assigned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  unassigned_at TIMESTAMPTZ,   -- NULL = currently active assignment
  PRIMARY KEY (device_id, assigned_at)  -- history preserved; current = WHERE unassigned_at IS NULL
);
CREATE INDEX idx_dpa_active ON device_poller_assignments (device_id) WHERE unassigned_at IS NULL;
```

---

#### `notification_channels` *(new — normalizes alert_rules.channels JSON)*
```sql
CREATE TABLE notification_channels (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  channel_type TEXT NOT NULL,  -- email | slack | teams | pagerduty | webhook | eda | kafka
  config_enc  BYTEA NOT NULL,  -- AES-256-GCM encrypted JSON (URL, token, routing key)
  enabled     BOOLEAN NOT NULL DEFAULT true,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE alert_rule_channels (
  rule_id    UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
  PRIMARY KEY (rule_id, channel_id)
);
```

**Why normalize:** JSON arrays of channel configs can't be joined, indexed, or audited independently. A single channel updated once (e.g., Slack webhook URL rotation) now propagates to all rules that reference it — no per-rule update needed.

---

#### `event_subscriptions` + `event_delivery_log` *(new — for EDA and webhooks)*
Defined in the Event Notifications section below.

---

### Index Summary

Complete index list for query patterns described in this spec:

| Table | Index | Type | Covers |
|---|---|---|---|
| `devices` | `(group_id)` | btree | Inventory filter by group |
| `devices` | `(status) WHERE is_active` | partial btree | Dashboard status counts |
| `devices` | `(tags)` | GIN | Tag-based filter `@>` |
| `devices` | `(custom_attributes)` | GIN jsonb_path_ops | Any custom attribute query |
| `devices` | `(search_vector)` | GIN | Full-text hostname/tag/attr search |
| `device_status_current` | PK = device_id | btree | Current status lookup |
| `metrics` | `(device_id, time DESC)` | btree | Per-device metric history |
| `metrics` | `(metric_id, time DESC)` | btree | Cross-device metric queries |
| `telemetry_stream` | `(device_id, time DESC)` | btree | Per-device telemetry |
| `alerts` | `(device_id, status, fired_at DESC)` | btree | Active alerts per device |
| `alerts` | `(severity, status)` | btree | Global severity dashboard |
| `alerts` | `(fired_at DESC) WHERE status='active'` | partial | Active alerts (most queries) |
| `audit_log` | `(user_id, timestamp DESC)` | btree | Per-user audit |
| `audit_log` | `(resource_type, resource_id, timestamp DESC)` | btree | Per-resource audit |
| `audit_log` | `(detail)` | GIN | JSON field search |
| `config_backups` | `(device_id, backed_up_at DESC)` | btree | Latest backup per device |
| `config_backups` | `(device_id) WHERE status='failed'` | partial | Failed backup dashboard |
| `compliance_results` | `(device_id, rule_id, checked_at DESC)` | btree | Latest result per device+rule |
| `compliance_results` | `(rule_id, status) WHERE status='fail'` | partial | Rules with failures |
| `security_events` | `(event_type, timestamp DESC)` | btree | SIEM event type queries |
| `refresh_tokens` | `(token_hash)` | btree | Token lookup (primary auth path) |
| `refresh_tokens` | `(user_id) WHERE revoked_at IS NULL` | partial | Active tokens per user |
| `api_keys` | `(key_hash)` | btree | Key lookup (primary auth path) |
| `api_keys` | `(user_id) WHERE revoked_at IS NULL` | partial | Active keys per user |
| `webauthn_credentials` | `(credential_id)` | btree UNIQUE | WebAuthn authentication |
| `maintenance_windows` | `(start_at, end_at)` | btree | Active window lookup |
| `device_poller_assignments` | `(device_id) WHERE unassigned_at IS NULL` | partial | Current assignment |
| `device_neighbors` | `(source_device_id)` | btree | Topology graph neighbors |
| `jit_access_grants` | `(user_id) WHERE revoked_at IS NULL AND expires_at > now()` | partial | Active JIT grants |
| `compliance_rules` | `(enabled) WHERE enabled=true` | partial | Scan job rule list |
| `notification_channels` | `(channel_type) WHERE enabled=true` | partial | Channel dispatch |

---

## Auth & RBAC

### Roles

| Role | Capabilities |
|---|---|
| Admin | Full access: users, roles, devices, push, settings, IdP config |
| Operator | View all + push configs, acknowledge alerts |
| Read-Only | View dashboards and history only |
| API | Service account for automation (scoped permissions via API key) |

- JWT access tokens expire in 15 minutes; refresh tokens in 7 days (stored `httpOnly; Secure; SameSite=Strict` cookie)
- Every config push and alert acknowledgement writes to `audit_log`
- Device groups can be scoped to specific roles (Operator for group A cannot push to group B)
- Role membership synced from IdP groups (Okta group → NetPilot role mapping, AD group → NetPilot role mapping) — no manual role assignment needed when using SSO

### Pluggable AuthProvider Backend

All authentication paths funnel through a single `AuthProvider` protocol in `core/auth_provider.py`. Every provider returns the same `AuthResult` (user record + NetPilot JWT). Adding a new IdP = implement one class.

```
core/auth_provider.py     AuthProvider protocol + AuthResult dataclass
core/providers/
  local.py                bcrypt + TOTP in-app
  oidc.py                 Generic OIDC (Okta, Azure AD, Google, etc.)
  saml.py                 SAML 2.0 SP (AD FS, on-prem AD)
  ldap.py                 Direct LDAP/LDAPS (on-prem AD without AD FS)
```

Active providers and their config are driven by environment variables — enable/disable without code changes.

### Auth Paths

**Path 1 — Local (admin bootstrap / fallback)**
- `POST /api/auth/login` → bcrypt verify → optional TOTP check → NetPilot JWT
- Local accounts are the fallback if all IdPs are unreachable; at least one local Admin account always exists
- TOTP enforced for all local accounts with Admin role

**Path 2 — OIDC (Okta, Azure AD / Entra ID, any OIDC IdP)**
- `GET /api/auth/oidc/login?provider=<name>` → builds Authorization URL with PKCE + `nonce` → redirect to IdP
- IdP handles all MFA (Okta Verify push, Microsoft Authenticator, biometric, SMS) — NetPilot never sees the second factor
- Callback at `GET /api/auth/oidc/callback` → validate ID token signature + `nonce` + `aud` + expiry → upsert user → issue NetPilot JWT
- ID token signed by IdP; public keys fetched from IdP JWKS endpoint and cached with TTL
- Multiple OIDC providers supported simultaneously (Okta for employees, Azure AD for contractors)

**Path 3 — SAML 2.0 (AD FS, on-prem Active Directory)**
- NetPilot acts as SAML Service Provider (SP); metadata exposed at `/api/auth/saml/metadata`
- `GET /api/auth/saml/login` → signed AuthnRequest → AD FS / ADFS proxy
- AD handles Kerberos / NTLM / smartcard / Windows Hello MFA
- ACS endpoint at `POST /api/auth/saml/acs` → validate assertion signature + conditions → upsert user → issue NetPilot JWT
- Library: `python3-saml`; SP certificate rotated via env var without restart

**Path 4 — Direct LDAP/LDAPS (on-prem AD without AD FS)**
- `POST /api/auth/login` with LDAP backend → bind as user to verify password → fetch group memberships → map to NetPilot roles
- TLS required (`ldaps://` or STARTTLS); plain LDAP rejected
- Library: `ldap3`; service account used for group lookups (read-only, minimal permissions)

### SCIM 2.0 — Automated User Lifecycle

SCIM (System for Cross-domain Identity Management, RFC 7644) allows Okta or Azure AD to automatically provision and deprovision NetPilot users — no manual user creation, and more importantly, **automatic deprovisioning when an employee leaves**.

**SCIM server endpoints** (implemented in `modules/auth/scim_router.py`):

| Endpoint | Operation |
|---|---|
| `GET /scim/v2/Users` | List users (used by IdP to reconcile) |
| `POST /scim/v2/Users` | Create user from IdP directory |
| `GET /scim/v2/Users/{id}` | Read single user |
| `PUT /scim/v2/Users/{id}` | Full update (name, email, active status) |
| `PATCH /scim/v2/Users/{id}` | Partial update — most important: `{"active": false}` immediately deactivates |
| `DELETE /scim/v2/Users/{id}` | Hard delete (Okta preference) |
| `GET /scim/v2/Groups` | Map IdP groups → NetPilot roles |
| `PATCH /scim/v2/Groups/{id}` | Add/remove group members → role changes |

**Deprovisioning flow:**
```
Employee leaves org → HR triggers offboarding in Okta
    ↓
Okta SCIM PATCH /scim/v2/Users/{netpilot_id}  { "active": false }
    ↓
NetPilot: user.is_active = false; all refresh_tokens revoked; Redis user_revoked_at set
    ↓
All active sessions terminated within 15 minutes (access token TTL)
```

This is the most important user lifecycle operation — manual deprovisioning is an audit finding in SOC2 and PCI-DSS assessments.

**SCIM authentication:** the IdP authenticates to the SCIM endpoint using a long-lived bearer token (`np_scim_<token>`) stored in the IdP connector config. This token has the `scim:write` scope — distinct from all user-facing API scopes.

### Just-In-Time (JIT) Access

For privileged operations (config push to production devices, Admin role actions) that are rarely needed, JIT access provides time-bounded elevation rather than persistent privilege:

**Flow:**
1. Operator clicks "Request elevated access" in the UI
2. Submits: reason, device(s) or group, requested duration (max 4h), optional ticket ID
3. Request is sent to Admins via in-app notification + email
4. Admin approves → `jit_access_grants` table records: user_id, scope, device_ids, expires_at, reason, approved_by
5. User's effective permissions include the JIT grant until `expires_at`
6. After expiry: access automatically revoked, user must re-request
7. All actions taken during the JIT window are tagged in `audit_log` with the `jit_grant_id`

JIT is enforced in the `require_role()` FastAPI dependency — it checks both permanent role AND active JIT grants. A Read-Only user with a JIT grant for `config:push` on group A can push configs; without the grant, the same endpoint returns 403.

### Break-Glass Emergency Access

When all IdPs are unreachable and the normal local Admin account is locked/forgotten, a break-glass procedure provides last-resort access:

- A break-glass token is generated at setup time: `python -m tools.generate_breakglass` → outputs a 64-byte token to stdout (only time it's shown)
- Token is stored as an HMAC-SHA256 hash in the DB + printed to the on-call runbook
- `POST /api/auth/breakglass` with the token → issues a time-limited Admin JWT (1h, no refresh)
- **Every break-glass use** fires a `break_glass_used` Critical security event — visible in SIEM immediately
- Token is single-use: after use, a new token must be generated and the old hash is marked consumed
- Physical storage requirement: break-glass token printed and stored in sealed envelope in the NOC — not in any digital system

### MFA Support

| MFA method | How it works | Enforced by |
|---|---|---|
| TOTP (Google Authenticator, Authy, 1Password) | `pyotp` — QR code enrolment in Settings | NetPilot (local auth path) |
| WebAuthn / FIDO2 (YubiKey, passkeys, Touch ID) | `py_webauthn` — hardware key or platform authenticator | NetPilot (local auth path) |
| Okta Verify (push, biometric, TOTP) | Okta handles the MFA step before issuing OIDC token | Okta (OIDC path) |
| Microsoft Authenticator / Conditional Access | Azure AD handles MFA; NetPilot just validates the resulting ID token | Azure AD (OIDC path) |
| Duo Security | Duo Universal Prompt via OIDC or as Okta/AD MFA plugin | Duo / IdP |
| Smartcard / PIV / CAC | AD handles it; forwarded via SAML assertion | AD FS (SAML path) |

MFA enforcement policy: Admin-configurable per auth path. Local path can require TOTP or WebAuthn. OIDC/SAML paths delegate enforcement to the IdP — NetPilot rejects ID tokens from IdPs not configured with MFA policy.

### REST API Security

**API Keys (for automation and service accounts)**
- Key format: `np_live_<32-bytes-base58>` — prefix identifies environment, body is unguessable
- Only `SHA-256(key)` stored in DB; full key shown exactly once at creation — non-recoverable
- Each key has: owner user, name, scopes (`read` / `write` / `config:push` / `admin`), optional expiry, last-used timestamp
- Rate limited independently from browser sessions (higher rate for trusted automation keys)
- Key rotation: generate new key → overlap window (configurable, default 24h) → revoke old key; both valid during overlap

**OAuth2 Machine-to-Machine (client credentials flow)**
- For automation pipelines that need short-lived tokens rather than long-lived keys
- `POST /api/auth/token` with `grant_type=client_credentials` + client_id + client_secret → scoped access token (1h expiry)
- Client credentials registered by Admin; secret stored hashed; never logged

**API key management table:**

| Column | Description |
|---|---|
| `id` | UUID |
| `user_id` | Owner (service account user) |
| `name` | Human label ("Ansible prod", "Terraform CI") |
| `key_hash` | SHA-256 of full key |
| `key_prefix` | First 8 chars for display/identification |
| `scopes` | JSON array of granted scopes |
| `expires_at` | Optional hard expiry |
| `last_used_at` | Updated on each use |
| `revoked_at` | Set when rotated or revoked |

**API security headers and transport**
- All API responses include `Cache-Control: no-store` to prevent credential caching by proxies
- API versioning via URL prefix (`/api/v1/`) so breaking security changes can be rolled out in a new version without breaking consumers
- OpenAPI schema (auto-generated by FastAPI) documents required scopes per endpoint — visible in `/docs` (disabled in production; accessible only to Admin role)

---

## Module Details

### Monitor
- APScheduler SNMP poll job fires every 60s across all devices in parallel (asyncio gather)
- Persistent gNMI subscriptions started at app startup via `lifespan`; reconnect loop with exponential backoff (1s → 2s → 4s → max 60s)
- Metrics written to TimescaleDB; latest value cached in-process for fast dashboard loads
- WebSocket endpoint at `/ws/telemetry` streams live metric updates to the Vue frontend
- Threshold-based alert rules evaluated after each poll batch

### Config Management
- Nightly backup job SSHs to each device, pulls running config, commits to `configs/` git repo via GitPython
- Diff API: given two commit SHAs (or "latest vs previous"), returns structured unified diff
- Compliance scan runs hourly: each rule is a regex applied to the latest config; failures written to `compliance_results`
- Config push flow: render Jinja2 template → dry-run (send to device, parse for errors) → confirm → commit → write audit log → rollback available via `git revert`
- Unexpected config change detection: if backup differs from previous commit outside a scheduled window, fires an alert

### Config Credential Scrubbing

**Raw configs stored in git are never modified.** Scrubbing is applied exclusively at read time in `core/config_scrubber.py` when the API serves config content to any client — browser, API key, or OAuth2 token. No plaintext secret ever appears in an API response.

#### Architecture

```
configs/ (git)          ← full config, unscrubbed, at rest (git-crypt encrypted)
       ↓
GET /api/v1/config/devices/{id}/content
GET /api/v1/config/devices/{id}/diff
       ↓
ConfigScrubber.scrub(text, vendor)   ← applied here, in service layer
       ↓
API response → browser               ← scrubbed text only
```

The scrubber lives in `core/config_scrubber.py`. Every vendor has a list of `ScrubRule(pattern: re.Pattern, label: str)` objects. A single `scrub()` call returns `ScrubResult(text: str, redaction_count: int, weak_encryption_warnings: list[str])`.

#### Patterns scrubbed per vendor

**Cisco IOS / IOS-XE / NX-OS:**

| Config line pattern | What gets replaced |
|---|---|
| `enable secret \S+` | secret value |
| `enable password \S+` | password value |
| `username \S+ (secret\|password) \d* \S+` | secret/password value |
| `neighbor \S+ password \S+` | BGP MD5 password |
| `ip ospf authentication-key \S+` | OSPF auth key |
| `ip ospf message-digest-key \d+ md5 \S+` | OSPF MD5 key |
| `area \S+ authentication message-digest key \d+ md5 \S+` | OSPF area MD5 key |
| `snmp-server community \S+ (RO\|RW\|...)` | community string |
| `radius-server key \S+` | RADIUS shared secret |
| `tacacs-server key \S+` | TACACS+ key |
| `key \S+` (inside key-chain stanzas) | key string |
| `crypto isakmp key \S+ address \S+` | IKEv1 PSK |
| `crypto ikev2 ... psk \S+` | IKEv2 PSK |
| `ntp authentication-key \d+ md5 \S+` | NTP auth key |
| `standby \d+ authentication \S+` | HSRP auth string |
| `tunnel key \S+` | GRE tunnel key |
| `password \S+` (generic fallback) | any remaining password field |

**Arista EOS:** `secret sha512 \S+`, `ospf authentication-key \S+`, `isis authentication key \S+`

**Juniper JunOS:** `\$9\$[A-Za-z0-9./]+` (all `$9$` encrypted values), `authentication \S+` in routing stanzas, community name in SNMP hierarchy

**Generic fallback (all vendors):** any line matching `(?i)(password|secret|key|community)\s+\S+` that wasn't caught by vendor-specific rules

#### Replacement format

Scrubbed values are replaced with `<redacted>` inline, preserving the rest of the line:

```
Before: enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
After:  enable secret 5 <redacted>

Before: neighbor 10.0.0.1 password BGPsecret123
After:  neighbor 10.0.0.1 password <redacted>

Before: snmp-server community corp_ro RO
After:  snmp-server community <redacted> RO
```

#### Diff scrubbing

When a secret line changed between two versions, the diff shows that **something changed** without revealing either value:

```diff
- neighbor 10.0.0.1 password <redacted>
+ neighbor 10.0.0.1 password <redacted>  ⚠ sensitive value changed
```

The `⚠ sensitive value changed` annotation is added by the scrubber when both sides match the same pattern but have different values. This tells engineers the BGP password was rotated without exposing old or new values.

#### Weak encryption warnings

Cisco Type 0 (plaintext) and Type 7 (reversibly obfuscated) passwords are flagged with a compliance warning surfaced in the UI alongside the config view:

```
⚠ 2 weak password encodings detected:
  Line 14: "enable password" uses Type 0 (plaintext) — replace with "enable secret"
  Line 22: "username admin password 7 ..." uses Type 7 (reversible) — replace with "secret 9"
```

These also generate `compliance_results` entries under a built-in rule "No plaintext or Type-7 passwords" that ships with NetPilot by default.

#### UI presentation

- A yellow info bar above every config view: **"X sensitive values redacted for display security"**
- Hovering a `<redacted>` token shows a tooltip: *"Sensitive value hidden. Use SSH directly on the device to view raw configuration."*
- No "show raw" toggle — even Admin role does not see plaintext secrets in the browser. Raw access requires direct device SSH or physical console.
- Redaction count is included in the API response metadata: `{ "content": "...", "redaction_count": 14, "weak_encryption_warnings": [...] }`

#### Compliance reports and exports

All PDF/CSV compliance reports that include config snippets apply the same scrubber before writing output. The scrubber is never bypassed for any output format — a report emailed to a recipient contains no credentials.

#### Audit log

`GET /api/v1/config/devices/{id}/content` is logged in `audit_log` (user, timestamp, device, IP). If a user repeatedly downloads configs for devices outside their normal group, the security event log emits a `config_access_anomaly` event for SIEM review.

### Inventory
- Device CRUD via REST; bulk import via CSV upload
- Groups and tags for filtering; tags are free-form strings stored as JSON array
- Device detail page shows: current metrics, last config backup, compliance status, alert history

### Compliance Rules Engine

#### Rule Model

Compliance rules test whether a device config satisfies a constraint. Every rule is a regex pattern applied to the latest config backup for a device.

**Rule fields:**

| Field | Description |
|---|---|
| `id` | UUID |
| `name` | Human label ("Require SSH version 2", "No Telnet allowed") |
| `description` | What this rule checks and why |
| `pattern` | Python `re` regex pattern (compiled at save time; validated for safety) |
| `rule_type` | `must_contain` / `must_not_contain` / `must_match_value` / `line_count_min` |
| `flags` | `IGNORECASE`, `MULTILINE`, `DOTALL` — user-selectable checkboxes |
| `severity` | `critical` / `major` / `minor` / `info` |
| `category` | Free-form string (e.g., "Security Baseline", "Change Mgmt", "CIS Benchmark L1") |
| `remediation_hint` | Text shown in the UI when rule fails — tells the engineer what to add/remove |
| `applies_to_device_types` | JSON array of device_type values — empty means all |
| `applies_to_groups` | JSON array of group IDs — empty means all |
| `applies_to_tags` | JSON array of tag strings — empty means all |
| `applies_to_compliance_category` | Attribute value match — e.g., "PCI", "HIPAA", "SOX" |
| `enabled` | bool — disabled rules are skipped without deletion |
| `is_builtin` | bool — built-in rules can be disabled but not deleted |

**Rule types explained:**

| `rule_type` | Passes when |
|---|---|
| `must_contain` | Config text contains ≥1 match for the pattern |
| `must_not_contain` | Config text contains 0 matches for the pattern |
| `must_match_value` | A captured group in the pattern equals `expected_value` (e.g., `ip ssh version (\d+)` must capture `2`) |
| `line_count_min` | Pattern matches ≥ N lines (e.g., minimum 3 NTP servers configured) |

#### Regex Safety

Unconstrained regex from user input can cause catastrophic backtracking (ReDoS), hanging the compliance worker:

- On save (`POST /api/v1/compliance/rules`), the pattern is validated by `re2` (Google's linear-time regex engine, Python binding `google-re2`) — if `re2` rejects the pattern, it is rejected with a helpful error
- All compliance scans execute patterns via `re2` (not stdlib `re`) — linear time guaranteed
- Pattern max length: 2048 characters
- If `re2` is unavailable (fallback), patterns run inside a thread with a 5-second timeout via `concurrent.futures.ThreadPoolExecutor` with `Future.result(timeout=5)` — timeout fires `compliance_rule_timeout` event

#### Rule Assignment Logic

The rule's `applies_to_*` fields are combined with AND logic: a rule is evaluated against a device only if **all** applicable filter conditions match.

```
Device matches rule if:
  device.device_type IN rule.applies_to_device_types  (or rule list is empty)
  AND device.group_id IN rule.applies_to_groups       (or rule list is empty)
  AND any(tag in device.tags for tag in rule.applies_to_tags)  (or rule list is empty)
  AND device.custom_attributes.compliance_category == rule.applies_to_compliance_category  (or rule field is null)
```

#### Compliance Scan Flow

```
APScheduler job (hourly):
  for each enabled rule:
    devices = query devices matching rule assignment filters
    for each device:
      config = latest git backup text for this device
      scrubbed_config = ConfigScrubber.scrub(config, vendor)  ← scan scrubbed config
      result = evaluate_rule(rule, scrubbed_config)
      upsert compliance_results(device_id, rule_id, status, detail, checked_at)
      if status == FAIL and previous status was PASS:
        fire compliance_violation_alert(device, rule)
```

Scrubbed config is used for scanning — secrets are not needed to evaluate structural compliance (presence of `ip ssh version 2`, absence of `service telnet`), and this prevents the scanner from inadvertently logging a credential.

#### Compliance Rule UI

**Rules list (`/compliance/rules`):**
- Table of all rules with: name, category, severity, scope (device types / groups / tags), enabled toggle, last scan result summary (% pass)
- Filter by category, severity, scope, enabled/disabled
- Bulk enable / disable / delete (non-builtin)
- "Run scan now" — triggers an immediate scan for selected rules

**Create / Edit rule form:**
- Name, description, severity, category
- Pattern input with a **live test pane** (see Rule Testing below)
- Rule type selector with explanation text per type
- `expected_value` field (shown only for `must_match_value`)
- `line_count_min` field (shown only for `line_count_min`)
- Flags: `IGNORECASE` / `MULTILINE` / `DOTALL` checkboxes
- Scope: device types multi-select, groups multi-select, tags multi-select, compliance_category text input
- Remediation hint text area
- Save → `POST /api/v1/compliance/rules`

**Rule Testing (inline test pane):**

The rule form has a split-pane: left = pattern + options, right = test input + result. As the user types the pattern:

1. A text area accepts a config snippet (paste from any device or from history)
2. Live evaluation runs client-side (via `re2` WASM or server-side on debounce) — no save needed
3. Matching lines are **highlighted in yellow** in the config snippet
4. Pass / Fail badge updates in real time
5. Captured groups are shown: `Captured group 1: "2"` (useful for `must_match_value` rules)

Separately, from the device detail Compliance tab:
- Select any specific config backup from history + select one or more rules → "Run Test"
- Shows per-rule pass/fail with matched/unmatched line highlights
- Useful for: "does this old config version violate this new rule?"

#### REST API

| Action | Endpoint |
|---|---|
| List rules | `GET /api/v1/compliance/rules` |
| Create rule | `POST /api/v1/compliance/rules` |
| Update rule | `PATCH /api/v1/compliance/rules/{id}` |
| Delete rule | `DELETE /api/v1/compliance/rules/{id}` |
| Enable / disable | `PATCH /api/v1/compliance/rules/{id}` `{ "enabled": true/false }` |
| List results for device | `GET /api/v1/compliance/devices/{device_id}/results` |
| Scan device now | `POST /api/v1/compliance/devices/{device_id}/scan` |
| Test pattern | `POST /api/v1/compliance/rules/test` `{ "pattern", "rule_type", "flags", "config_text" }` |
| Get violation history | `GET /api/v1/compliance/results?rule_id=&device_id=&from=&to=` |

#### Data Model Update

```
compliance_rules   id, name, description, pattern, rule_type, expected_value (nullable),
                   line_count_min (nullable), flags (JSON), severity, category,
                   remediation_hint, applies_to_device_types (JSON), applies_to_groups (JSON),
                   applies_to_tags (JSON), applies_to_compliance_category (nullable),
                   enabled, is_builtin, created_by, created_at, updated_at

compliance_results id, device_id, rule_id, status (pass/fail/skip/error), detail (JSON — matched lines,
                   captured groups), config_backup_sha, checked_at
```

`skip` status is written when a rule's `applies_to_*` filters don't match the device — the scan ran but this rule doesn't apply to this device. This distinguishes "not applicable" from "never scanned".

#### Built-in Rule Packs

NetPilot ships with curated rule packs that are active by default:

| Pack | Rules |
|---|---|
| **Security Baseline** | SSH v2 enforced, no Telnet, no HTTP server, AAA enabled, NTP auth, logging configured |
| **Weak Password Detection** | Type 0 and Type 7 passwords (ties into ConfigScrubber weak_encryption_warnings) |
| **CIS Cisco IOS Benchmark L1** | 20+ rules from the CIS hardening guide |
| **SNMP Hardening** | No SNMP v1, v3 authPriv enforced, no default community strings |
| **BGP Security** | BGP MD5 auth present, no `no bgp enforce-first-as` |
| **Access Control** | VTY access-class configured, console timeout set |

Built-in packs can be disabled per device group but not deleted. Custom rules are additive.

### Alerting
- Rules defined per metric + condition + threshold (e.g. `cpu_util > 90 for 5m`)
- Severity levels: Critical, Warning, Info
- Each rule has a list of enabled notification channels
- Alert deduplication: a second firing of the same rule on the same device extends the existing alert rather than creating a new one
- Alert auto-resolution when metric returns below threshold

---

## Security

### Philosophy
Two goals: eliminate as many vulnerabilities as possible upfront, and keep every security control in one place so a future fix is a one-line change rather than a hunt across the codebase.

### Authentication & Session Security
- JWT access tokens expire in 15 minutes; refresh tokens in 7 days stored in `httpOnly; Secure; SameSite=Strict` cookies (not localStorage — prevents XSS token theft)
- Refresh token rotation on every use: old token is invalidated immediately (stored in `revoked_tokens` table with TTL index)
- Bcrypt for password hashing (cost factor 12); password length enforced 12–128 chars
- Rate limiting on `/api/auth/*` endpoints via `slowapi` (10 attempts/minute per IP); lockout after 20 failures
- All auth logic lives in `core/security.py` — one file to audit and patch

### Authorization & Access Control (OWASP A01)
- Every FastAPI route uses a `Depends(require_role(...))` guard — no unprotected endpoints by accident
- Device group scoping enforced at the service layer (not just UI): an Operator for group A cannot read, push, or diff devices in group B even via direct API calls
- Config push additionally requires a second RBAC check (`can_push` permission) separate from read access
- Audit log written for every mutation (create/update/delete/push/ack) — tamper-evident append-only table

### Injection Prevention (OWASP A03)
- All DB queries use SQLAlchemy ORM with parameterized statements — no raw SQL string formatting anywhere
- Jinja2 config templates rendered with `autoescape=True` for any user-supplied variable values; template files themselves are admin-only managed (not user-uploaded)
- SSH commands sent via Netmiko's `send_command`/`send_config_set` — no shell=True subprocess, no f-string command construction
- All API inputs validated by Pydantic v2 models with strict types; extra fields rejected (`model_config = ConfigDict(extra='forbid')`)

### Sensitive Data Protection (OWASP A02)
- SNMP community strings encrypted at rest using `cryptography.fernet` with the app's `SECRET_KEY`; decrypted only in memory at poll time, never logged
- SSH/device credentials stored as references to environment variables or Vault/SSM paths — the DB row contains only the reference name, not the secret value
- No credentials or secrets appear in log output (structured logging with a redaction filter for known secret field names)
- TLS required for all external connections: gNMI uses `grpc.ssl_channel_credentials`, RESTCONF SSE uses `https`, SMTP uses STARTTLS/TLS
- **Device config credential scrubbing**: passwords, keys, and community strings in running configs are scrubbed server-side before any API response — raw config text never reaches the browser. Scrubbing is vendor-aware (Cisco IOS/XE/XR/NX-OS, Arista EOS, Juniper JunOS) with a generic fallback. Applied uniformly to config view, diff view, compliance reports, and CSV/PDF exports. No "show raw" toggle exists — not even for Admins. See Config Management → Config Credential Scrubbing for full detail.

### Security Headers & Transport (OWASP A05)
All HTTP responses include these headers, set once in a FastAPI middleware in `main.py`:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

CORS configured to explicit origin allowlist (not `*`); set in one place in `core/config.py`.

### SSH & Network Protocol Hardening
- Netmiko connections use `StrictHostKeyChecking` with a managed `known_hosts` file; unknown hosts are rejected, not auto-accepted
- SSH key-based auth preferred over passwords; credential type tracked per device (`ssh_key_ref` vs `password_ref`)
- gNMI connections use mutual TLS (client cert + server cert verification) where the device supports it; falls back to server-cert-only with a warning
- SNMP v3 (`authPriv` mode: authentication + encryption) preferred over v2c; v2c allowed only if explicitly set per device with a visible warning in the UI
- Full post-quantum + hardened SSH cipher suite applied to all Netmiko connections — see **Transport Layer Security** section for detail

### Dependency & Supply Chain Security (OWASP A06)
- All Python deps pinned in `pyproject.toml` with exact versions; `pip-audit` runs in CI on every push and blocks merge on any known CVE
- All Node deps pinned in `package-lock.json`; `npm audit --audit-level=high` runs in CI
- Renovate bot (or Dependabot) opens weekly PRs for dependency updates; auto-merged for patch bumps with passing tests
- Docker base images pinned to digest (`python:3.12-slim@sha256:...`); image scanning via Trivy in CI

### Container Image Signing (Sigstore / cosign)

Every NetPilot image built in CI is **signed using Sigstore cosign** (keyless signing via OIDC identity of the CI runner):

```bash
# CI pipeline — after docker build + push
cosign sign --yes ghcr.io/netpilot/api:1.4.2@sha256:<digest>
```

The signature is stored in the OCI registry alongside the image. At deployment time, Kubernetes admission webhook (via `policy-controller` or Kyverno) verifies the signature before pulling:

```yaml
# kyverno-policy.yaml — reject unsigned images
spec:
  rules:
  - name: verify-netpilot-image
    match: { resources: { kinds: [Pod] } }
    verifyImages:
    - imageReferences: ["ghcr.io/netpilot/*"]
      attestors:
      - count: 1
        entries:
        - keyless:
            issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/org/netpilot/.github/workflows/build.yml@refs/heads/main
```

Any image not signed by the NetPilot CI pipeline — including a tampered or injected image — is rejected before it can start.

### Software Bill of Materials (SBOM)

An SBOM in **SPDX 2.3 / CycloneDX 1.5** format is generated for every image build and attached as an OCI attestation:

```bash
# CI pipeline — generate SBOM with Syft + attach as cosign attestation
syft ghcr.io/netpilot/api:1.4.2 -o spdx-json > sbom.spdx.json
cosign attest --predicate sbom.spdx.json --type spdxjson ghcr.io/netpilot/api:1.4.2
```

The SBOM lists every OS package, Python package, and Node package with exact version, license, and CVE status. This is required for:
- SLSA Level 2+ compliance (provenance + SBOM)
- Enterprise vendor security questionnaires
- FedRAMP / SOC2 audits that require a complete software inventory
- Rapid response when a new CVE drops — immediately know if any version of the affected library is in any NetPilot image ever shipped

SBOM is queryable: `cosign verify-attestation --type spdxjson ghcr.io/netpilot/api:1.4.2 | jq '.payload | @base64d | fromjson'`

### Runtime Security (Falco)

Falco runs as a privileged DaemonSet (K8s) or privileged container alongside each host (Compose). It uses eBPF kernel probes to detect anomalous syscalls at runtime — catching attacks that bypass container-layer controls:

**Rules deployed for NetPilot:**
```yaml
# Custom Falco rules — falco_rules.local.yaml
- rule: Unexpected outbound connection from api container
  desc: API container should only connect to pgbouncer, redis, vault, cyberark, OIDC IdPs
  condition: >
    evt.type=connect and container.name=netpilot-api
    and not fd.sip in (ALLOWED_API_EGRESS_IPS)
  output: "Unexpected egress from api pod (ip=%fd.sip cmd=%proc.cmdline)"
  priority: CRITICAL

- rule: Shell spawned in NetPilot container
  desc: A shell in a production container is almost always an attacker
  condition: >
    spawned_process and container.name startswith "netpilot"
    and proc.name in (bash, sh, zsh, ash, dash)
  output: "Shell in netpilot container (pod=%k8s.pod.name user=%user.name cmd=%proc.cmdline)"
  priority: CRITICAL

- rule: Write to read-only filesystem
  desc: NetPilot containers run with read-only root filesystem
  condition: >
    open_write and container.name startswith "netpilot"
    and not fd.name startswith /tmp
    and not fd.name startswith /var/log/netpilot
  priority: ERROR
```

Falco alerts are forwarded to the same SIEM sink as application security events (`LOG_SINK` env var). A shell spawned in the API container fires an immediate Critical alert to Admin — it means someone is already inside.

### Distroless + Minimal Base Images

Production images use **Google Distroless** (`gcr.io/distroless/python3-debian12`) instead of `python:3.12-slim`:

| Property | `python:3.12-slim` | Distroless |
|---|---|---|
| Shell (`bash`, `sh`) | Present | **Absent** |
| Package manager (`apt`) | Present | **Absent** |
| C library utils (`curl`, `wget`) | Partial | **Absent** |
| Image size | ~140 MB | ~55 MB |
| CVE attack surface | Medium | Minimal |

Without a shell, an attacker who gains code execution inside the container cannot run `bash`, install tools, or pivot laterally — the Falco shell-spawned rule catches any attempt. Combined with `readOnlyRootFilesystem: true` in K8s, the container is a sealed runtime environment.

Build pattern:
```dockerfile
# Multi-stage: build in full Python, run in distroless
FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --target=/app/deps .

FROM gcr.io/distroless/python3-debian12 AS runtime
COPY --from=builder /app/deps /app/deps
COPY --from=builder /app/backend /app/backend
ENV PYTHONPATH=/app/deps
USER nonroot
ENTRYPOINT ["python", "-m", "backend.main"]
```

### Container & Runtime Hardening
- API container runs as a non-root user (`USER appuser`); filesystem is read-only except for the `configs/` volume mount
- PostgreSQL container not exposed on host network — internal Docker network only; only the `api` service can reach it
- No `privileged: true`, no host network mode, no host volume mounts except the explicit `configs/` bind mount
- Secrets passed via Docker secrets or environment variables from a `.env` file that is `.gitignore`d; `.env.example` ships with placeholders only

### Fixing Future Vulnerabilities Quickly
The controls above are deliberately centralised so a fix touches one file:

| What needs changing | Where to change it |
|---|---|
| JWT algorithm or expiry | `core/security.py` |
| Security response headers | `main.py` middleware |
| Password hashing algorithm | `core/security.py` → `hash_password()` |
| Credential encryption scheme | `core/crypto.py` — single Fernet wrapper used everywhere |
| Rate limiting thresholds | `core/config.py` (env var driven) |
| CORS origins | `core/config.py` (env var driven) |
| Dependency with a CVE | `pyproject.toml` or `package.json` — CI enforces the fix before merge |
| TLS cert rotation | Docker secret or env var swap — no code change |
| Swap Okta for a different OIDC IdP | Change `OIDC_ISSUER_URL` env var — no code change |
| Add a new SAML IdP | New env var block + upload their metadata — no code change |
| Rotate SAML SP certificate | Swap `SAML_SP_CERT` + `SAML_SP_KEY` env vars |
| Revoke a compromised API key | `DELETE /api/keys/<id>` — instant, no restart needed |
| Enforce MFA on local accounts | `REQUIRE_MFA=true` env var — applies globally |
| Disable local auth (SSO-only mode) | `LOCAL_AUTH_ENABLED=false` env var |
| Add a new credential pattern to scrub | Add one `ScrubRule` to the vendor list in `core/config_scrubber.py` |
| Extend scrubbing to a new vendor | Add a new vendor rule set to `core/config_scrubber.py` |
| Switch a device from DB creds to Vault | Update `credentials_ref` field — no code change |
| Switch all devices to CyberArk | Bulk re-credential via `PATCH /api/v1/inventory/devices/bulk-recredential` |
| Rotate AES-256-GCM master key | Add new key to `CREDENTIAL_MASTER_KEYS` env var, run `tools/reencrypt_credentials.py` |
| Revoke a compromised Vault token | Vault revoke — takes effect within 1h (token TTL); Vault agent renews immediately with new token |
| Replace CyberArk with Vault (or vice versa) | Implement one `CredentialProvider` class in `core/credential_providers/` |

### Security Logging & SIEM Integration (OWASP A09)

Every security-relevant event is emitted to a dedicated `security_events` table AND to the structured log stream simultaneously. The log stream can be tailed by any SIEM without code changes.

**Security event types logged:**
- `login_success`, `login_failed`, `login_locked` (with IP, user agent, auth provider)
- `mfa_success`, `mfa_failed`, `mfa_enrolled`, `mfa_removed`
- `impossible_travel` — login from two geographic regions within 1 hour
- `session_revoked`, `refresh_token_rotated`
- `api_key_created`, `api_key_revoked`, `api_key_used` (sampled — 1 in 100)
- `config_push_attempted`, `config_push_succeeded`, `config_push_failed`
- `admin_role_granted`, `admin_role_revoked`, `user_deactivated`
- `compliance_violation_detected`
- `idp_config_changed`

**Structured log format** (JSON lines, one event per line):
```json
{"ts":"2026-04-25T14:32:01Z","level":"WARN","event":"login_failed",
 "user":"alice@corp.com","ip":"203.0.113.4","ua":"Mozilla/5.0","provider":"local","attempt":3}
```

**SIEM / log shipping** — configured via env var; zero code change to switch targets:
- `LOG_SINK=stdout` (default — Docker log driver ships to wherever)
- `LOG_SINK=syslog://host:514`
- `LOG_SINK=splunk://host:8088?token=<HEC token>`
- `LOG_SINK=elastic://host:9200`
- `LOG_SINK=file:/var/log/netpilot/security.jsonl`

**Log integrity:** `security_events` table is append-only (no UPDATE/DELETE permissions granted to the app DB user on this table). Log lines include a SHA-256 chain hash of the previous entry so tampering is detectable.

#### Splunk Integration (Detailed)

Splunk is the primary SIEM target for enterprise deployments. NetPilot integrates via **Splunk HTTP Event Collector (HEC)** for real-time event streaming, with a Universal Forwarder fallback for environments where HEC is not available.

**HEC integration (`LOG_SINK=splunk://`):**

```python
# core/logging.py — Splunk HEC handler
SPLUNK_HEC_URL=https://splunk.corp.com:8088/services/collector/event
SPLUNK_HEC_TOKEN=<HEC token>           # created in Splunk: Settings → Data Inputs → HTTP Event Collector
SPLUNK_INDEX=netpilot                  # target index
SPLUNK_SOURCETYPE=netpilot:security    # override per event type (see below)
SPLUNK_BATCH_SIZE=100                  # events batched before flush (reduces HEC calls)
SPLUNK_FLUSH_INTERVAL_MS=2000         # flush every 2s regardless of batch size
SPLUNK_TLS_VERIFY=true                 # verify Splunk's TLS certificate
```

**Event routing by index and sourcetype:**

| Event stream | Splunk index | sourcetype |
|---|---|---|
| Security events (`login_*`, `mfa_*`, `config_push_*`) | `netpilot_security` | `netpilot:security` |
| Audit log (all mutations) | `netpilot_audit` | `netpilot:audit` |
| Application access log (API requests) | `netpilot_access` | `netpilot:access` |
| Background job events (poll results, backup results) | `netpilot_ops` | `netpilot:ops` |
| CVE scan results | `netpilot_security` | `netpilot:cve` |
| pgaudit DB-level events | `netpilot_db` | `netpilot:pgaudit` |

Each event sent to HEC includes standard Splunk metadata:
```json
{
  "time": 1745612121.483,
  "host": "netpilot-api-1",
  "source": "netpilot",
  "sourcetype": "netpilot:security",
  "index": "netpilot_security",
  "event": {
    "ts": "2026-04-25T14:32:01Z",
    "level": "WARN",
    "event": "login_failed",
    "user": "alice@corp.com",
    "ip": "203.0.113.4",
    "provider": "local",
    "attempt": 3,
    "_chain_hash": "sha256:abc123..."
  }
}
```

**Batching and reliability:**
- Events are buffered in an in-process queue (max 10,000 events); if HEC is unreachable, events overflow to `LOG_SINK_FALLBACK=file:/var/log/netpilot/hec-buffer.jsonl`
- On HEC recovery, the buffer file is replayed in order — no events lost during transient Splunk outages
- HEC acknowledgement mode enabled (`ackEnabled=true`) — Splunk confirms receipt before events are removed from the buffer

**Splunk Universal Forwarder fallback:**
For environments where HEC access is restricted, configure `LOG_SINK=file:/var/log/netpilot/security.jsonl` and deploy a Splunk Universal Forwarder on the host with:
```
[monitor:///var/log/netpilot/security.jsonl]
index = netpilot_security
sourcetype = netpilot:security
```
The log file uses JSON Lines format (one JSON object per line) — Splunk's JSON line-breaking works natively.

**Pre-built Splunk searches and dashboards** — shipped as a Splunk app in `integrations/splunk/`:
- `Failed Logins by IP` — detect brute-force
- `Admin Role Changes` — SOC alert for privilege escalation
- `Config Push Activity` — all pushes in a time range with device + user + status
- `CVE Status Overview` — current open CVEs by severity
- `Compliance Violations Trend` — pass/fail ratio over 30 days

#### Syslog Integration (RFC 5424)

For Syslog-ng, rsyslog, QRadar, LogRhythm, or any RFC 5424-compliant SIEM:

```bash
LOG_SINK=syslog://loghost.corp.com:6514     # TLS syslog (recommended)
LOG_SINK=syslog://loghost.corp.com:514      # plain UDP syslog (no TLS — legacy only)
SYSLOG_FACILITY=16                          # local0 (16–23 = local0–local7)
SYSLOG_APP_NAME=netpilot
SYSLOG_STRUCTURED_DATA=true                 # emit RFC 5424 structured data elements
```

RFC 5424 structured data elements map NetPilot's fields to IANA-registered SD-IDs:
```
<133>1 2026-04-25T14:32:01Z netpilot-host netpilot - login_failed
[netpilot@52553 user="alice@corp.com" ip="203.0.113.4" provider="local" attempt="3"]
Login failed for alice@corp.com
```

**Syslog TLS:** transport uses TLS 1.3 with server certificate verification (`ssl_cafile` from env var). Plain UDP syslog accepted only if `SYSLOG_ALLOW_PLAINTEXT=true` is explicitly set — default is reject plain UDP.

#### pgaudit Log Forwarding

PostgreSQL's `pgaudit` logs are forwarded to the same SIEM as application logs. The `postgres` container's log output is JSON-formatted (`log_destination = jsonlog`) and shipped via one of:
- Docker log driver → Splunk logging driver (`splunk` Docker log driver with HEC token)
- File → Universal Forwarder monitoring `$PGDATA/pg_log/`
- Syslog output from PostgreSQL → same syslog sink

This ensures that direct DB access (bypassing the application) is visible in the same SIEM as application events — a DBA running `psql` directly against the database generates pgaudit entries that appear in the same security dashboard.

**Security alert rules** — these fire in-app alerts AND email the Admin group:
- ≥5 failed logins for the same user in 5 minutes
- Impossible travel detected
- First login for any new SSO-provisioned user
- Any Admin role grant/revoke
- API key created with `admin` scope

### Credential Encryption Key Rotation

All Fernet-encrypted values (SNMP community strings, TOTP secrets) must survive key rotation without data loss.

**Rotation procedure** (zero-downtime, no plaintext exposure):
1. Generate new Fernet key; add it to `ENCRYPTION_KEYS` env var as a comma-separated list (new key first, old key second)
2. `core/crypto.py` uses `MultiFernet` — it tries keys in order: encrypts with key[0], decrypts trying all keys
3. Run the background re-encryption job: `docker compose run --rm api python -m tools.reencrypt` — reads each encrypted value, decrypts with old key, re-encrypts with new key, writes back
4. Remove old key from `ENCRYPTION_KEYS` env var; redeploy
5. `encryption_key_versions` table records the rotation timestamp for audit

### Session Invalidation on User State Change

Active sessions (JWTs) must become invalid immediately when:
- User is deactivated (`is_active = false`) → `user_revoked_at` timestamp set; access token middleware rejects tokens issued before this timestamp
- Role changes → new role takes effect at next token refresh (≤15 min); for immediate effect, Admin can force-revoke all sessions via `POST /api/admin/users/{id}/revoke-sessions`
- Password reset → all refresh tokens for the user are invalidated in `refresh_tokens` table; access tokens expire naturally within 15 min

The access token middleware checks `user_revoked_at` on every request (cached in Redis or in-process LRU cache with 1-minute TTL to avoid a DB hit per request).

### Backup Security

**Config git repo** (`configs/`) — contains full running configs for up to 2000 devices including BGP passwords, OSPF keys, and ACLs:
- Repo encrypted at rest using `git-crypt` with a symmetric key stored in Vault/SSM
- Automated offsite backup: daily `git bundle` pushed to an encrypted S3 bucket (or equivalent)
- Access to the `configs/` volume restricted to the `api` container only

**PostgreSQL backups:**
- Daily `pg_dump` scheduled job (inside the `postgres` container via cron)
- Dumps encrypted with `gpg --symmetric` before upload; key stored in Vault/SSM
- Uploaded to offsite storage (S3 / Azure Blob / GCS) with 30-day retention
- Weekly restore test in CI validates backup integrity

**Backup restore drill** — documented in `docs/DISASTER_RECOVERY.md`; tested quarterly.

### Input Sanitization — CSV Injection

Bulk device import via CSV is vulnerable to formula injection if a hostname or description starts with `=`, `+`, `-`, or `@`. Any such cell value is prefixed with a `'` (tab character) before writing to DB and before generating any CSV export, preventing Excel/Sheets from interpreting it as a formula. This sanitization lives in one utility function in `core/sanitize.py`.

---

### Device & Protocol Injection Hardening

Network devices are the ultimate target — an attacker who can make NetPilot send crafted SSH commands or malformed SNMP payloads to a device can crash it, corrupt its config, or pivot into the management plane. Every path that touches a device is hardened as a distinct threat surface.

#### SSH Command Injection Prevention

**Input allowlist on change requests and templates:**
- All config snippet text submitted via `POST /api/v1/config/devices/{id}/change-requests` is validated before any SSH session opens
- Hostname, IP address, and community string fields accept only their respective character sets (hostname: `[A-Za-z0-9.\-_]`; IP: validated by `ipaddress.ip_address()`; community: `[A-Za-z0-9!@#$%^&*_\-]`)
- Reject any field value containing shell metacharacters (`|`, `;`, `&&`, `||`, backticks, `$()`, `>`, `<`, `\n`) — these have no valid place in a network config field

**Netmiko command execution:**
- All device interactions use Netmiko's `send_command()` and `send_config_set()` — never `subprocess`, never `os.system()`, never `shell=True`
- Netmiko sends commands as individual SSH channel writes, not as shell pipelines — there is no shell to inject into
- User-supplied Jinja2 template variables are HTML-escaped with `autoescape=True`; template files themselves are admin-managed (never user-uploaded)
- `send_config_set()` receives a Python list of command strings, not a single concatenated string — no delimiter injection possible

**Pre-execution dry-run gate:**
Every config push goes through a mandatory dry-run phase before any change is committed:

```
1. Render Jinja2 template with user variables
2. Validate rendered output against a per-vendor command allowlist
3. Send to device via "dry-run" method (Cisco: `| no-more`, Arista: `commit check`, JunOS: `commit check`)
4. Parse device response for error keywords: "Invalid input", "% Error", "Syntax error", "Incomplete command"
5. If any error keyword detected → abort, log `config_push_dry_run_failed`, alert Operator
6. Only if dry-run passes → proceed with actual push
```

**Anomalous device response detection:**
- If SSH returns an unexpected prompt (e.g., device drops into rommon, EXEC prompt instead of config mode, "enable password" prompt when key auth was expected), the session is aborted immediately
- `ssh_unexpected_prompt` security event is fired; the device is flagged in the UI with a warning badge
- Configurable regex per vendor for "expected prompt" detection in `drivers/vendors/`

#### SNMP Exploitation Mitigation

**Rate limiting per device:**
- SNMP poll concurrency capped via asyncio semaphore (default 500 simultaneous, tunable via `SNMP_CONCURRENCY`)
- Per-device SNMP retry limit: 3 attempts, 5-second timeout — avoids holding a socket open against an unresponsive device
- Protects the network management plane from accidental SNMP storms at 2000-device scale

**Community string protection:**
- SNMP v2c community strings stored AES-256-GCM encrypted; decrypted in memory only at poll time
- Community strings validated on input: no whitespace, max 32 chars, printable ASCII only — prevents malformed PDU construction
- SNMP v3 `authPriv` enforced where supported; v2c allowed only with explicit per-device override and a visible warning in the UI

**Malformed PDU defence:**
- `pysnmp` wraps all SNMP operations with exception handlers; malformed responses from devices (truncated PDUs, unexpected OID types) are caught and logged — they do not crash the poll worker
- SNMP OID injection: OIDs sent to devices are from a validated internal list (`drivers/snmp.py` OID registry), never constructed from user input

#### Config Push Output Validation

After a config push succeeds over SSH, the response from the device is parsed for error indicators before the git commit is written:

| Vendor | Error patterns checked |
|---|---|
| Cisco IOS/XE | `% Invalid input`, `% Incomplete command`, `% Ambiguous command`, `% Error` |
| Cisco NX-OS | `ERROR:`, `% Invalid command`, `% Permission denied` |
| Cisco IOS-XR | `RP/0/... ERROR`, `% Failed` |
| Arista EOS | `% Invalid input`, `Error:` (eAPI JSON `errors` field) |
| Juniper JunOS | `error:`, `syntax error` (PyEZ exception, `CommitError`) |

If any error pattern matches:
1. Push is marked `failed` in `change_requests`
2. The config is NOT committed to git — previous version preserved
3. `config_push_output_error` security event logged
4. Admin and Operator alerted immediately

This ensures that a partial or failed push never silently overwrites a known-good config in git.

#### Connection Safeguards

**SSH timeout hardening:**
```python
# drivers/ssh.py — applied to every device connection
DEVICE_CONNECT_TIMEOUT = 30      # seconds — abort if TCP SYN not answered
DEVICE_AUTH_TIMEOUT = 15         # seconds — abort if auth handshake stalls
DEVICE_COMMAND_TIMEOUT = 120     # seconds — abort if command produces no output
DEVICE_BANNER_TIMEOUT = 15       # seconds — abort if login banner hangs
```

A device that hangs at any of these stages gets a `device_ssh_timeout` event, is marked degraded in the UI, and the SSH thread is released immediately. No SSH thread is ever held open indefinitely.

**SSH known-hosts enforcement (device MITM prevention):**
- All SSH connections require a valid entry in the managed `known_hosts` file
- Host key changes block the connection (not auto-accepted) and fire `ssh_host_key_changed` — this is the primary control against management-plane MITM attacks
- First-time TOFU fingerprints are shown to an Admin for approval before being stored — automated-only acceptance is disabled

**gNMI stream validation:**
- gNMI telemetry paths subscribed to are from a validated allowlist per vendor — arbitrary path subscription is not permitted via the UI
- gNMI response parser has a max-event-size limit (default 64 KB per message) — oversized payloads are dropped with a warning rather than buffered
- gNMI reconnect uses exponential backoff capped at 60s — prevents reconnect storms against a misbehaving device

#### Device-Side Attack Surface Reduction

These recommendations are surfaced in the UI as compliance rules (see Compliance Rules Engine):

| Recommendation | Compliance rule |
|---|---|
| Disable HTTP server on Cisco | `no ip http server` must be present |
| Disable Telnet (use SSH only) | `transport input ssh` must be present |
| Enforce SSHv2 | `ip ssh version 2` must be present |
| Disable SNMP v1 | No `snmp-server community` with `version 1` |
| Disable unused services (CDP, finger, etc.) | `no cdp run`, `no service finger` must be present |
| AAA authentication required | `aaa new-model` must be present (Cisco) |
| Logging buffer configured | `logging buffered` must be present |
| NTP authentication enabled | `ntp authentication-key` must be present |

These are built-in compliance rules shipped with NetPilot (cannot be deleted, but can be disabled per device group by Admin).

---

## CVE Vulnerability Management

### Philosophy

NetPilot actively tracks its own software vulnerabilities — not just the devices it monitors. A tool that can SSH into 2000 network devices must itself be free of known exploitable CVEs. This module provides pre-install CVE gating, a live CVE dashboard, and guided self-healing remediation.

---

### Pre-Install CVE Check

Before the Docker containers start for the first time (and on every image build in CI), an automated CVE check runs against all installed software:

```
CI pipeline:
  1. Build Docker image
  2. pip-audit --output=json --desc > reports/python-cve.json
  3. npm audit --audit-level=high --json > reports/node-cve.json
  4. trivy image --format json netpilot-api:latest > reports/image-cve.json
  5. Fail build if any CVSS ≥ 7.0 CVE found with a known fix available
  6. Block merge — CVE is not "we'll fix it later"
```

**What is scanned:**
- Python packages (`pip-audit` against OSV database + NIST NVD)
- Node.js packages (`npm audit` / `trivy`)
- OS packages in the Docker base image (Trivy — checks Alpine/Debian packages against CVE databases)
- Dockerfile itself (Trivy misconfig scan — checks for root users, exposed secrets, world-readable volumes)

**Severity thresholds:**
| CVSS Score | Action |
|---|---|
| ≥ 9.0 (Critical) | **Block CI** — must be patched before any merge |
| 7.0–8.9 (High) | **Block CI** — must be patched or explicitly waived with justification |
| 4.0–6.9 (Medium) | Warning in CI — logged, Renovate opens a PR within 7 days |
| < 4.0 (Low) | Informational only |

**Waiver process:** A CVE can be waived (if no fix exists) by an Admin via `POST /api/v1/cve/waivers` — records the CVE ID, justification, expiry date, and approver. Waivers expire; an expired waiver re-blocks CI.

---

### CVE Dashboard (UI Tab)

A dedicated **CVE** tab in the navigation (visible to Admin and Operator roles) shows the current vulnerability posture of the running NetPilot installation:

#### Dashboard view

| Column | Description |
|---|---|
| CVE ID | Clickable link to NVD entry |
| Severity | Critical / High / Medium / Low (color-coded) |
| CVSS Score | Numeric score |
| Affected Component | Package name + installed version |
| Fixed In | Version that contains the fix (if available) |
| Published | Date CVE was published |
| Status | Open / Waived / Remediated / No Fix Available |
| Action | "Apply Fix" button (if automated fix available) |

**Filters:** by severity, by component type (Python / Node / OS), by status, date range.

**Sort:** default sort is CVSS descending (Critical first).

#### CVE detail panel

Clicking a CVE opens a side panel with:
- Full CVE description from NVD
- Affected packages and the vulnerable version range
- Remediation guidance (specific version to upgrade to, or workaround)
- References (NVD, GitHub advisory, vendor bulletin)
- Waiver history (who waived it, when, why)

---

### CVE Scan Job (APScheduler)

A nightly background job (`modules/cve/jobs.py`) runs the same CVE checks as CI but against the running container:

```python
# Runs daily at 03:30 UTC (offset from backup jobs)
@scheduler.scheduled_job("cron", hour=3, minute=30, id="cve_scan")
async def run_cve_scan():
    results = await cve_service.scan_all()       # pip-audit + npm audit + trivy
    await cve_service.store_results(results)      # persist to cve_scan_results table
    await cve_service.evaluate_alerts(results)    # fire alerts for new critical CVEs
```

**Alert escalation:**
- New Critical CVE (CVSS ≥ 9.0) with a fix available → in-app alert + email to all Admins
- New High CVE → in-app alert to Admins
- Previously-waived CVE has a fix now available → alert re-opens ("waiver can now be closed")

---

### Self-Healing Remediation

For Python package CVEs where an automated fix is safe to apply:

**Flow:**

```
Admin clicks "Apply Fix" on CVE card
         ↓
POST /api/v1/cve/{cve_id}/remediate
         ↓
Backend validates: is there a fixed version? Is it a patch bump? (major bumps require manual approval)
         ↓
Runs: pip install <package>==<fixed_version> inside a test container (isolated, not live)
         ↓
Runs: integration test suite against patched container (same suite as CI)
         ↓
If tests pass → creates a GitHub PR with the dependency bump via git API
If tests fail → marks remediation "failed — manual review required", shows test output
```

**What "self-healing" means and doesn't mean:**
- It means: NetPilot can propose and verify a fix, and create the PR
- It does NOT mean: unreviewable auto-merges to production — a human approves the PR
- Admin can configure `CVE_AUTO_PR=true` for patch bumps to open PRs without clicking; merging always requires human approval

**OS-level CVEs:**
- Cannot be auto-fixed inline (would require rebuilding the Docker image)
- Action: "Rebuild Image" button triggers a CI pipeline run (`POST /api/v1/cve/trigger-rebuild`) that builds a new image with updated base packages and runs the full test suite
- Admin approves the deployment via the normal deploy flow

---

### CVE Data Sources

| Source | What it covers | Update frequency |
|---|---|---|
| Google OSV API (`api.osv.dev`) | Python, Node, Go, Rust packages | Real-time |
| NIST NVD API v2 (`services.nvd.nist.gov`) | All CVEs (CPE-based) | Daily sync |
| GitHub Advisory Database | GitHub-hosted packages | Real-time via OSV |
| Trivy DB | OS packages + container images | Daily pull |

All CVE data is cached locally in the `cve_definitions` table with a TTL — the scanner works offline against the cached data if NVD is unreachable.

---

### Data Model Additions

| Table | Key columns |
|---|---|
| `cve_scan_results` | id, scan_at, scanner (pip_audit/npm_audit/trivy), cve_id, package_name, installed_version, fixed_version, cvss_score, severity, status (open/waived/remediated), detail (JSON) |
| `cve_waivers` | id, cve_id, justification, approved_by, expires_at, created_at |
| `cve_remediations` | id, cve_id, remediation_type (pr/rebuild), status (pending/in_progress/pr_opened/failed), pr_url, triggered_by, started_at, completed_at |

---

### Directory Structure Addition

```
backend/
  modules/
    cve/
      router.py      # GET /api/v1/cve/*, POST /api/v1/cve/waivers, POST /api/v1/cve/*/remediate
      service.py     # scan orchestration, result storage, alert evaluation
      jobs.py        # APScheduler nightly scan job
      scanners/
        pip_audit.py # subprocess pip-audit wrapper, parses JSON output
        npm_audit.py # subprocess npm audit wrapper
        trivy.py     # Trivy CLI wrapper (image + fs scan)
      schemas.py

frontend/
  views/
    CVE.vue          # CVE dashboard tab with filters, severity summary cards, data table
  components/
    CVEDetailPanel.vue   # slide-in panel with full CVE details + remediation actions
    CVESeverityBadge.vue # Critical/High/Medium/Low colored badge
```

---

## Error Handling & Resilience

- Per-device SSH/SNMP failures are isolated — logged and surfaced as device-level alerts, never propagate to crash the poll batch
- gNMI subscriber reconnects automatically; persistent disconnect (>5 min) fires a system alert
- Config push validates the template render before opening an SSH session; SSH errors abort the push and preserve the previous config in git
- All unhandled background job exceptions are caught in a global APScheduler listener, logged, and written as system-level alerts visible in the UI

---

## Testing Strategy

- **Unit tests**: driver parsers for each vendor tested against fixture files of real `show` command output (no device needed) — includes Gigamon (`show version`, `show port`), Opengear (`show version`, `show ports`), and BlueCat (`show configuration`) fixture files
- **Integration tests**: FastAPI test client + ephemeral PostgreSQL via `testcontainers-python`; covers all API endpoints and job logic
- **E2E tests**: Playwright against the Vue frontend with mock API responses; covers critical flows (login, device add, config diff, alert ack)
- **Lab smoke tests**: optional manual tests against GNS3 / EVE-NG for SSH and SNMP drivers; Gigamon/Opengear/BlueCat drivers tested against sandbox VMs if available
- CI: unit + integration on every push; E2E on merge to main
- **Security tests**: `pip-audit` + `npm audit` + Trivy image scan run in CI on every push; auth bypass and IDOR scenarios covered by integration test suite

---

## Transport Layer Security

### Design Principle

All transport — SSH to devices, HTTPS to browsers, gRPC telemetry, internal service connections — uses TLS 1.3 minimum with post-quantum hybrid key exchange where supported. Weak algorithms are explicitly disabled, not just deprioritised.

---

### SSH — Post-Quantum Hardened Cipher Suite

SSH is the primary management plane for 2000 network devices. NetPilot configures Paramiko (the Python SSH library underlying Netmiko) with an explicit algorithm preference list that:

1. **Prefers post-quantum hybrid KEX** — if the device supports it, a harvest-now/decrypt-later attack against the session recording yields nothing
2. **Falls back to strongest classical algorithms** — gracefully, without exposing weak algorithms
3. **Explicitly rejects all legacy algorithms** — no MD5, no SHA-1, no 3DES, no arcfour, no DH group1/group14

#### Key Exchange (KEX) — post-quantum first

```python
# drivers/ssh.py — applied to every Netmiko ConnectHandler
SSH_KEX_ALGORITHMS = [
    # Post-quantum hybrid (NIST ML-KEM-768 + X25519)
    # Finalised NIST FIPS 203 standard, August 2024
    "mlkem768x25519-sha256",                  # OpenSSH 9.9+ hybrid
    "sntrup761x25519-sha512@openssh.com",     # NTRU Prime hybrid (OpenSSH 9.0+ default)
    # Classical — strongest only
    "curve25519-sha256",                      # X25519 ECDH
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",                     # P-521
    "ecdh-sha2-nistp384",                     # P-384
    "diffie-hellman-group18-sha512",          # 8192-bit DH — last resort
    "diffie-hellman-group16-sha512",          # 4096-bit DH — last resort
    # Explicitly absent: group1, group14, group-exchange-sha1
]
```

**Hybrid KEM rationale**: `mlkem768x25519-sha256` combines ML-KEM-768 (post-quantum, NIST FIPS 203) with X25519 (classical). Both must be broken simultaneously to compromise the session. If a quantum computer breaks X25519 tomorrow, the ML-KEM component still holds. If ML-KEM has an undiscovered flaw, X25519 still holds. Neither weakness alone is sufficient.

#### Symmetric Ciphers — authenticated encryption only

```python
SSH_CIPHERS = [
    "chacha20-poly1305@openssh.com",   # preferred — stream cipher + Poly1305 MAC, timing-attack resistant
    "aes256-gcm@openssh.com",          # AES-256 in GCM — authenticated encryption
    "aes128-gcm@openssh.com",          # AES-128 in GCM — faster, still strong
    "aes256-ctr",                      # fallback for older devices lacking GCM
    # Explicitly absent: aes128-cbc, 3des-cbc, blowfish-cbc, arcfour, cast128-cbc
]
```

#### MAC — Encrypt-then-MAC (EtM) only

```python
SSH_MACS = [
    "hmac-sha2-512-etm@openssh.com",   # EtM — MAC computed over ciphertext (stronger)
    "hmac-sha2-256-etm@openssh.com",   # EtM
    "hmac-sha2-512",                    # fallback: MAC-then-Encrypt
    "hmac-sha2-256",
    # Explicitly absent: hmac-sha1, hmac-md5, hmac-ripemd160
]
```

EtM (Encrypt-then-MAC) is mandatory where supported — it prevents padding oracle and CBC-mode attacks that affect MAC-then-Encrypt.

#### Host Key Algorithms

```python
SSH_HOST_KEY_ALGORITHMS = [
    "ssh-ed25519",                     # EdDSA over Curve25519 — preferred
    "sk-ssh-ed25519@openssh.com",      # FIDO2/hardware-backed Ed25519
    "ecdsa-sha2-nistp521",             # P-521 ECDSA
    "ecdsa-sha2-nistp384",             # P-384 ECDSA
    "rsa-sha2-512",                    # RSA with SHA-512 — 4096-bit minimum enforced
    "rsa-sha2-256",                    # RSA with SHA-256
    # Explicitly absent: ssh-rsa (SHA-1), ssh-dss (DSA), ecdsa-sha2-nistp256 (weak curve)
]
```

RSA host keys accepted only if ≥ 4096 bits. Keys shorter than 4096 bits cause connection failure with a logged warning.

#### Paramiko transport configuration

```python
# drivers/ssh.py
import paramiko

def _hardened_transport_config() -> dict:
    return {
        "disabled_algorithms": {
            # Belt-and-suspenders: explicitly disable even if not in preference list
            "kex": [
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1",
            ],
            "keys": ["ssh-rsa", "ssh-dss"],
            "ciphers": ["3des-cbc", "blowfish-cbc", "cast128-cbc",
                        "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour"],
            "macs": ["hmac-md5", "hmac-sha1", "hmac-ripemd160",
                     "hmac-md5-96", "hmac-sha1-96"],
        },
        "preferred_kex": SSH_KEX_ALGORITHMS,
        "preferred_ciphers": SSH_CIPHERS,
        "preferred_macs": SSH_MACS,
        "preferred_keys": SSH_HOST_KEY_ALGORITHMS,
        "look_for_keys": False,     # use only explicitly supplied credentials
        "allow_agent": False,       # no SSH agent forwarding
    }
```

#### Device compatibility and fallback behaviour

Not all network devices support post-quantum KEX (most Cisco IOS/XE images predate it). Negotiation is automatic — the SSH handshake picks the strongest algorithm both sides support.

| Device capability | Algorithm negotiated |
|---|---|
| OpenSSH 9.9+ (Linux hosts, modern Arista EOS) | `mlkem768x25519-sha256` |
| OpenSSH 9.0–9.8 | `sntrup761x25519-sha512@openssh.com` |
| Cisco IOS-XE 17.x, NX-OS 10.x, JunOS 23.x | `curve25519-sha256` |
| Older IOS/XE without Curve25519 | `ecdh-sha2-nistp521` |
| Legacy devices (IOS 15.x) | `diffie-hellman-group16-sha512` |
| Device only supports DH-group14/group1 | **Connection rejected** — logged as `ssh_weak_kex_rejected` security event; Admin alerted |

If a device is rejected, the UI shows a warning badge: "SSH rejected — device only supports deprecated key exchange. Upgrade device SSH configuration."

#### known_hosts management

- `configs/known_hosts` file inside the `configs/` git repo — version-controlled
- First connection to a new device: fingerprint displayed in the UI for Admin confirmation before being added to `known_hosts` (TOFU — trust on first use, with human review)
- Host key changes on existing devices: connection blocked, `ssh_host_key_changed` security event fired, Admin must explicitly approve — prevents MITM attacks

---

### HTTPS — TLS 1.3 with Post-Quantum Hybrid

#### nginx TLS configuration

The nginx container uses **OpenSSL 3.x with the OQS (Open Quantum Safe) provider** to enable post-quantum hybrid key exchange for browser connections:

```nginx
# nginx/nginx.conf

server {
    listen 443 ssl;
    http2 on;

    # TLS 1.3 only — 1.2 explicitly disabled
    ssl_protocols TLSv1.3;

    # TLS 1.3 cipher suites (in priority order)
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

    # Post-quantum hybrid key exchange groups (with OQS provider)
    # X25519MLKEM768 = X25519 + ML-KEM-768 hybrid (NIST FIPS 203)
    # Supported by: Chrome 131+, Firefox 132+, curl 8.9+
    ssl_ecdh_curve X25519MLKEM768:X25519:P-521:P-384;

    # Certificate — ECDSA P-384 (stronger than P-256, widely supported)
    ssl_certificate     /certs/netpilot.crt;
    ssl_certificate_key /certs/netpilot.key;
    ssl_trusted_certificate /certs/ca-chain.crt;

    # OCSP stapling — reduces TLS handshake latency + privacy
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;

    # No session tickets — eliminates risk of ticket key compromise
    # TLS 1.3 uses PSK for resumption instead
    ssl_session_tickets off;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;

    # Disable 0-RTT early data — replay attack risk
    ssl_early_data off;

    # Security headers (also set in FastAPI middleware, belt-and-suspenders)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
}

# Redirect all HTTP to HTTPS — no plain HTTP accepted
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

#### Why TLS 1.3 only (no 1.2 fallback)

- TLS 1.3 mandates forward secrecy on every connection — there is no cipher suite without ephemeral key exchange
- TLS 1.2 has 300+ cipher suites including weak ones; misconfiguration risk is high
- All supported browsers (Chrome 70+, Firefox 63+, Safari 12.1+) support TLS 1.3
- Network devices accessing the API use `requests`/`httpx`/`curl` — all support TLS 1.3
- TLS 1.2 is explicitly disabled to eliminate downgrade attack surface

#### Post-quantum TLS rationale

`X25519MLKEM768` combines X25519 + ML-KEM-768 (NIST FIPS 203). Supported by:
- Chrome 131+ (shipped ML-KEM by default)
- Firefox 132+
- curl 8.9+ with liboqs
- Java 21+ with Bouncy Castle provider

For clients that don't support `X25519MLKEM768` (legacy browsers, older curl), nginx negotiates `X25519` — the curve list is an ordered preference, not a hard requirement. No connection is rejected for lacking PQC support on the client side.

#### Certificate standards

| Property | Value | Reason |
|---|---|---|
| Algorithm | ECDSA P-384 | Stronger than P-256; smaller than RSA-4096; widely supported |
| Key size | 384-bit | NIST security level 3 |
| Signature hash | SHA-384 | Matches key strength |
| Validity | ≤ 90 days | Shorter = faster compromise recovery; automate renewal |
| SAN | hostname + IP SANs | Required for internal/private CA deployments |
| OCSP | Must-Staple extension | Browser checks revocation without OCSP round-trip |

Certificate renewal is automated via `certbot` (Let's Encrypt) or internal CA integration. Expiry monitored by the watchdog — alerts 30, 14, and 7 days before expiry.

#### Internal service TLS

All internal Docker network connections use TLS 1.3 with mutual authentication:

| Connection | Protocol | Auth |
|---|---|---|
| nginx → FastAPI (uvicorn) | HTTP/1.1 on internal network (TLS terminated at nginx) | Internal Docker network |
| FastAPI → PgBouncer | TLS 1.3 | Client cert (mutual TLS) |
| PgBouncer → PostgreSQL | TLS 1.3 | Client cert (mutual TLS) |
| FastAPI → Vault | TLS 1.3 | AppRole + CA cert verification |
| FastAPI → CyberArk AIM | TLS 1.3 | mTLS client cert |
| FastAPI → gNMI devices | gRPC over TLS 1.3 | Server cert + optional mTLS |
| FastAPI → RESTCONF devices | HTTPS TLS 1.3 | Server cert verification |

`ssl_min_protocol_version = TLSv1.3` enforced in `postgresql.conf` and `pgbouncer.ini` — connections using TLS 1.2 are rejected at the PostgreSQL and PgBouncer level.

#### TLS certificate management (Docker secrets)

```bash
# Certs injected as Docker secrets — never baked into the image
docker secret create netpilot_cert    ./certs/netpilot.crt
docker secret create netpilot_key     ./certs/netpilot.key
docker secret create ca_chain         ./certs/ca-chain.crt
```

Cert rotation: update Docker secrets → rolling container restart — zero downtime.

---

### Algorithm Deprecation Tracking

A quarterly review checks each algorithm against NIST, IANA, and OpenSSH deprecation notices. The review is documented in `docs/CIPHER_REVIEW.md`. When an algorithm is deprecated:

1. Move it from the preference list to `disabled_algorithms` in `drivers/ssh.py`
2. Remove it from `ssl_ecdh_curve` / `ssl_ciphers` in `nginx.conf`
3. Run CI — any test using the deprecated algorithm will fail
4. One PR, one review, deployed

The "fixing future vulnerabilities" table already covers where each control lives for fast patching.

---

## Privileged Credential Management

### Design Principle

**NetPilot never needs to own device passwords.** The preferred architecture is: credentials live in CyberArk or Vault; NetPilot retrieves them just-in-time, uses them in memory for the duration of the SSH session, then discards them. Nothing sensitive is ever written to the database, logs, or disk by the application.

When an external PAM system is not available (lab environments, first-time setup), NetPilot falls back to AES-256-GCM encrypted storage in the database — a significant upgrade from the AES-128-CBC Fernet used previously.

### Credential Reference Model

Every device stores a `credentials_ref` string — a URI that tells the driver *where* to get the credential, not what it is:

```
vault://kv/secret/data/network/core-rtr-01           → HashiCorp Vault KV v2
vault://ssh/creds/netpilot-role?ip=10.1.1.1          → Vault SSH dynamic (OTP)
cyberark://NetworkSafe/core-rtr-01-ssh               → CyberArk AIM CCP REST
env://DEVICE_CORE_RTR_01_PASSWORD                    → env var (dev / lab only)
db://encrypted                                        → AES-256-GCM in DB (fallback)
```

The `credentials_ref` URI is the only thing stored in the `devices` table. Switching a device from DB-stored to Vault is a single field update — no code change, no redeploy.

### Pluggable CredentialProvider Backend

```
core/credential_provider.py      CredentialProvider protocol + CredentialResult dataclass
core/credential_providers/
  vault.py                        HashiCorp Vault (AppRole auth, KV v2, SSH dynamic)
  cyberark.py                     CyberArk AIM Central Credential Provider (CCP)
  env_var.py                      Environment variable (dev/lab only)
  encrypted_db.py                 AES-256-GCM encrypted column (fallback)
```

The driver layer (`drivers/ssh.py`) calls `await credential_provider.get(ref)` before opening an SSH session. The provider is selected by parsing the URI scheme of `credentials_ref`. The resolved `CredentialResult(username, password, ttl)` is held in memory only, never serialised.

---

### CyberArk AIM Integration

CyberArk AIM (Application Identity Manager) with the **Central Credential Provider (CCP)** REST API is the recommended integration for enterprise environments.

#### How it works

```
NetPilot driver needs SSH password for core-rtr-01
      ↓
credential_provider.get("cyberark://NetworkSafe/core-rtr-01-ssh")
      ↓
POST https://cyberark-aim/AIMWebService/api/Accounts
  AppID=NetPilot
  Safe=NetworkSafe
  Object=core-rtr-01-ssh
  Reason="SSH session for monitoring poll"   ← logged in CyberArk audit
  (authenticated via mTLS client certificate)
      ↓
CyberArk returns: { "UserName": "netpilot", "Content": "<password>", "Address": "10.1.1.1" }
      ↓
Password held in memory → SSH session opened → password object zeroed after session
```

#### Authentication to CyberArk AIM

Three methods supported, configured by env var `CYBERARK_AUTH_METHOD`:

| Method | How | Security level |
|---|---|---|
| `cert` (recommended) | mTLS client certificate — NetPilot presents a certificate signed by the CyberArk-trusted CA | Highest — no shared secret |
| `os` | OS-level credential (running user's certificate store) | High |
| `appid_only` | AppID without cert (CyberArk allows IP-based trust) | Medium — requires strict IP allowlist in CyberArk |

Client certificate stored as a Docker secret or in Vault — never in the image or on disk.

#### CyberArk-specific features

- **Automatic password rotation**: CyberArk rotates device passwords on its schedule. NetPilot always retrieves the current value — no stale credentials, no rotation coordination needed.
- **Dual account support**: CyberArk can provide two accounts in rotation. NetPilot retries with the alternate account if the first fails authentication (handles rotation overlap window).
- **Reason field**: every credential retrieval includes a `Reason` string logged in CyberArk's audit trail — visible in CyberArk reports independently of NetPilot's own audit log.
- **Safe + Object naming convention**: documented in `docs/CYBERARK_SAFE_STRUCTURE.md` — one Safe per device group (Production, Staging, etc.), Object name matches device hostname.

#### Configuration

```bash
CYBERARK_CCP_URL=https://cyberark-aim.corp.com
CYBERARK_APP_ID=NetPilot
CYBERARK_CLIENT_CERT=/run/secrets/cyberark-client.crt
CYBERARK_CLIENT_KEY=/run/secrets/cyberark-client.key
CYBERARK_CA_CERT=/run/secrets/cyberark-ca.crt
CYBERARK_CONNECTION_TIMEOUT=5          # fail fast rather than hang SSH poll
CYBERARK_RETRY_ATTEMPTS=2
CYBERARK_FALLBACK_TO_DB=false          # never fall back silently — fail instead
```

---

### HashiCorp Vault Integration

Two Vault secret engines supported: **KV v2** (static credentials) and **SSH Secrets Engine** (dynamic one-time passwords).

#### KV v2 — static credentials

```
credential_provider.get("vault://kv/secret/data/network/core-rtr-01")
      ↓
Vault client reads cached token (or renews via AppRole)
      ↓
GET https://vault/v1/secret/data/network/core-rtr-01
      ↓
Returns: { "data": { "username": "netpilot", "password": "<value>" } }
      ↓
Password held in memory → SSH session → zeroed after use
```

#### SSH Secrets Engine — dynamic OTP (preferred for highest security)

```
credential_provider.get("vault://ssh/creds/netpilot-role?ip=10.1.1.1")
      ↓
POST https://vault/v1/ssh/creds/netpilot-role
  { "ip": "10.1.1.1" }
      ↓
Vault generates a one-time password valid for 60 seconds
The device must have the Vault SSH helper installed
      ↓
OTP used for SSH → automatically invalidated after use
```

With dynamic OTPs, even if a credential is intercepted in transit, it cannot be reused.

#### AppRole Authentication to Vault

NetPilot authenticates to Vault using **AppRole** (recommended for service accounts):

```
Startup sequence:
1. Read role_id from env var (VAULT_ROLE_ID) — non-secret, static
2. Read secret_id from wrapped token file (VAULT_WRAPPED_SECRET_ID_PATH)
   → POST /v1/sys/wrapping/unwrap → gets real secret_id (one-time use)
3. POST /v1/auth/approle/login { role_id, secret_id } → Vault token (TTL 1h)
4. Token stored in memory; renewed every 45 min before expiry
5. secret_id rotated on every container start via a CI/CD pipeline step
```

The wrapped secret_id pattern means the secret_id file is a single-use token — if someone reads the file before NetPilot starts, NetPilot's startup fails (the token was already consumed), which is a detectable attack signal.

#### Vault Agent sidecar (optional, recommended for production)

Instead of the above, a **Vault Agent** sidecar container handles all auth + renewal and writes the current token to a shared memory volume (`tmpfs`). NetPilot reads the token file without needing to know the AppRole credentials at all:

```
vault-agent container:
  - authenticates to Vault (AppRole, Kubernetes auth, AWS IAM, etc.)
  - renews token automatically
  - writes token to /vault/token (tmpfs shared mount)

api container:
  - VAULT_TOKEN_FILE=/vault/token
  - reads token from file — never touches auth credentials
```

This is fully transparent to NetPilot's credential provider code.

#### Configuration

```bash
VAULT_ADDR=https://vault.corp.com:8200
VAULT_ROLE_ID=<role-id>                         # non-secret
VAULT_WRAPPED_SECRET_ID_PATH=/run/secrets/vault-wrapped-sid  # Docker secret
VAULT_CA_CERT=/run/secrets/vault-ca.crt
VAULT_NAMESPACE=network-ops                     # Vault Enterprise namespaces
VAULT_KV_MOUNT=secret
VAULT_SSH_MOUNT=ssh
VAULT_CONNECTION_TIMEOUT=3
VAULT_FALLBACK_TO_DB=false
```

---

### Fallback: AES-256-GCM Encrypted Storage

For environments without CyberArk or Vault, credentials are stored in the database encrypted with **AES-256-GCM** — authenticated encryption that provides both confidentiality (AES-256) and integrity (GCM authentication tag prevents ciphertext tampering).

This replaces the previous Fernet approach (which used AES-128-CBC + HMAC-SHA256).

#### Key derivation

```python
# core/credential_providers/encrypted_db.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

def derive_key(master_passphrase: bytes, salt: bytes) -> bytes:
    # Argon2id: memory-hard, GPU-resistant key derivation
    return hash_secret_raw(
        secret=master_passphrase,
        salt=salt,
        time_cost=3,          # 3 iterations
        memory_cost=65536,    # 64 MB memory
        parallelism=4,        # 4 parallel threads
        hash_len=32,          # 256-bit output key
        type=Type.ID,         # Argon2id (hybrid, recommended)
    )
```

Master passphrase comes from `CREDENTIAL_MASTER_KEY` env var (or Vault secret). Salt is stored alongside the ciphertext. The Argon2id parameters make brute-force attacks on the master key computationally prohibitive even with GPUs.

#### Encryption format stored in DB

```
<version:1 byte> | <salt:16 bytes> | <nonce:12 bytes> | <ciphertext+tag:N+16 bytes>
```

- Version byte enables algorithm migration without decrypting all values first
- Nonce is 96-bit random, unique per encryption operation (GCM requires unique nonces)
- GCM authentication tag (16 bytes) appended to ciphertext — any tampering with the ciphertext causes decryption to fail with `InvalidTag`

#### Key rotation

Same multi-key approach as Fernet but for AES-256-GCM:
- `CREDENTIAL_MASTER_KEYS=<new-key>,<old-key>` (comma-separated)
- Decryption tries keys in order; encryption always uses key[0]
- `tools/reencrypt_credentials.py` re-encrypts all DB values from old key to new key

---

### Memory Safety

Passwords retrieved from any provider are wrapped in a `SecureString` context manager that zeros the memory on exit:

```python
async with credential_provider.get(ref) as cred:
    conn = await netmiko_connect(ip, cred.username, cred.password)
    # ... use connection ...
# cred.password memory zeroed here via ctypes.memset
```

Python strings are immutable and the GC may keep copies, so `ctypes.memset` is applied to the underlying buffer of the `bytearray` holding the password before the object is released. This reduces the window in which a memory dump could expose a plaintext credential.

---

### Security Controls Summary

| Risk | Mitigation |
|---|---|
| Password in database | `credentials_ref` URI — DB holds a pointer, not the secret |
| Password in logs | Structured log redaction filter strips all `password`, `secret`, `key` fields |
| Password in API response | Never returned; `GET /devices/{id}` returns `credentials_ref` only |
| Password in memory after use | `SecureString` context manager zeros buffer |
| CyberArk/Vault unreachable | SSH poll fails for that device; system alert fired; no silent fallback |
| Compromised Vault token | Short TTL (1h) + auto-renewal; Vault revocation takes effect in ≤1h |
| Compromised CyberArk client cert | Cert revoked in CyberArk CA; next connection rejected |
| Brute-force on DB-encrypted creds | Argon2id key derivation — millions of times slower than bcrypt for an attacker |
| Ciphertext tampering | AES-256-GCM authentication tag — tampered ciphertext fails to decrypt |
| Credential harvesting via API | Rate limit + security event `credential_access_anomaly` on unusual patterns |

### Credential Provider UI (Settings → Credentials)

Admins configure and test credential providers in the Settings UI:

- **Provider list**: shows configured providers (CyberArk, Vault, DB fallback) with connection status
- **Test retrieval**: enter a `credentials_ref` URI → shows success/failure + resolved username (never password)
- **Bulk re-reference**: select devices → change their `credentials_ref` prefix from `db://` to `vault://kv/...` in bulk
- **Rotation status**: for CyberArk-managed accounts, shows last rotation time (from CyberArk API)
- Every action in this UI hits a REST endpoint — `POST /api/v1/credentials/test`, `PATCH /api/v1/inventory/devices/bulk-recredential`

---

### Reliability — Won't Crash

**PostgreSQL crash-safety settings** (`postgresql.conf` overrides in Docker):
```
# Write-ahead log — guarantees crash recovery without data loss
fsync                         = on        # Never turn off — data loss on crash otherwise
synchronous_commit            = on        # Every commit flushed to WAL before ACK
wal_level                     = replica   # Required for streaming replication
archive_mode                  = on        # WAL archiving for PITR
archive_command               = 'pgbackrest --stanza=netpilot archive-push %p'

# Checkpoint tuning — reduces I/O spikes that cause latency spikes
checkpoint_completion_target  = 0.9
checkpoint_timeout            = 15min
max_wal_size                  = 4GB       # Allow large WAL before forced checkpoint

# Connection safety — prevents connection exhaustion from taking down the DB
max_connections               = 100       # PgBouncer absorbs burst; keep this low
reserved_connections          = 3         # Reserved for superuser emergency access

# Statement safety — prevents runaway queries from hanging the DB
statement_timeout             = 30s       # Kill queries running longer than 30s
lock_timeout                  = 5s        # Fail fast rather than deadlock wait
idle_in_transaction_timeout   = 60s       # Kill sessions stuck mid-transaction
tcp_keepalives_idle           = 60        # Drop dead client connections
tcp_keepalives_interval       = 10
tcp_keepalives_count          = 5
```

**WAL archiving & Point-in-Time Recovery (PITR):**
- `pgBackRest` manages WAL archiving to offsite storage (S3/Azure Blob/GCS)
- Full backup weekly + incremental daily + continuous WAL streaming
- PITR allows restoring to any point in time within the retention window (30 days)
- Restore drill quarterly: restore to a scratch instance, verify row counts, run smoke tests

**Streaming replication (standby):**
```
Primary  →  streaming WAL  →  Standby (hot standby, read-only queries allowed)
```
- Standby configured with `hot_standby = on` — can serve read-only queries (reporting, dashboard history) without touching primary
- Failover via **Patroni** (distributed consensus with etcd or Consul): if primary becomes unresponsive for >30 seconds, Patroni promotes standby and updates the `pgbouncer` config automatically
- Failover is transparent to the application — PgBouncer reconnects to the new primary within seconds

**Database-level health monitoring:**
- `pg_stat_activity` polled every 30s by the watchdog script — alerts if long-running transactions, idle-in-transaction, or replication lag >30s
- Replication lag exposed as a Prometheus metric `netpilot_db_replication_lag_seconds`
- Docker health check: `pg_isready -U netpilot` — Docker restarts the container on failure

**Out-of-memory protection:**
- PostgreSQL `work_mem` set conservatively (64MB) to prevent per-query memory exhaustion
- `huge_pages = try` — uses transparent huge pages if available (reduces TLB pressure at 2000-device query rates)
- OS-level: PostgreSQL process excluded from OOM killer via `/proc/PID/oom_score_adj = -1000` (set in the container entrypoint)

---

### Performance — Fast Retrieval

**Index strategy** (beyond the TimescaleDB hypertable indexes):

| Table | Index | Pattern served |
|---|---|---|
| `devices` | `(group_id)` | Filter by group in inventory |
| `devices` | `GIN (custom_attributes jsonb_path_ops)` | Query any custom attribute value |
| `devices` | `GIN (tags)` | Tag-based filtering |
| `alerts` | `(device_id, status, fired_at DESC)` | Active alerts per device |
| `alerts` | `(severity, status)` | Global alert dashboard |
| `audit_log` | `(user_id, timestamp DESC)` | Per-user audit history |
| `audit_log` | `(resource_type, resource_id, timestamp DESC)` | Per-resource history |
| `config_backups` | `(device_id, backed_up_at DESC)` | Latest backup per device |
| `compliance_results` | `(device_id, rule_id, checked_at DESC)` | Latest compliance per device |
| `security_events` | `(event_type, timestamp DESC)` | SIEM queries by event type |

**Autovacuum tuning** (critical for TimescaleDB write-heavy hypertables):
```
autovacuum_vacuum_scale_factor    = 0.01   # Vacuum after 1% of rows change (not 20%)
autovacuum_analyze_scale_factor   = 0.005  # Analyze after 0.5%
autovacuum_vacuum_cost_delay      = 2ms    # Allow autovacuum to run faster on SSDs
autovacuum_max_workers            = 4      # Parallel autovacuum workers
```

**Query performance monitoring** — `pg_stat_statements` extension enabled:
- Tracks cumulative execution time, call count, and mean time for every query shape
- `GET /api/v1/admin/db/slow-queries` (Admin only) surfaces the top 20 slowest queries by mean time
- Prometheus metric `netpilot_db_slow_queries_total` alerts when a query exceeds 1s mean

**Buffer cache warm-up** — `pg_prewarm` extension loads the most-queried tables into `shared_buffers` on container start:
```sql
SELECT pg_prewarm('devices');
SELECT pg_prewarm('alerts');
SELECT pg_prewarm('metrics_hourly');  -- continuous aggregate
```
Prevents cold-start latency after a container restart.

**Read replica offload:**
- Reporting queries (`GET /api/v1/reports/*`), compliance history, and audit log searches are routed to the hot standby replica
- SQLAlchemy `read_replica` session factory configured in `core/database.py` — service layer picks the right session (write → primary, read-heavy → replica)
- This keeps heavy report queries from competing with the write path on the primary

**Full-text search for Global Search:**
- `tsvector` column on `devices` (hostname + tags + custom_attributes text values), maintained by a trigger
- `GIN (search_vector)` index on `devices` and `alerts`
- `GET /api/v1/search?q=` hits `to_tsquery()` — fast, PostgreSQL-native, no Elasticsearch needed

---

### Database Encryption

**Principle:** data must be unreadable to anyone who gains access to the disk, the Docker volume, the backup files, or the database process itself — without the encryption keys.

#### Layer 1 — Filesystem Encryption (data at rest)

The PostgreSQL data directory is stored on a **LUKS-encrypted volume** (Linux Unified Key Setup):

```
Host disk  →  LUKS encrypted volume (AES-256-XTS)  →  PostgreSQL data directory
                        ↑
              Key unlocked at container start from Vault/SSM
              If disk is stolen/imaged offline → unreadable
```

- LUKS key stored in HashiCorp Vault or AWS SSM — never on the same disk as the data
- Volume auto-unlocked at container start via a secrets-fetching entrypoint script
- If the container is killed and the volume is cold, the key must be re-fetched — prevents offline attacks on disk snapshots

In cloud environments (AWS, Azure, GCP) this is achieved via:
- AWS: EBS volume with KMS-managed encryption (`aws:kms` key)
- Azure: Azure Disk Encryption with Azure Key Vault
- GCP: CMEK (customer-managed encryption key) on Persistent Disk

#### Layer 2 — PostgreSQL Native TDE (pg_tde extension, PostgreSQL 17+)

When running PostgreSQL 17+, enable the `pg_tde` extension for tablespace-level encryption:
```sql
CREATE TABLESPACE netpilot_secure LOCATION '/data/pgdata'
  WITH (encryption_key_id = 'netpilot-master-key');
```
- Data files, WAL, and temp files encrypted at the PostgreSQL level
- Keys managed externally (Vault KMS provider plugin for `pg_tde`)
- Encryption transparent to all queries — no application changes needed

For PostgreSQL 16 (current default), filesystem encryption (Layer 1) provides equivalent protection.

#### Layer 3 — Column-Level Encryption (pgcrypto)

The most sensitive columns are additionally encrypted at the application level using `pgcrypto`, so even a user with direct PostgreSQL access and the correct DB password cannot read them in plaintext:

| Table | Column | Encrypted with |
|---|---|---|
| `devices` | `snmp_community_enc` | Fernet (app-layer, `core/crypto.py`) |
| `users` | `mfa_totp_secret_enc` | Fernet (app-layer) |
| `users` | `hashed_password` | bcrypt (one-way) |
| `api_keys` | `key_hash` | SHA-256 (one-way) |
| `oauth2_clients` | `client_secret_hash` | SHA-256 (one-way) |
| `refresh_tokens` | `token_hash` | SHA-256 (one-way) |

Fernet-encrypted columns: only decryptable by the FastAPI process holding the `ENCRYPTION_KEY` env var. A DBA with `SELECT` access sees ciphertext, not the value.

#### Layer 4 — Encryption in Transit (TLS for all connections)

```
FastAPI ──TLS──► PgBouncer ──TLS──► PostgreSQL
```

PostgreSQL `postgresql.conf`:
```
ssl                   = on
ssl_cert_file         = '/certs/server.crt'
ssl_key_file          = '/certs/server.key'
ssl_ca_file           = '/certs/ca.crt'
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers           = 'HIGH:!aNULL:!MD5'
```

PgBouncer `pgbouncer.ini`:
```
client_tls_sslmode    = require
server_tls_sslmode    = require
client_tls_cert_file  = /certs/pgbouncer.crt
client_tls_key_file   = /certs/pgbouncer.key
```

SQLAlchemy connection string enforces SSL:
```
postgresql+asyncpg://user:pass@pgbouncer/netpilot?ssl=require
```

Any connection attempt without TLS is rejected at both PgBouncer and PostgreSQL levels.

#### Layer 5 — Database Access Control (Least Privilege)

Three PostgreSQL roles — **never** a superuser for application traffic:

```sql
-- Role 1: app user — day-to-day API traffic
CREATE ROLE netpilot_app LOGIN PASSWORD '...';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO netpilot_app;
REVOKE DELETE ON security_events FROM netpilot_app;   -- append-only
REVOKE DELETE ON audit_log FROM netpilot_app;          -- append-only
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM netpilot_app;
REVOKE DROP ON ALL TABLES IN SCHEMA public FROM netpilot_app;

-- Role 2: read-only replica queries (reporting, dashboards)
CREATE ROLE netpilot_readonly LOGIN PASSWORD '...';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO netpilot_readonly;

-- Role 3: migration user — Alembic only, used during deployments
CREATE ROLE netpilot_migrate LOGIN PASSWORD '...';
GRANT ALL PRIVILEGES ON DATABASE netpilot TO netpilot_migrate;
-- Credentials rotated after every migration run
```

`pg_hba.conf` — connection restrictions:
```
# Only allow app connections from the internal Docker network
host  netpilot  netpilot_app      172.20.0.0/24  scram-sha-256
host  netpilot  netpilot_readonly 172.20.0.0/24  scram-sha-256
# Migration user only from localhost (inside the api container)
local netpilot  netpilot_migrate                 scram-sha-256
# No connections from anywhere else
host  all       all               0.0.0.0/0      reject
```

Password authentication uses **SCRAM-SHA-256** (not MD5 — MD5 is broken for this purpose).

#### Layer 6 — Database Audit Logging (pgaudit)

The `pgaudit` extension records all DDL, DML, and connection events at the PostgreSQL level — independently of the application audit log. This catches:
- Direct DB access via `psql` or a GUI client bypassing the application
- Schema changes outside of Alembic
- Unexpected `SELECT *` on sensitive tables

```sql
-- Log all DDL (CREATE, DROP, ALTER) and write operations (INSERT, UPDATE, DELETE)
pgaudit.log = 'ddl, write, role'
pgaudit.log_relation = on    -- log table name on each row operation
pgaudit.log_catalog  = off   -- reduce noise from system catalog queries
```

pgaudit logs are shipped to the same SIEM sink as application security events via the structured log pipeline.

#### Row-Level Security (RLS) — defense in depth

PostgreSQL Row-Level Security enforces device group access at the database level, making it impossible for a bug in the application RBAC to accidentally expose cross-group data:

```sql
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_group_access ON devices
  USING (
    group_id IN (
      SELECT group_id FROM user_group_access
      WHERE user_id = current_setting('app.current_user_id')::uuid
    )
  );
```

The FastAPI request middleware sets `SET LOCAL app.current_user_id = '...'` at the start of each DB transaction. Even if the application RBAC has a bug, the DB enforces the boundary.

#### Backup Encryption

Already covered in the Security section. Summary:
- `pg_dump` output encrypted with `gpg --symmetric --cipher-algo AES256` before upload
- WAL archive files encrypted by `pgBackRest` using AES-256 with a key stored in Vault/SSM
- Backup encryption key is separate from the database encryption key — compromise of one does not compromise both

---

## Polling Engine Architecture

### Design Goal

Polling 2000 devices with a single process puts polling CPU, I/O wait, and API serving on the same event loop. A brief CPU spike during a batch-write to TimescaleDB delays HTTP responses; a slow device's SSH session holds a thread that could service the next poll. The solution is to **completely separate polling from API serving** — polling runs in one or more dedicated `netpilot-poller` containers that have no REST surface and do nothing but talk to devices and write results.

This means:
- Adding more polling capacity = `docker compose scale poller=4` — no API restart, no code change
- API container CPU is flat regardless of fleet size — it serves reads from the DB, not from live device connections
- Each poller's event loop is quiet between polls — no HTTP routing, middleware, or WebSocket multiplexing competing for it

---

### Poller vs API Container Responsibilities

| Responsibility | API container | Poller container(s) |
|---|---|---|
| Serve REST endpoints | ✓ | — |
| Serve WebSocket telemetry | ✓ | — |
| JWT auth, RBAC, audit log | ✓ | — |
| SNMP polling | — | ✓ |
| SSH config backup | — | ✓ |
| gNMI subscriptions | — | ✓ |
| On-demand SSH/SNMP tests | ✓ (one-shot, user-triggered) | — |
| Alert rule evaluation | ✓ (reads from DB) | — |
| Compliance scans | ✓ (reads configs from git) | — |
| CVE scans | ✓ | — |
| Write metrics to TimescaleDB | — | ✓ (direct DB write) |
| Heartbeat to coordinator | — | ✓ |

Pollers write **directly to the database** (bypassing the API) to avoid adding network hops and API CPU to the hot write path. They use the same `netpilot_app` DB role and PgBouncer pool — the API's security model applies at the DB layer.

---

### Internal Engine Structure (per poller)

Each `netpilot-poller` container runs three independent engines concurrently. They share the same process but each has its own concurrency primitive — they do not compete for the same threads or event loop slots.

```
netpilot-poller process
  │
  ├── SNMPEngine (asyncio)
  │     asyncio.Semaphore(SNMP_CONCURRENCY=500)
  │     asyncio.gather() dispatches all device polls simultaneously within semaphore
  │     Results batched → bulk INSERT to TimescaleDB every SNMP_WRITE_BATCH_MS=500ms
  │
  ├── SSHEngine (ThreadPoolExecutor)
  │     max_workers = SSH_CONCURRENCY (default 25 per poller)
  │     Each thread: credential_provider.get() → Netmiko connect → commands → disconnect
  │     Results queued → bulk INSERT to TimescaleDB (SSH metrics written post-backup)
  │
  └── gNMIEngine (asyncio)
        Persistent gRPC bidi-streams — one coroutine per subscribed device
        Events arrive as asyncio callbacks → asyncio.Queue → batch writer coroutine
        Batch writer flushes every 1 second or when queue reaches 1000 events
```

**Key CPU properties:**
- SNMP: `asyncio.gather()` suspends on socket reads — zero CPU while waiting for device response. CPU spike = only during parsing NTC-Templates output (microseconds per device, run in `loop.run_in_executor()` to not block the event loop).
- SSH: threads block on network I/O (waiting for device CLI output) — the OS scheduler handles this. CPU usage = near zero between command send and response receive.
- gNMI: pure event-driven callback — CPU fires only when a telemetry event arrives from a device. Idle devices = zero CPU.

---

### Device Partitioning (Consistent Hashing)

Devices are distributed across pollers using **consistent hashing** on `device_id` (UUID). This produces a stable, deterministic assignment that minimises reassignments when pollers are added or removed.

```python
# poller/coordinator_client.py
import hashlib

def assign_device_to_poller(device_id: str, poller_ids: list[str]) -> str:
    # Sort poller IDs for determinism
    ring = sorted(poller_ids)
    h = int(hashlib.sha256(device_id.encode()).hexdigest(), 16)
    return ring[h % len(ring)]
```

**Properties of consistent hashing:**
- Adding 1 poller to a 3-poller fleet: only ~25% of devices reassign (not all)
- Removing 1 poller: only the dead poller's devices reassign
- Same device always goes to the same poller (absent poller changes) — no duplicate SNMP polls from two pollers simultaneously

---

### Coordinator (API-side)

The `modules/poller_coord/` module in the API container manages the poller fleet:

**Registration:** on startup, each poller calls `POST /internal/poller/register`:
```json
{ "poller_id": "poller-abc123", "hostname": "poller-1", "version": "1.4.2",
  "capabilities": ["snmp", "ssh", "gnmi"] }
```
The coordinator stores this in `poller_nodes` and returns the poller's initial device partition.

**Heartbeat:** every 30 seconds, each poller calls `POST /internal/poller/heartbeat`:
```json
{ "poller_id": "poller-abc123", "metrics": {
    "devices_assigned": 667, "snmp_polls_last_60s": 660,
    "ssh_sessions_active": 4, "gnmi_subscriptions": 200,
    "cpu_percent": 8.2, "memory_mb": 312 } }
```

**Health threshold:** if a poller misses 3 consecutive heartbeats (90 seconds), the coordinator marks it `dead` and reassigns its devices to the remaining healthy pollers.

**Partition update:** when the fleet composition changes (poller joins, leaves, or dies), the coordinator recalculates assignments and sends updated device lists to each poller via `GET /internal/poller/assignments?poller_id=...` (pollers long-poll this endpoint or receive a push via WebSocket).

**`/internal/` endpoints** are on a separate internal router — blocked by nginx for all external traffic. Only containers on `netpilot-internal` Docker network can reach them.

---

### Per-Engine Configuration

All limits are env-var tunable on each poller container — different pollers can have different profiles (e.g., a dedicated SSH-only poller for config backups):

```bash
# SNMP engine
SNMP_CONCURRENCY=500         # max simultaneous async SNMP requests
SNMP_TIMEOUT_S=5             # per-device SNMP timeout
SNMP_RETRIES=2               # SNMP retries before marking device unreachable
SNMP_WRITE_BATCH_SIZE=500    # rows per TimescaleDB bulk INSERT
SNMP_WRITE_BATCH_MS=500      # max ms to buffer before forced flush
SNMP_POLL_INTERVAL_S=60      # base poll interval; adaptive per device (see below)

# SSH engine
SSH_CONCURRENCY=25           # max simultaneous SSH sessions per poller
SSH_CONNECT_TIMEOUT_S=30
SSH_AUTH_TIMEOUT_S=15
SSH_COMMAND_TIMEOUT_S=120
SSH_BANNER_TIMEOUT_S=15
SSH_KEEPALIVE_INTERVAL_S=30  # TCP keepalive to prevent firewall state drops

# gNMI engine
GNMI_MAX_SUBSCRIPTIONS=700   # max persistent gRPC streams per poller
GNMI_RECONNECT_BASE_S=1      # exponential backoff base
GNMI_RECONNECT_MAX_S=60      # exponential backoff cap
GNMI_QUEUE_MAX_EVENTS=1000   # batch writer queue depth before backpressure
GNMI_FLUSH_INTERVAL_S=1      # max seconds between batch writes

# Poller identity
POLLER_ID=poller-1           # unique per container; use Docker hostname if unset
POLLER_API_URL=http://api:8000  # coordinator URL (internal Docker network)
POLLER_CAPABILITIES=snmp,ssh,gnmi  # can restrict a poller to specific protocols
```

---

### Adaptive Poll Interval

To keep CPU and network load smooth, the SNMP engine tracks response latency per device and adapts the poll interval:

```python
# poller/engines/snmp.py
def compute_next_interval(device_id, last_latency_ms, miss_count):
    base = SNMP_POLL_INTERVAL_S  # default 60s
    if miss_count >= 3:
        return min(base * 4, 240)   # back off to 4× for repeatedly unreachable devices
    if last_latency_ms > 4000:
        return min(base * 2, 120)   # back off slightly for slow devices
    return base
```

Slow or unreachable devices don't consume semaphore slots on every 60-second cycle — they naturally back off, freeing concurrency for healthy devices.

---

### Batch Writes (TimescaleDB)

Rather than one `INSERT` per metric value, each engine accumulates results and writes in bulk:

```python
# poller/db_writer.py
class BatchWriter:
    async def flush(self, rows: list[MetricRow]):
        # Single executemany — one round-trip for up to 500 rows
        await db.execute(
            "INSERT INTO metrics (device_id, metric_name, value, timestamp) "
            "VALUES (:device_id, :metric_name, :value, :timestamp) "
            "ON CONFLICT DO NOTHING",
            rows
        )
```

At 2000 devices × 20 metrics = 40,000 metrics per 60-second cycle. With batch size 500, this is 80 DB round-trips per cycle — one every 750ms on average. PgBouncer absorbs the burst; TimescaleDB writes are append-only (no lock contention).

---

### Poller Health Dashboard (Admin UI)

A sub-section of the Admin → Settings page shows the live state of the poller fleet:

| Column | Description |
|---|---|
| Poller ID | Container hostname |
| Status | Healthy / Degraded / Dead (color-coded) |
| Devices assigned | Count from coordinator partition |
| Polls/min | SNMP poll throughput |
| SSH active | Current open SSH sessions |
| gNMI streams | Active subscriptions |
| CPU % | From heartbeat metrics |
| Memory MB | From heartbeat metrics |
| Last heartbeat | Relative time |

**Actions:**
- "Drain poller" — stop sending new assignments to this poller; existing polls complete; useful for graceful scale-down
- "Force rebalance" — redistribute all devices immediately (Admin action, logged)

---

### Directory Structure (poller service)

```
netpilot/
  poller/                   # separate Python package, built into netpilot-poller image
    main.py                 # entry point: register → start engines → heartbeat loop
    coordinator_client.py   # API registration, heartbeat, partition polling
    partition.py            # consistent hashing, device assignment logic
    db_writer.py            # BatchWriter for TimescaleDB bulk inserts
    engines/
      snmp.py               # SNMPEngine — asyncio, pysnmp, semaphore, adaptive interval
      ssh.py                # SSHEngine — ThreadPoolExecutor, Netmiko, backup scheduler
      gnmi.py               # gNMIEngine — async gRPC, persistent subscriptions, queue
      sse.py                # SSEEngine — httpx RESTCONF SSE listener
    health.py               # /health/live and /metrics (Prometheus) — tiny FastAPI app
```

The poller image is built from the same `Dockerfile` as the API image with a different `CMD`:
```dockerfile
# Dockerfile — shared base image
FROM python:3.12-slim
# ... install dependencies including drivers/ ...

# API container:
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Poller container (same image, different CMD):
CMD ["python", "-m", "poller.main"]
```

This means one Docker build produces both the API image and the poller image — no dependency drift between them. The poller has access to `drivers/`, `core/crypto.py`, `core/config.py`, and `credential_providers/` from the shared backend package.

---

### Data Model Addition

```
poller_nodes   id (poller_id, text PK), hostname, version, capabilities (JSON),
               status (healthy/degraded/dead), devices_assigned (int),
               last_heartbeat_at, registered_at, metrics_snapshot (JSON — last heartbeat payload)

device_poller_assignments   device_id (FK), poller_id (FK), assigned_at, is_active (bool)
               — tracks current and historical partition assignments
```

---

### Scaling Examples

| Fleet size | Devices per poller | Recommended for |
|---|---|---|
| 1 poller | 2000 | Small environments, single-host Docker Compose |
| 2 pollers | 1000 each | Standard production (redundancy) |
| 4 pollers | 500 each | Large fleets, separate SSH-backup poller |
| 1 SNMP + 1 SSH + 1 gNMI | Protocol-dedicated | High-frequency gNMI telemetry isolation |

A protocol-dedicated deployment is configured by setting `POLLER_CAPABILITIES=snmp` on one poller, `POLLER_CAPABILITIES=ssh` on another, and `POLLER_CAPABILITIES=gnmi` on a third. The coordinator assigns each device to the appropriate poller based on the device's enabled protocols and each poller's declared capabilities.

---

## Scalability for 2000 Devices

### Write volume at steady state

| Source | Rate at 2000 devices |
|---|---|
| SNMP metrics (20 metrics/device, 60s poll) | ~667 rows/sec |
| gNMI telemetry (10 paths/device, 1Hz) | ~20,000 rows/sec (peak) |
| Config backups (nightly, staggered) | ~3–4 writes/sec sustained overnight |
| Alert evaluations (30s interval) | negligible |

TimescaleDB is designed for 100k+ rows/sec on modest hardware; the above volumes are well within its envelope on a 4-core / 16 GB VM.

### Poll concurrency controls

All concurrency limits are env-var tunable per poller container — no code change to adjust for fleet size. With N pollers, each handles ~2000/N devices; total throughput scales linearly.

| Setting | Default (per poller) | Purpose |
|---|---|---|
| `SNMP_CONCURRENCY` | 500 | Max simultaneous async SNMP requests per poller (asyncio semaphore) |
| `SSH_CONCURRENCY` | 25 | Max simultaneous SSH sessions per poller (ThreadPoolExecutor size) |
| `GNMI_MAX_SUBSCRIPTIONS` | 700 | Max persistent gNMI streams per poller |
| `SNMP_WRITE_BATCH_SIZE` | 500 | Rows per TimescaleDB bulk INSERT |
| `SNMP_WRITE_BATCH_MS` | 500 | Max milliseconds to buffer before forced flush |
| `SNMP_POLL_INTERVAL_S` | 60 | Base SNMP poll interval; adaptive per device |

With 2 pollers at SSH_CONCURRENCY=25 each, the fleet maintains 50 concurrent SSH sessions max — protecting device control planes from connection storms. SSH is the most resource-intensive path; each poller's thread pool is deliberately small and focused on its partition.

### Database tuning for 2000 devices

**TimescaleDB hypertable settings:**
- `metrics` hypertable: `chunk_time_interval = '1 day'`; retention policy 90 days (auto-drop old chunks)
- `telemetry_stream` hypertable: `chunk_time_interval = '1 hour'`; retention policy 7 days
- Continuous aggregates on `metrics`: pre-compute hourly and daily rollups so dashboard queries hit the aggregate, not 90 days of raw rows
- Compression enabled on chunks older than 7 days (TimescaleDB native compression, ~90% size reduction)

**Indexes:**
- `(device_id, timestamp DESC)` on both hypertables — primary query pattern
- `(metric_name, timestamp DESC)` on `metrics` — for cross-device metric queries
- `(device_id, status)` on `alerts` — active alert lookups

**Connection pooling (PgBouncer):**
- FastAPI opens up to 20 async SQLAlchemy connections per worker
- PgBouncer sits between FastAPI and PostgreSQL in transaction-mode pooling
- PostgreSQL `max_connections = 100`; PgBouncer absorbs burst connection demand from the async worker pool
- PgBouncer configured as a separate container; its DSN is the only DB URL FastAPI sees — swap or scale transparently

**PostgreSQL configuration (postgresql.conf overrides in Docker):**
```
max_connections        = 100
shared_buffers         = 4GB          # 25% of RAM on 16GB host
effective_cache_size   = 12GB
work_mem               = 64MB
maintenance_work_mem   = 1GB
wal_buffers            = 64MB
checkpoint_completion_target = 0.9
random_page_cost       = 1.1          # SSD storage assumed
```

### Dashboard query performance

Raw 90-day metric queries for 2000 devices would be slow. Pattern to avoid this:
- Dashboard "last value" widgets: served from in-process cache (updated each poll), never query DB
- Sparkline charts (last 1h): query TimescaleDB continuous aggregate hourly rollup, not raw table
- Historical deep-dives: raw hypertable query, but scoped to one device + time range — always fast with the `(device_id, timestamp)` index
- Inventory and alert list views: standard PostgreSQL, indexed, paginated (never `SELECT *`)

---

## Upgradability

### Philosophy

Every upgrade — patch, minor, or major — must be executable without manual intervention, with a tested rollback path, and without requiring downtime for read-only operations.

### Semantic versioning and API compatibility

- API versioned by URL prefix: `/api/v1/`, `/api/v2/` — a new major version coexists with the old one; consumers migrate on their schedule
- Breaking changes are never made within a version; deprecations are announced in the response headers (`Deprecation: true`, `Sunset: <date>`) before removal
- Frontend and backend versioned together in `pyproject.toml`; version exposed at `GET /api/v1/version` for health monitoring

### Database migrations (Alembic)

- Every schema change — column add, index add, type change, table rename — is an Alembic migration file, never manual SQL
- Migrations are additive where possible: new columns are nullable with a default; backfills run as a separate migration after deployment
- Large-table operations (`CREATE INDEX`, `ADD COLUMN` on `metrics`) use `CONCURRENTLY` / `NOT VALID` patterns to avoid table locks
- Migration script runs automatically on container startup (with a lock to prevent parallel runs); if it fails, the container exits and the previous version stays live
- Rollback: `alembic downgrade -1` restores the previous schema state; always tested before shipping a migration

### Zero-downtime deployment

```
1. Pull new image:          docker compose pull api
2. Run migrations:          docker compose run --rm api alembic upgrade head
3. Replace container:       docker compose up -d --no-deps api
   (old container finishes in-flight requests before exit — SIGTERM → 30s drain)
4. Health check passes:     GET /health/ready returns 200
5. Done — no service gap for read operations
```

FastAPI handles `SIGTERM` with a 30-second graceful drain: new requests are refused, in-flight requests complete, APScheduler jobs finish their current run. SSH sessions in progress are allowed to complete (not killed mid-command, which could leave a device in a partial config state).

### Graceful shutdown details

- APScheduler: `scheduler.shutdown(wait=True)` — waits for running jobs to complete (max 60s, then force-stop)
- Active SSH config pushes: tracked in a `shutdown_barrier`; new pushes are rejected during drain, active ones complete
- gNMI subscriptions: closed cleanly via gRPC `channel.close()`; devices detect the disconnect and buffer telemetry
- WebSocket connections: server sends `1001 Going Away` close frame; Vue client auto-reconnects to the new container

### Rollback procedure

```
# Rollback to previous version
docker compose stop api
docker compose run --rm api alembic downgrade -1   # if migration was part of this version
docker compose up -d --no-deps api                  # previous image tag still in compose.override.yml
```

Pin the previous image tag in `compose.override.yml` before upgrading — standard practice documented in `UPGRADING.md`.

### Feature flags

New features that touch shared state (schema changes, new polling jobs) are gated by env-var feature flags (`FEATURE_GNMI_TELEMETRY=true`, `FEATURE_CONFIG_PUSH=true`). This allows:
- Deploying code before enabling a feature (dark launch)
- Disabling a feature instantly if it causes issues — no redeploy needed
- Rolling out to a subset of deployments first

### Dependency upgrades

- Renovate bot opens weekly PRs for Python and Node dependency bumps
- Patch bumps with passing CI tests are auto-merged
- Minor/major bumps require manual review and a changelog entry
- `pip-audit` and `npm audit` in CI catch CVEs between Renovate runs — a CVE blocks merge immediately

### Upgrade runbook location

`docs/UPGRADING.md` ships with the repo and contains:
- Version-specific migration notes (e.g., "v1.3 → v1.4 requires running the backfill job manually")
- Rollback steps for each release
- Known breaking changes per major version

---

## User Experience

### Standard Device Onboarding Attributes

These attributes ship as **pre-configured attribute definitions** in every NetPilot installation — created by the database seed/init migration and immediately available in the device onboarding form without any Admin setup.

They are standard (non-deletable), but can be marked optional or have their display labels changed. They live in `custom_attributes` JSONB alongside any custom fields the team adds.

| Attribute key | Label | Type | Required | Description |
|---|---|---|---|---|
| `node_hostname` | Node Hostname | `text` | Yes | Canonical FQDN / short hostname as it appears on the device (`show version`) |
| `device_type` | Device Type | `select` | Yes | Options: Router, Switch, Firewall, Load Balancer, WLC, AP, OOB Console Server, Packet Broker, DDI Server, Other |
| `os_category` | OS / Platform | `select` | Yes | Options: Cisco IOS, IOS-XE, IOS-XR, NX-OS, ASA, Arista EOS, Juniper JunOS, GigaVUE OS, Opengear Linux, BlueCat BDDS, Other |
| `asset_tag` | Asset Tag | `text` | Yes | Hardware asset tag / serial number for CMDB correlation |
| `center_name` | Data Center / Site | `text` | Yes | Data center name, campus, or site code (e.g., "DC-EAST", "HQ-NYC") |
| `city` | City | `text` | No | Physical city where device is located |
| `department` | Department | `text` | No | Owning business unit or team (e.g., "Network Engineering", "Cloud Ops") |
| `functional_category` | Functional Category | `select` | No | Options: Core, Distribution, Access, Edge, DMZ, Management, OOB, WAN, Other |
| `compliance_category` | Compliance Category | `multi_select` | No | Options: PCI-DSS, HIPAA, SOX, NIST-CSF, CIS-L1, CIS-L2, Internal — drives compliance rule scoping |
| `credential_rotation` | Credential Rotation Policy | `select` | No | Options: 30-day, 60-day, 90-day, Manual, PAM-managed — informational; CyberArk/Vault rotation tracked separately |
| `purchase_date` | Purchase Date | `date` | No | Hardware purchase date — used for warranty tracking |
| `service_date` | In-Service Date | `date` | No | Date device was placed into production |
| `comments` | Comments | `textarea` | No | Free-form notes, change history notes, known issues |

**These fields appear in:**
- The device onboarding form (DynamicForm.vue) — in the order listed above, below the core connectivity fields (IP, vendor, SNMP, SSH)
- The inventory table — `node_hostname`, `device_type`, `os_category`, `asset_tag`, `center_name`, `functional_category` are shown as table columns by default (`show_in_table=true`)
- Compliance rule `applies_to_*` filters — `device_type`, `os_category`, `compliance_category`, `department` are all filterable
- Compliance report filters — all fields are available as filter dimensions for report generation

**Seed migration:**
`alembic/versions/0002_seed_standard_attributes.py` inserts these definitions into `device_attribute_definitions` at schema init. Running the migration on an existing instance adds only definitions that don't already exist (idempotent via `INSERT ... ON CONFLICT DO NOTHING`).

---

### Dynamic Device Attribute Schema

Device forms are **schema-driven** — the fields rendered in the UI are read from the attribute definition API, not hardcoded. Admins can add, remove, rename, and reorder fields via GUI. If a user discovers a missing field *while adding a device*, they can define it inline without leaving the form.

#### How it works

```
GET /api/v1/inventory/attribute-definitions
→ returns ordered list of field definitions
→ Vue DynamicForm.vue renders them as the device form
```

Every device add/edit form has two zones:

1. **Standard fields** (always present, not deletable): hostname, IP address, vendor, OS type, device type, SNMP version/community, SSH credential reference, device group, tags
2. **Custom fields** (schema-driven, admin-managed): rendered below standard fields in configured order

#### Field types supported

| Type | Renders as | Example use |
|---|---|---|
| `text` | Single-line input | Location, rack ID, asset tag |
| `textarea` | Multi-line | Notes, change history notes |
| `number` | Numeric input | Rack unit, floor number, bandwidth Mbps |
| `select` | Dropdown | Environment (prod/staging/dev), role (core/edge/access) |
| `multi_select` | Tag picker | Services (BGP, OSPF, MPLS) |
| `boolean` | Toggle | "In maintenance contract", "Supports gNMI", "IPv6 enabled" |
| `date` | Date picker | Warranty expiry, install date, end-of-life date |
| `url` | URL input + link icon | Vendor support page, internal wiki |
| `ip_address` | IP input with validation | Out-of-band management IP |
| `user_ref` | User picker (dropdown from users table) | Owner, primary contact, on-call engineer |

#### Adding a missing field inline

While filling a device form, a user sees a field they need doesn't exist (e.g., "Rack Position"). They click **"+ Add field"** at the bottom of the form:

1. A popover opens — fill in: field name, type, required (yes/no), default value, display order
2. Click "Create field" → `POST /api/v1/inventory/attribute-definitions` → field is saved
3. The new field **immediately appears** in the current form, prefilled with the default
4. The form is not reset — all already-entered values are preserved

This flow requires no page navigation, no Admin portal visit, and no manual re-render — the form reactively updates from the Pinia store which is updated by the API response.

#### Attribute definition management (Settings → Device Attributes)

A dedicated settings page shows all attribute definitions in a drag-to-reorder list:
- Add, edit, delete field definitions
- Mark a field required / optional
- Set a default value
- Define select options for `select` and `multi_select` types
- Set field visibility: shown on device list table (column) vs form-only
- Archive (soft-delete) a field — existing device data preserved, field hidden from new forms

Every operation on this page is a REST call:

| Action | REST call |
|---|---|
| Load definitions | `GET /api/v1/inventory/attribute-definitions` |
| Create definition | `POST /api/v1/inventory/attribute-definitions` |
| Update definition | `PATCH /api/v1/inventory/attribute-definitions/{id}` |
| Reorder | `PUT /api/v1/inventory/attribute-definitions/order` |
| Archive | `DELETE /api/v1/inventory/attribute-definitions/{id}` |

#### Test connection before saving

The device form has a **"Test Connection"** button that runs a live connectivity check without saving the device:

```
POST /api/v1/inventory/devices/test-connection
Body: { ip, snmp_version, snmp_community, ssh_credential_ref, device_type }
Response: { snmp: "ok"|"failed"|"timeout", ssh: "ok"|"failed"|"auth_error",
            sysName: "router-01", sysDescr: "Cisco IOS XE..." }
```

Results appear inline in the form (green checkmark / red X per protocol) before the user clicks Save. This catches misconfigured credentials at onboarding time, not hours later when the first poll fails silently.

#### NCM Properties Tab — Connection Profile Testing

Every device detail page has a set of sub-tabs. The **NCM Properties** tab and the **SNMP Test** tab allow engineers to validate and troubleshoot connectivity without leaving the browser — no separate SSH client or SNMP tool needed.

**Device detail page tab structure:**

```
/inventory/devices/{id}
  ├── Overview        — current metrics snapshot, alert count, last backup
  ├── Monitor         — metric charts, live telemetry
  ├── Config          — backup history, diff viewer, push, compliance results
  ├── Compliance      — per-rule pass/fail for this device, violation history
  ├── NCM Properties  ← connection profile + SSH / REST / gNMI test
  └── SNMP Test       ← SNMP credential test + OID walk preview
```

##### NCM Properties Tab

Shows the device's current connection profile and provides live test buttons for each supported protocol:

**Connection profile panel:**

| Field | Value shown | Editable? |
|---|---|---|
| Management IP | Current value | Yes (PATCH device) |
| SSH port | Default 22, per-device override | Yes |
| Device type (Netmiko) | e.g., `cisco_ios`, `arista_eos`, `gigamon_gigavue`, `opengear`, `linux` | Yes |
| Credential reference | `vault://...` / `cyberark://...` / `db://encrypted` (URI only, no password) | Yes |
| REST API URL | For Arista eAPI / NX-API | Yes |
| gNMI port | Default 57400 | Yes |
| SSH keepalive | Seconds (default 30) | Yes |
| Connection timeout | Seconds (default 30) | Yes |

**Test SSH Connection:**
```
Button: "Test SSH"
→ POST /api/v1/inventory/devices/{id}/test-ssh
  Response:
    status: "success" | "auth_failed" | "timeout" | "unreachable" | "weak_kex_rejected"
    connected_as: "netpilot"
    negotiated_kex: "mlkem768x25519-sha256"
    negotiated_cipher: "chacha20-poly1305@openssh.com"
    host_key_fingerprint: "SHA256:abcd..."
    device_prompt: "core-rtr-01#"
    show_version_snippet: "Cisco IOS XE Software, Version 17.9.3..."
    latency_ms: 142
    error: null | "Auth failed — check credential_ref" | "Weak KEX rejected"
```

**Test REST Connection** (Arista eAPI / NX-API only):
```
Button: "Test REST/API"
→ POST /api/v1/inventory/devices/{id}/test-rest
  Response:
    status: "success" | "auth_failed" | "timeout" | "unreachable"
    api_version: "1.9" (Arista eAPI) | "1.0" (NX-API)
    platform: "cEOSLab" | "Nexus 9000v"
    latency_ms: 88
```

**Test gNMI Connection** (Cisco IOS-XR / Arista EOS / NX-OS 10.x+):
```
Button: "Test gNMI"
→ POST /api/v1/inventory/devices/{id}/test-gnmi
  Response:
    status: "success" | "auth_failed" | "tls_error" | "capability_unsupported"
    gnmi_version: "0.7.0"
    supported_encodings: ["JSON_IETF", "PROTO"]
    supported_models: ["Cisco-IOS-XR-*", "openconfig-interfaces"]
    latency_ms: 63
```

All test responses are shown inline as a result card below the button with color-coded status. The test does NOT require the device to already be in managed inventory — it can be used on the new device form before saving.

**Connection test history:**
- Last 10 test results per device stored in `connection_test_history` table
- Shown as a timeline: timestamp, protocol, status, latency, who triggered it
- Useful for diagnosing intermittent connectivity issues

**REST API for NCM tests:**

| Action | Endpoint |
|---|---|
| Test SSH | `POST /api/v1/inventory/devices/{id}/test-ssh` |
| Test REST/API | `POST /api/v1/inventory/devices/{id}/test-rest` |
| Test gNMI | `POST /api/v1/inventory/devices/{id}/test-gnmi` |
| Get test history | `GET /api/v1/inventory/devices/{id}/connection-tests` |
| Test (unsaved device) | `POST /api/v1/inventory/devices/test-connection` (full body with all fields) |

##### SNMP Test Tab

Tests SNMP connectivity and credentials without triggering a full poll. Shows diagnostic output useful for validating SNMP configuration during onboarding.

**SNMP credential panel:**
- Shows SNMP version (v2c / v3) and community string indicator (masked — shows only first 2 chars + ***)
- For v3: shows auth protocol (SHA-256 / SHA-512), privacy protocol (AES-256), auth/priv level

**Test SNMP:**
```
Button: "Test SNMP"
→ POST /api/v1/inventory/devices/{id}/test-snmp
  Response (v2c or v3 success):
    status: "success" | "timeout" | "auth_error" | "community_mismatch"
    snmp_version_confirmed: "v3"
    sys_descr: "Cisco IOS XE Software, Version 17.9.3a..."
    sys_name: "core-rtr-01.corp.com"
    sys_oid: "1.3.6.1.4.1.9.1.3146"
    sys_uptime: "47 days, 3:22:11"
    if_number: 48
    latency_ms: 34
```

**OID Walk Preview:**
A collapsible section shows the top-level OID tree from the device (`1.3.6.1.2.1` — MIB-2):
- Interfaces table: `ifDescr`, `ifOperStatus`, `ifAdminStatus` for all interfaces
- System info: `sysDescr`, `sysName`, `sysOID`, `sysUpTime`
- Rendered as a collapsible tree (not a raw OID dump) — vendor-resolved to friendly names via NTC-Templates OID map

**SNMP v3 troubleshooter:**
If SNMP v3 test fails, the error is specific:
- `auth_protocol_mismatch` — device uses SHA-1 but NetPilot configured SHA-256
- `priv_protocol_mismatch` — device uses DES but NetPilot configured AES
- `engine_id_mismatch` — v3 engine ID not discovered yet (retry with discovery)
- `timeout` — SNMP port unreachable (check ACL or firewall)

These specific errors replace the generic "SNMP unreachable" that makes v3 troubleshooting difficult.

---

#### Bulk onboarding via API (Infrastructure-as-Code)

The same attribute schema is enforced on the API, so Ansible/Terraform/scripts can onboard devices programmatically using the same field definitions:

```bash
# Ansible example — same endpoint the UI calls
- uri:
    url: https://netpilot/api/v1/inventory/devices
    method: POST
    headers:
      Authorization: "Bearer np_live_..."
    body_format: json
    body:
      hostname: "core-rtr-01"
      ip: "10.1.1.1"
      vendor: "cisco"
      device_type: "cisco_ios"
      custom_attributes:
        environment: "prod"
        rack_id: "R12-U4"
        owner_user_id: "uuid-of-alice"
```

Custom attributes submitted via API are validated against the schema (required fields enforced, type-checked, select options validated) — the same Pydantic model used by the UI form.

---

### API-First UI Design

**Every single UI action is a documented REST API call.** The Vue frontend has no privileged operations — it is a pure consumer of the same API available to automation tools, scripts, and third-party integrations. If it can be done in the UI, it can be done via API with the same authorization rules.

#### Principle

```
Browser click → Vue handler → axios → REST endpoint → same response the UI renders
                                  ↕
                         Ansible / Terraform / curl → same endpoint → same response
```

No special UI-only endpoints. No server-side session rendering. No "magic" form actions that bypass the API layer.

#### Complete UI → API mapping

| UI action | REST call |
|---|---|
| Add device | `POST /api/v1/inventory/devices` |
| Edit device | `PATCH /api/v1/inventory/devices/{id}` |
| Delete device | `DELETE /api/v1/inventory/devices/{id}` |
| Bulk tag devices | `POST /api/v1/inventory/devices/bulk-tag` |
| Test device connection | `POST /api/v1/inventory/devices/test-connection` |
| Import devices (CSV) | `POST /api/v1/inventory/devices/import` |
| Run SNMP poll now | `POST /api/v1/monitor/devices/{id}/poll` |
| View device metrics | `GET /api/v1/monitor/devices/{id}/metrics?from=&to=` |
| Subscribe to live telemetry | `WS /ws/telemetry?device_id={id}` |
| Run config backup now | `POST /api/v1/config/devices/{id}/backup` |
| View config history | `GET /api/v1/config/devices/{id}/backups` |
| View config diff | `GET /api/v1/config/devices/{id}/diff?from={sha}&to={sha}` |
| Push config (create change request) | `POST /api/v1/config/devices/{id}/change-requests` |
| Approve change request | `POST /api/v1/config/change-requests/{id}/approve` |
| Run compliance scan | `POST /api/v1/config/devices/{id}/compliance-scan` |
| Acknowledge alert | `POST /api/v1/alerts/{id}/acknowledge` |
| Snooze alert | `POST /api/v1/alerts/{id}/snooze` |
| Create maintenance window | `POST /api/v1/alerts/maintenance-windows` |
| Create alert rule | `POST /api/v1/alerts/rules` |
| Add attribute definition | `POST /api/v1/inventory/attribute-definitions` |
| Create user | `POST /api/v1/auth/users` |
| Assign role | `PATCH /api/v1/auth/users/{id}/role` |
| Create API key | `POST /api/v1/auth/api-keys` |
| Revoke API key | `DELETE /api/v1/auth/api-keys/{id}` |
| Run discovery scan | `POST /api/v1/discovery/jobs` |
| Generate report | `POST /api/v1/reports/generate` |
| List compliance rules | `GET /api/v1/compliance/rules` |
| Create compliance rule | `POST /api/v1/compliance/rules` |
| Test compliance pattern | `POST /api/v1/compliance/rules/test` |
| Run device compliance scan | `POST /api/v1/compliance/devices/{id}/scan` |
| Test SSH connection | `POST /api/v1/inventory/devices/{id}/test-ssh` |
| Test REST connection | `POST /api/v1/inventory/devices/{id}/test-rest` |
| Test gNMI connection | `POST /api/v1/inventory/devices/{id}/test-gnmi` |
| Test SNMP | `POST /api/v1/inventory/devices/{id}/test-snmp` |
| List CVE scan results | `GET /api/v1/cve` |
| Waive CVE | `POST /api/v1/cve/waivers` |
| Remediate CVE | `POST /api/v1/cve/{id}/remediate` |

#### Developer mode

A toggle in Settings → Developer Tools enables:
- **"Copy as curl"** tooltip on every button: hover shows the exact `curl` command that button would execute
- **Request log panel**: collapsible drawer at the bottom of the screen showing every API call made in the current session (method, URL, status, duration, request/response body)
- **API Explorer**: link to the OpenAPI `/docs` page (available to Admin role only in all environments)

This makes NetPilot self-documenting for engineers who want to automate workflows they built in the UI first.

#### OpenAPI documentation

FastAPI auto-generates the OpenAPI schema. Every endpoint includes:
- Required OAuth2 scopes / RBAC role
- Request body schema with field descriptions
- Response schema with example values
- Error response codes with descriptions

The `/api/v1/docs` Swagger UI is accessible only to users with Admin role (auth-gated via a FastAPI dependency). The raw `/api/v1/openapi.json` is accessible to all authenticated users for client generation.

---

### First-Run Onboarding Wizard

On first boot (zero devices, zero users except the bootstrap Admin), the UI shows a 4-step wizard that cannot be skipped:

1. **Admin account** — set email + password + enroll TOTP (mandatory for local Admin)
2. **Identity provider** — configure OIDC/SAML/LDAP or skip to use local auth only
3. **Add first device** — hostname, IP, SNMP credentials, test connection (live feedback)
4. **Verify connectivity** — shows SNMP poll result and SSH test; green = done

Wizard state is tracked in a `setup_complete` flag in the DB. Once set, the wizard never reappears. Each step is independently resumable — closing the browser mid-wizard resumes at the last incomplete step.

### Empty States

Every table and list view has a meaningful empty state with a clear call to action — never a blank white box:

| View | Empty state message | CTA |
|---|---|---|
| Inventory | "No devices yet" | "Add your first device" / "Import CSV" / "Run discovery" |
| Alerts | "No active alerts — all clear" | — |
| Compliance rules | "No rules defined yet" | "Create your first rule" |
| Config backups | "No backups yet for this device" | "Run backup now" |
| Maintenance windows | "No maintenance windows scheduled" | "Schedule one" |
| API keys | "No API keys for this account" | "Create API key" |

### Alert Fatigue Prevention

**Maintenance windows**
- Create a window with: name, target (one device / device group / all), start time, end time, reason
- During a window, alerts still fire and are stored but no external notifications are sent
- Active windows are shown as a banner on the Alerts view and a yellow indicator on affected device cards
- Windows can be created as one-time or recurring (e.g., "every Sunday 02:00–04:00")

**Alert snooze**
- Any alert can be snoozed for: 15 min, 1h, 4h, until resolved, or a custom time
- Snoozed alerts stay visible in the UI with a clock icon; notifications suppressed during snooze
- Snooze is per-user (my snooze doesn't affect your notifications)

**Alert grouping / incidents**
- When ≥3 alerts of the same severity fire within 2 minutes across ≥3 devices, they are automatically grouped into an `Incident`
- The Incident card shows: root cause hypothesis (common upstream device?), affected device count, timeline
- Acknowledging an incident bulk-acks all constituent alerts
- Incident grouping logic is tunable via `INCIDENT_MIN_ALERTS` and `INCIDENT_WINDOW_SECONDS` env vars

### Bulk Operations

Whenever rows are selected in any table, a `BulkActionBar` floats at the bottom of the screen showing context-appropriate actions:

| View | Bulk actions |
|---|---|
| Alerts | Acknowledge, Snooze 1h, Snooze 4h, Create maintenance window |
| Inventory | Add to group, Set tags, Run SNMP poll, Trigger config backup, Delete |
| Config (device list) | Push template to selected devices, Run compliance scan |
| Compliance results | Acknowledge violations, Export CSV |

Bulk config push requires explicit confirmation: "Push [template name] to [N] devices?" with a device list preview before execution.

### Config Diff UX

- **Syntax highlighting**: Cisco IOS/IOS-XE/NX-OS configs highlighted via a Monaco Editor (same engine as VS Code) with a custom IOS/NX-OS/JunOS/EOS grammar. Diffs are color-coded: green additions, red deletions, grey unchanged.
- **View toggle**: side-by-side (default) ↔ inline unified diff, toggled with a button or keyboard shortcut `D`
- **Navigation**: `N` / `P` jump to next/previous changed hunk; hunk count shown in toolbar ("3 of 12 changes")
- **Copy to clipboard**: one-click copy of the diff as a plain text patch
- **Change comments**: Operators and Admins can annotate a diff with a comment (stored in DB); useful for change management review workflows

### Virtual Scrolling & Pagination

The inventory table with 2000 devices uses `@tanstack/vue-virtual` (virtual scrolling): only the ~20 rows visible in the viewport are rendered in the DOM. Scrolling through 2000 rows is instantaneous.

All other paginated views use server-side pagination with a consistent `?page=&page_size=` API contract, default `page_size=50`, max `page_size=200`.

### Global Search

`Cmd+K` (Mac) / `Ctrl+K` (Windows) opens a full-screen search overlay powered by a server-side search endpoint:
- Searches across: device hostnames, IPs, tags, groups; alert messages; config content (recent backups); compliance rule names
- Results grouped by type with keyboard navigation (↑↓ to move, Enter to open)
- Recent searches persisted in `localStorage`

### Keyboard Shortcuts

Documented in a help overlay (`?` key). Key bindings:

| Shortcut | Action |
|---|---|
| `Cmd/Ctrl+K` | Global search |
| `?` | Show keyboard shortcuts |
| `A` | Acknowledge selected alert(s) |
| `M` | Create maintenance window for selected device(s) |
| `R` | Refresh current view |
| `D` | Toggle diff view (side-by-side ↔ inline) |
| `N` / `P` | Next / previous diff hunk |
| `G I` | Go to Inventory |
| `G A` | Go to Alerts |
| `G C` | Go to Config |
| `G M` | Go to Monitor |
| `Esc` | Close modal / clear selection |

### User Notification Preferences

Each user configures their own notification preferences in Settings → Notifications:
- Which alert severities trigger a notification (Critical only / Critical + Warning / All)
- Which device groups they care about (default: all)
- Which channels receive their notifications (email / Slack DM / browser push)
- Quiet hours: no notifications between 22:00–07:00 in their local timezone (except Critical)

Preferences stored in `user_preferences.notification_filters`. Global alert rules define the default channels; user preferences layer on top to filter or extend them for their own account.

### Theme & Accessibility

**Theme**: Dark mode by default (NOC environment). Light mode available via Settings → Appearance or OS-preference detection (`prefers-color-scheme`). Theme preference saved in `user_preferences.theme` and persists across sessions.

**Accessibility (WCAG 2.1 AA)**:
- All interactive elements keyboard-reachable via `Tab`; focus ring always visible
- Color is never the only indicator (status badges use both color + icon + text)
- All images and icons have `aria-label`; all tables have `role="grid"` with proper headers
- Color contrast ratio ≥ 4.5:1 for normal text in both themes
- Screen reader tested with NVDA (Windows) and VoiceOver (macOS)

**Responsive layout**:
- Dashboard and Alerts views are usable on tablets (≥768px) with a collapsed sidebar
- Config push and diff views require ≥1024px (too complex for mobile — show a "use desktop" message below 768px)
- Touch-friendly tap targets (≥44×44px) on tablet-sized views

### Timezone Handling

- All timestamps stored in UTC in the database — no timezone stored per record
- All timestamps displayed in the authenticated user's configured timezone (set in `user_preferences.timezone`, default UTC)
- Timezone selector in Settings → Profile shows IANA timezone names (e.g., `America/New_York`)
- Relative timestamps ("2 minutes ago", "3 hours ago") shown by default; hover reveals absolute datetime in user's timezone

### Dashboard Customization

The main Dashboard view is a grid of draggable, resizable widgets. Each user's layout is saved in `user_preferences.dashboard_layout`. Default layout ships with:
- Device health heatmap (all devices, color-coded by status)
- Active alert count by severity
- Top 5 devices by CPU utilization
- Recent config changes (last 24h)
- Compliance pass/fail ratio

Users can add/remove/rearrange widgets. Available widget types: metric chart, device status table, alert list, compliance summary, custom SNMP OID sparkline.

---

## Observability (NetPilot's Own Health)

NetPilot must be observable itself — not just the devices it monitors.

### OpenTelemetry — Distributed Tracing

Prometheus metrics tell you *what* is slow. Distributed traces tell you *why* — which poller, which device, which DB query, which Vault call added the latency. With multiple pollers and an API container, traces are the only way to follow a single request across the service boundary.

**Instrumentation:**
`opentelemetry-instrumentation-fastapi` auto-instruments every HTTP request with a trace span. Manual spans are added for the high-value operations:

```python
# poller/engines/snmp.py
from opentelemetry import trace
tracer = trace.get_tracer("netpilot.poller.snmp")

async def poll_device(device):
    with tracer.start_as_current_span("snmp.poll", attributes={"device.id": str(device.id), "device.ip": device.ip}):
        with tracer.start_as_current_span("snmp.connect"):
            ...
        with tracer.start_as_current_span("snmp.get_oids"):
            ...
        with tracer.start_as_current_span("db.batch_write"):
            ...
```

**Trace propagation across poller → API:** when a poller publishes a metric update to Redis, it includes the OTel trace context in the message payload — the API WebSocket broadcaster continues the trace when it fans out to clients.

**Exporter:** `OTEL_EXPORTER_OTLP_ENDPOINT` env var points to a Jaeger or Grafana Tempo collector:
```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4317
OTEL_SERVICE_NAME=netpilot-api          # or netpilot-poller per container
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1            # sample 10% of traces in production
```

**What traces expose that metrics can't:**
- A single slow SNMP poll causing downstream alert evaluation delay
- A CyberArk credential fetch adding 800ms to every SSH poll for a device group
- A Vault token renewal blocking 3 SSH threads simultaneously
- A compliance scan holding a DB connection during a peak traffic window

**Libraries:** `opentelemetry-sdk`, `opentelemetry-instrumentation-fastapi`, `opentelemetry-instrumentation-sqlalchemy`, `opentelemetry-instrumentation-redis`, `opentelemetry-exporter-otlp-proto-grpc`

---

### Health Endpoints

- `GET /health/live` — liveness: returns `200` if the process is alive (used by Docker health check)
- `GET /health/ready` — readiness: checks DB connectivity + APScheduler running + gNMI subscriptions; returns `200` only when fully operational (used by deploy orchestration)
- `GET /health/status` — human-readable JSON: DB latency, active gNMI connections, job scheduler state, queue depths, version

### Internal Metrics (Prometheus)

`GET /metrics` exposes Prometheus-format metrics (accessible only from internal network, blocked by nginx for external requests):

| Metric | Description |
|---|---|
| `netpilot_devices_total` | Total device count by vendor/status |
| `netpilot_snmp_poll_duration_seconds` | Histogram of SNMP poll round-trip time |
| `netpilot_ssh_session_active` | Current active SSH sessions |
| `netpilot_gnmi_subscriptions_active` | Active gNMI subscription count |
| `netpilot_alerts_active_total` | Active alert count by severity |
| `netpilot_db_query_duration_seconds` | Histogram of DB query latency |
| `netpilot_job_last_run_timestamp` | Last successful run time per APScheduler job |
| `netpilot_job_failures_total` | Background job failure count by job name |

### Structured Application Logging

All log lines are JSON (via `structlog`). Fields on every line: `ts`, `level`, `logger`, `request_id`, `user_id` (if authenticated), `method`, `path`, `duration_ms`. Sensitive fields (`password`, `token`, `key`, `community`) are redacted by a filter in `core/logging.py` before the log line is emitted — a future leak of logs does not expose credentials.

### Alerting on NetPilot Itself

A separate lightweight health-watcher script (`tools/watchdog.py`) runs outside the main container and sends an alert if:
- `/health/live` returns non-200 for >30 seconds
- `/health/ready` returns non-200 for >2 minutes
- A background job has not run within 2× its scheduled interval

This prevents the situation where NetPilot silently stops polling but appears fine because the UI is still up.

---

## Disaster Recovery

### Recovery Objectives

| Scenario | RTO target | RPO target |
|---|---|---|
| Container crash (auto-restart) | < 30 seconds | 0 (no data loss) |
| Host failure (redeploy from image) | < 15 minutes | < 24h (last DB backup) |
| DB corruption | < 1 hour | < 24h (last pg_dump) |
| Ransomware / full environment loss | < 4 hours | < 24h (offsite backup) |

### Backup Schedule

| Asset | Method | Frequency | Retention | Offsite? |
|---|---|---|---|---|
| PostgreSQL | `pg_dump` + gpg encrypt | Daily 02:00 UTC | 30 days | Yes (S3/Azure) |
| Config git repo | `git bundle` + gpg encrypt | Daily 03:00 UTC | 90 days | Yes (S3/Azure) |
| `.env` / secrets | Vault snapshot or SSM export | Daily | 30 days | Yes |
| Docker images | Registry push (tagged) | On every build | Last 10 versions | Yes (registry) |

### Restore Procedure

Full procedure documented in `docs/DISASTER_RECOVERY.md`. High-level steps:

```
1. Provision new host / VM
2. Install Docker + Docker Compose
3. Pull latest NetPilot image from registry
4. Restore .env from Vault/SSM
5. Start postgres container (empty)
6. Restore DB: gpg decrypt backup → pg_restore
7. Restore configs/ repo: gpg decrypt → git clone from bundle
8. Start remaining services: docker compose up -d
9. Verify: GET /health/ready returns 200
10. Run smoke test: poll one known device
```

Restore is drilled quarterly. The drill includes validating that the restored DB matches expected row counts and that a config backup from the restored repo is readable.

### Single Points of Failure

| Component | Current SPOF? | Mitigation |
|---|---|---|
| PostgreSQL | Yes (single container) | Daily backup + fast restore; for HA: promote to Patroni cluster |
| FastAPI process | Yes (single container) | Docker auto-restart; watchdog alerts on failure |
| Config git repo | Yes (local volume) | Daily offsite bundle backup |
| APScheduler | Yes (in-process) | Job last-run monitoring via Prometheus; watchdog alerts on missed jobs |

For environments requiring higher availability, the design notes where each component can be promoted to an HA configuration without code changes (Patroni for PG, multiple API replicas behind a load balancer).

---

## Additional Capabilities

### Event Notifications & Ansible EDA Integration

NetPilot emits structured events for every operationally significant state change. Any external tool — Ansible Event-Driven Automation, a custom webhook, Kafka consumers, or another SIEM — can subscribe to these events and react in real time.

---

#### Event Payload Format (CloudEvents 1.0)

All events conform to the **CloudEvents 1.0 specification** (CNCF standard) so they are natively portable to Ansible EDA, AWS EventBridge, Azure Event Grid, Google Eventarc, Knative Eventing, and any other CloudEvents-compatible system without translation.

```json
{
  "specversion": "1.0",
  "id":          "evt-f3a2c1d4-...",
  "source":      "https://netpilot.corp.com",
  "type":        "com.netpilot.alert.fired",
  "time":        "2026-04-25T14:32:01Z",
  "datacontenttype": "application/json",
  "subject":     "device/uuid-of-core-rtr-01",
  "data": {
    "alert_id":           "uuid",
    "device_id":          "uuid",
    "hostname":           "core-rtr-01",
    "ip":                 "10.1.1.1",
    "severity":           "critical",
    "message":            "CPU utilization 95.2% (threshold: 90%)",
    "metric":             "cpu_util",
    "value":              95.2,
    "group_name":         "Production-Core",
    "center_name":        "DC-EAST",
    "department":         "Network Engineering",
    "device_type":        "Router",
    "os_category":        "Cisco IOS-XE",
    "functional_category":"Core",
    "compliance_category":["PCI-DSS"],
    "vendor":             "cisco"
  }
}
```

---

#### Event Types

| Event type | Fired when |
|---|---|
| `com.netpilot.alert.fired` | Alert rule threshold crossed |
| `com.netpilot.alert.resolved` | Alert auto-resolved (metric dropped below threshold) |
| `com.netpilot.alert.acknowledged` | Alert manually acknowledged by user |
| `com.netpilot.device.down` | Device SNMP poll fails 3× consecutively |
| `com.netpilot.device.up` | Device recovers from down state |
| `com.netpilot.device.degraded` | Partial connectivity (SNMP ok but SSH/gNMI failing) |
| `com.netpilot.incident.created` | Alert group promoted to an incident |
| `com.netpilot.incident.resolved` | Incident marked resolved |
| `com.netpilot.config.changed` | Unexpected config change detected (outside scheduled window) |
| `com.netpilot.config.push.completed` | Config push succeeded |
| `com.netpilot.config.push.failed` | Config push failed (dry-run or execution error) |
| `com.netpilot.compliance.violation` | Device fails a compliance rule |
| `com.netpilot.compliance.resolved` | Previously failing rule now passes |
| `com.netpilot.anomaly.detected` | Metric Z-score > 3.0 detected by anomaly engine |
| `com.netpilot.cve.critical` | New Critical CVE (CVSS ≥ 9.0) detected in nightly scan |
| `com.netpilot.device.onboarded` | New device added to inventory |
| `com.netpilot.poller.dead` | Poller container missed 3 heartbeats |

---

#### Event Subscription Model

Subscribers register via REST. Each subscription declares which event types it wants, optional filter conditions, and a delivery target.

```
POST /api/v1/events/subscriptions
{
  "name":        "EDA — prod alert handler",
  "event_types": ["com.netpilot.alert.fired", "com.netpilot.device.down"],
  "filter": {
    "severity":       ["critical"],
    "center_name":    ["DC-EAST", "DC-WEST"],
    "device_type":    ["Router", "Switch"]
  },
  "target": {
    "type":    "webhook",
    "url":     "https://eda-controller.corp.com:5000/endpoint",
    "headers": { "Authorization": "Bearer <EDA token>" },
    "retry_policy": { "max_retries": 5, "backoff_seconds": [1, 5, 30, 120, 600] }
  }
}
```

Filter fields map directly to `data.*` fields in the CloudEvents payload — the engine evaluates `all(filter_field in event.data[field] for filter_field in filter_values)` before dispatching.

---

#### Data Model

```sql
CREATE TABLE event_subscriptions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  event_types   TEXT[] NOT NULL,              -- CloudEvents type strings
  filter        JSONB NOT NULL DEFAULT '{}',  -- field → value-list filter conditions
  target_type   TEXT NOT NULL,                -- webhook | kafka | redis_stream | eda_webhook
  target_url    TEXT,                         -- for webhook / eda_webhook
  target_config_enc BYTEA,                    -- AES-256-GCM: full target config (tokens, topics)
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_by    UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_delivery_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES event_subscriptions(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,
  event_id        TEXT NOT NULL,              -- CloudEvents id field
  event_payload   JSONB NOT NULL,
  target_url      TEXT,
  http_status     SMALLINT,                   -- NULL for non-HTTP targets
  response_body   TEXT,
  retry_count     SMALLINT NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'pending', -- pending | delivered | failed | abandoned
  delivered_at    TIMESTAMPTZ,
  next_retry_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_edl_subscription ON event_delivery_log (subscription_id, created_at DESC);
CREATE INDEX idx_edl_pending      ON event_delivery_log (next_retry_at) WHERE status = 'pending';
```

---

#### Ansible Event-Driven Automation (EDA) Integration

EDA Controller connects via two complementary methods:

**Method 1 — NetPilot pushes to EDA Webhook source plugin (recommended)**

NetPilot acts as the publisher. The EDA Controller runs the built-in `ansible.eda.webhook` source plugin on an inbound port. NetPilot posts CloudEvents payloads to it via an event subscription with `target_type=eda_webhook`.

```
Alert fires in NetPilot
    ↓
Event engine evaluates subscriptions matching com.netpilot.alert.fired
    ↓
POST https://eda-controller:5000/endpoint
  Content-Type: application/json
  Ce-Id: evt-abc123                        ← CloudEvents headers (HTTP binding)
  Ce-Type: com.netpilot.alert.fired
  Ce-Source: https://netpilot.corp.com
  Body: { "alert_id": ..., "hostname": "core-rtr-01", "severity": "critical", ... }
    ↓
EDA Rulebook evaluates condition
    ↓
Run Ansible playbook (remediation / CMDB update / escalation)
```

**Example EDA Rulebook:**
```yaml
# playbooks/eda/netpilot_rules.yml
---
- name: NetPilot Network Remediation
  hosts: all
  sources:
    - ansible.eda.webhook:
        host: 0.0.0.0
        port: 5000
        token: "{{ lookup('env', 'EDA_WEBHOOK_TOKEN') }}"

  rules:
    - name: Device Down — restart monitoring and page on-call
      condition: >
        event.meta.headers['Ce-Type'] == "com.netpilot.device.down"
        and event.payload.severity == "critical"
      action:
        run_job_template:
          name: "Device Unreachable Response"
          organization: "Network Ops"
          extra_vars:
            hostname:    "{{ event.payload.hostname }}"
            device_ip:   "{{ event.payload.ip }}"
            center_name: "{{ event.payload.center_name }}"

    - name: Compliance Violation — auto-remediate known rules
      condition: >
        event.meta.headers['Ce-Type'] == "com.netpilot.compliance.violation"
        and event.payload.rule_name == "Require SSH version 2"
      action:
        run_playbook:
          name: "playbooks/enforce_ssh_v2.yml"
          extra_vars:
            hostname: "{{ event.payload.hostname }}"

    - name: Config Changed Unexpectedly — open change ticket
      condition: >
        event.meta.headers['Ce-Type'] == "com.netpilot.config.changed"
      action:
        run_playbook:
          name: "playbooks/create_servicenow_ticket.yml"
          extra_vars:
            device:     "{{ event.payload.hostname }}"
            changed_at: "{{ event.meta.received_at }}"

    - name: Critical CVE Detected — trigger patch workflow
      condition: >
        event.meta.headers['Ce-Type'] == "com.netpilot.cve.critical"
      action:
        run_job_template:
          name: "Patch NetPilot Container"
          organization: "Platform Ops"
          extra_vars:
            cve_id:    "{{ event.payload.cve_id }}"
            component: "{{ event.payload.package_name }}"
```

**Method 2 — EDA pulls from NetPilot SSE stream (custom source plugin)**

A custom Python source plugin ships in `integrations/ansible_eda/` that connects to NetPilot's `/api/v1/events/stream` SSE endpoint and feeds events into the EDA queue. Useful when the EDA controller is behind a firewall and cannot receive inbound webhooks.

```python
# integrations/ansible_eda/netpilot_source.py
from ansible_rulebook.event_source import EventSource
import httpx, asyncio

class NetPilotSource(EventSource):
    async def produce(self, queue: asyncio.Queue, args: dict):
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "GET", f"{args['url']}/api/v1/events/stream",
                headers={"Authorization": f"Bearer {args['token']}"},
                params={"types": ",".join(args.get("event_types", []))},
                timeout=None
            ) as response:
                async for line in response.aiter_lines():
                    if line.startswith("data:"):
                        event = json.loads(line[5:])
                        await queue.put({"payload": event["data"], "meta": event})
```

```yaml
# Usage in rulebook
sources:
  - custom.netpilot.netpilot_source:
      url: "https://netpilot.corp.com"
      token: "{{ lookup('env', 'NETPILOT_API_TOKEN') }}"
      event_types:
        - com.netpilot.alert.fired
        - com.netpilot.device.down
        - com.netpilot.compliance.violation
```

---

#### Alternative Transports

| Transport | `target_type` | When to use |
|---|---|---|
| Webhook / EDA push | `eda_webhook` | EDA reachable from NetPilot; simplest setup |
| Kafka topic | `kafka` | High-volume environments; multiple consumers; Kafka already in org |
| Redis Streams | `redis_stream` | Redis already deployed (it is in this stack); low-latency |
| Generic webhook | `webhook` | ServiceNow, Jira, custom ITSM, Teams Incoming Webhook |
| Custom SSE pull | N/A (source plugin) | EDA behind firewall; cannot receive inbound connections |

**Kafka target config:**
```json
{
  "target_type": "kafka",
  "target_config": {
    "bootstrap_servers": "kafka.corp.com:9093",
    "topic": "netpilot.events",
    "security_protocol": "SASL_SSL",
    "sasl_mechanism": "SCRAM-SHA-512"
  }
}
```

**Redis Streams target (using the stack's own Redis):**
```json
{
  "target_type": "redis_stream",
  "target_config": {
    "stream_key": "netpilot:events",
    "maxlen": 10000
  }
}
```
EDA or any other Redis consumer reads from the stream with `XREAD COUNT 100 BLOCK 5000`.

---

#### Delivery Reliability

- **At-least-once delivery**: events are committed to `event_delivery_log` before dispatch; if the app restarts mid-delivery, the pending row is retried on restart
- **Retry with exponential backoff**: default 5 retries at 1s → 5s → 30s → 120s → 600s; abandoned after final retry with `status='abandoned'`
- **Dead letter visibility**: `GET /api/v1/events/delivery-log?status=abandoned` shows all failed deliveries; Admin can manually re-trigger via `POST /api/v1/events/delivery-log/{id}/retry`
- **Deduplication**: EDA consumers should treat CloudEvents `id` as idempotency key — NetPilot may deliver the same event twice during retry; the unique `id` field allows downstream dedup

---

### Network Auto-Discovery

The Discovery module performs SNMP-based subnet sweeps to find new devices without manual entry:

- Input: one or more CIDR subnets (e.g., `10.0.0.0/22`) + SNMP community string(s) to try
- Sweep sends SNMP GET for `sysDescr` and `sysName` to each host in the subnet (parallelised, concurrency-capped)
- Responsive hosts are fingerprinted by `sysDescr` to determine vendor/OS
- Results presented in the Discovery UI: list of found devices with detected vendor, hostname from DNS/SNMP, current inventory status (new / already managed / ignored)
- Operator can select devices to add to inventory in bulk with one click; optionally assign to a group and trigger an immediate SNMP poll
- Discovery jobs run on-demand; can be scheduled (e.g., weekly sweep to catch new devices)

### Reporting

Scheduled and on-demand reports exportable as PDF or CSV. All reports support filter dimensions derived from standard device attributes and custom fields.

#### Report Types

| Report | Contents |
|---|---|
| **Compliance Summary** | Pass/fail % per rule per device; trend vs prior period; violation breakdown by severity |
| **Compliance Violations** | Per-device, per-rule violation detail with the offending config line (scrubbed) and remediation hint |
| **Compliance Trend** | Compliance score over time (daily) — useful for demonstrating improvement to auditors |
| **Device Availability** | Uptime % per device over selected period, downtime events, MTTR |
| **Config Change Log** | All config changes in a date range, diff summaries, who pushed, approval status |
| **Alert History** | Alert count by severity/device/group, MTTR (mean time to resolve) |
| **Security Audit** | All security events in a date range (for auditors) |
| **CVE Status** | Current open CVEs by severity; waiver status; remediation actions taken |
| **Inventory Snapshot** | All devices with all standard attributes — useful for CMDB reconciliation |
| **Credential Rotation Status** | Per-device credential_rotation policy, last rotation date (from CyberArk/Vault), overdue devices |

#### Compliance Report Filters

Every compliance report supports multi-dimensional filtering so teams can generate targeted compliance evidence for auditors:

| Filter dimension | Source |
|---|---|
| Device type | `device_type` standard attribute |
| OS / Platform | `os_category` standard attribute |
| Data center / Site | `center_name` standard attribute |
| City | `city` standard attribute |
| Department | `department` standard attribute |
| Functional category | `functional_category` standard attribute |
| Compliance category | `compliance_category` standard attribute (e.g., "PCI-DSS", "HIPAA") |
| Device group | Device group membership |
| Tags | Any device tag(s) |
| Rule category | Compliance rule `category` field (e.g., "CIS Benchmark L1") |
| Rule severity | Critical / Major / Minor / Info |
| Status | Pass / Fail / Skip / All |
| Date range | `checked_at` window for compliance scan results |

**Example use cases:**
- "PCI-DSS compliance report for all Cisco devices in DC-EAST" → filter: `compliance_category=PCI-DSS`, `device_type=Router,Switch`, `center_name=DC-EAST`
- "Weekly security baseline report for the Network Engineering team" → filter: `department=Network Engineering`, `rule_category=Security Baseline`, scheduled weekly

#### Report Generation

```
POST /api/v1/reports/generate
{
  "report_type": "compliance_violations",
  "format": "pdf",
  "filters": {
    "compliance_category": ["PCI-DSS"],
    "center_name": ["DC-EAST"],
    "severity": ["critical", "major"],
    "date_from": "2026-04-01",
    "date_to": "2026-04-25"
  },
  "title": "Q2 PCI-DSS Compliance — DC-EAST"
}
```

Response: `{ "report_id": "uuid", "status": "queued" }` — report generates in the background.
`GET /api/v1/reports/{id}` polls status; when `complete`, a signed URL is returned for download.

#### Scheduled Reports

Reports can be scheduled with a cron expression and delivered by email:

```
POST /api/v1/reports/schedules
{
  "name": "Weekly PCI Compliance — DC-EAST",
  "report_type": "compliance_summary",
  "schedule_cron": "0 8 * * MON",
  "format": "pdf",
  "filters": { ... },
  "recipients": ["ciso@corp.com", "audit@corp.com"]
}
```

All compliance report PDFs apply `ConfigScrubber` to any config snippets included — no credentials appear in emailed reports.

Reports can be scheduled (e.g., every Monday 08:00) and delivered by email to a list of recipients. PDF reports use `WeasyPrint`; CSV uses Python's `csv` module. Report generation is a background APScheduler job — large reports do not block the API.

### Network Topology Visualization

A visual graph of how devices interconnect — essential for understanding blast radius during an incident and for validating network design against the device inventory.

**Data source:** CDP/LLDP neighbor tables collected via SNMP (`CISCO-CDP-MIB`, `LLDP-MIB`) during the regular SNMP poll. Neighbor data stored in `device_neighbors` table (source_device_id, neighbor_device_id, local_interface, remote_interface, protocol).

**Frontend component:** `TopologyGraph.vue` renders an interactive force-directed graph using **D3.js v7**:
- Nodes: each device, colored by status (green=UP, red=DOWN, yellow=DEGRADED)
- Edges: CDP/LLDP adjacencies, labeled with interface names
- Node size: proportional to number of connected devices (spine nodes visually larger)
- Click a node → fly-out panel with device summary (status, last backup, active alerts)
- Click an edge → shows interface utilization chart for both endpoints
- Filters: by group, by vendor, by functional_category (show only Core + Distribution)
- Layout toggle: force-directed (auto-arrange) ↔ hierarchical (spine → leaf tree view)

**REST API:**
```
GET /api/v1/topology/graph          → { nodes: [...], edges: [...] }
GET /api/v1/topology/device/{id}/neighbors  → direct neighbors only
```

**Impact radius on incident:** when an alert fires, the Incident card includes a "Show topology" button that opens the graph pre-filtered to the affected device and its neighbors — immediately shows which upstream devices could be the root cause.

### AI-Assisted Operations

These features use lightweight statistical models and LLM integration — no GPU required. Everything runs in the API container.

#### Anomaly Detection (Statistical Baseline)

For each metric on each device, a rolling baseline is computed from the previous 7 days of TimescaleDB data. Anomaly detection runs as a post-poll step in the poller's metric pipeline:

```python
# Welford's online algorithm — O(1) per update, no full history load
class MetricBaseline:
    def update(self, value: float) -> AnomalyResult:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (value - self.mean)
        std = math.sqrt(self.M2 / self.n) if self.n > 1 else 0
        z_score = (value - self.mean) / std if std > 0 else 0
        return AnomalyResult(is_anomaly=abs(z_score) > 3.0, z_score=z_score)
```

A metric reading with Z-score > 3.0 (3 standard deviations from the rolling mean) fires an `anomaly_detected` alert with severity proportional to the Z-score. This catches:
- CPU spiking to 95% on a device that typically idles at 15%
- Interface utilization suddenly dropping to 0% (link failure not yet reported via SNMP trap)
- Memory creeping up 5% per day (memory leak on a device before it crashes)

Baselines are stored in Redis (rolling statistics, not raw values) — no extra DB storage. A device's baseline is ready after 24 hours of polling.

**Why not ML models?** A well-tuned Z-score baseline catches the same anomalies as a simple LSTM for this use case, with zero training data requirement, deterministic output, and sub-millisecond inference. ML models are added in a future release after baselines are validated in production.

#### Natural Language Search

The global search (`Cmd+K`) accepts natural language queries in addition to exact text:

```
"show routers in DC-EAST with high CPU"
→ devices WHERE device_type='Router' AND center_name='DC-EAST'
  AND last metric cpu_util > 80

"devices that failed compliance last week"
→ compliance_results WHERE status='fail' AND checked_at > now()-7d

"who pushed configs to core switches yesterday"
→ audit_log WHERE resource_type='config_push' AND device.functional_category='Core'
  AND timestamp > yesterday
```

**Implementation:** a small prompt sent to the Claude API (Anthropic) translates natural language to a structured filter object. The filter is validated server-side (no SQL injection — it generates a Pydantic filter model, not raw SQL). LLM calls are optional — if `ANTHROPIC_API_KEY` is not set, NL search is disabled and only exact text search works.

```python
# modules/search/nl_query.py
async def parse_nl_query(text: str) -> DeviceFilter | AuditFilter | ComplianceFilter:
    response = await anthropic_client.messages.create(
        model="claude-haiku-4-5-20251001",  # fast + cheap for query parsing
        system=NL_QUERY_SYSTEM_PROMPT,      # describes available filter fields
        messages=[{"role": "user", "content": text}]
    )
    return validate_filter(json.loads(response.content[0].text))
```

#### Predictive Alert Suppression

When an alert fires, the system checks whether a similar alert on the same device resolved itself within 5 minutes in the last 30 days. If the historical self-resolution rate is > 80%, the alert is tagged `likely_transient` and notification channels are suppressed for the first 3 minutes. If the alert is still active at 3 minutes, full notification fires.

This cuts alert noise for devices with known intermittent issues without hiding genuine outages.

**Implementation:** a simple lookup against `alerts` table history — no ML needed.

---

### Change Management Integration

Config pushes can optionally require approval before execution, integrating with external ticketing systems:

**Approval workflow:**
1. Operator creates a change request: selects device(s), template, and renders the config preview
2. Change request is saved in `change_requests` table with status `pending`
3. Notification sent to Admins (in-app + email) with a link to review
4. Admin reviews diff, approves or rejects with a comment
5. On approval, the push executes automatically (or the Operator triggers it manually, depending on config)

**External ticketing integration:**
- ServiceNow: change request creation fires a ServiceNow Change Request via REST API; approval in ServiceNow updates NetPilot status via a webhook
- Jira: change request creates a Jira issue; issue transition to "Done" triggers the push
- Generic webhook: POST to any URL on status change — custom ITSM systems supported
- All integrations configured via env vars; no code change to swap systems

### Performance SLA Targets

These targets define "working correctly" for monitoring and alerting purposes:

| Operation | Target p95 | Target p99 |
|---|---|---|
| Dashboard initial load | < 1.5s | < 3s |
| Device inventory list (2000 devices) | < 500ms | < 1s |
| Alert list (paginated) | < 300ms | < 500ms |
| Config diff render (2000-line config) | < 800ms | < 1.5s |
| SNMP poll round-trip (per device) | < 2s | < 5s |
| Config backup (per device) | < 30s | < 60s |
| API key authentication overhead | < 5ms | < 10ms |

Prometheus metrics (`netpilot_db_query_duration_seconds`, `netpilot_snmp_poll_duration_seconds`) are used to alert when p95 exceeds these thresholds.

---

## Deployment Approaches

NetPilot is container-native — every service (API, poller, postgres, pgbouncer, nginx) runs in a container. The question is which orchestrator manages those containers. Three tiers are supported, chosen based on environment size and operational maturity.

---

### Tier 1 — Docker Compose (Dev / Small Deployments)

Already designed throughout this spec. Single host, single `docker compose up`. Best for:
- Development and local testing
- Small teams (< 200 devices) on a single VM
- Air-gapped environments without a K8s cluster

**Poller scaling on Compose:**
```bash
docker compose up -d --scale poller=2
```

---

### Tier 2 — Kubernetes (Production / Enterprise)

The recommended production deployment. The architecture was intentionally designed to be K8s-native: stateless API pods, stateless poller pods (state lives in DB), coordinator-managed partition assignments (no pod-level state needed).

#### Helm Chart (`charts/netpilot/`)

A Helm chart is shipped with the repo for one-command deployment:

```bash
helm repo add netpilot https://netpilot.example.com/charts
helm install netpilot netpilot/netpilot \
  --set api.image.tag=1.4.2 \
  --set poller.replicaCount=3 \
  --set postgresql.enabled=true \
  --values my-values.yaml
```

Chart structure:
```
charts/netpilot/
  Chart.yaml
  values.yaml                 # all defaults documented with comments
  templates/
    api-deployment.yaml
    api-service.yaml
    api-hpa.yaml
    poller-deployment.yaml
    poller-hpa.yaml           # scales pollers based on device count per poller
    frontend-deployment.yaml
    pgbouncer-deployment.yaml
    configmap.yaml
    secret.yaml               # references ExternalSecrets or Vault Agent injector
    networkpolicy.yaml        # deny-all + explicit allow rules per pod
    poddisruptionbudget.yaml  # ensures ≥1 poller stays up during rolling updates
    serviceaccount.yaml
    rbac.yaml
```

#### Horizontal Pod Autoscaler — Pollers

The poller `HPA` scales on a custom metric: `netpilot_devices_per_poller` (exposed via Prometheus Adapter):

```yaml
# templates/poller-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  scaleTargetRef:
    name: netpilot-poller
  minReplicas: 1
  maxReplicas: 10
  metrics:
  - type: Pods
    pods:
      metric:
        name: netpilot_devices_per_poller
      target:
        type: AverageValue
        averageValue: "600"   # scale up when any poller exceeds 600 devices
```

This means growing from 500 to 2000 devices triggers automatic poller scale-out — no manual intervention.

#### Kubernetes-Native Secrets (External Secrets Operator)

Instead of Docker secrets or `.env` files, K8s deployments use the **External Secrets Operator (ESO)** to sync secrets from Vault or AWS Secrets Manager into K8s `Secret` objects:

```yaml
# templates/external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
spec:
  secretStoreRef:
    name: vault-backend
  target:
    name: netpilot-secrets
  data:
  - secretKey: ENCRYPTION_KEY
    remoteRef: { key: netpilot/config, property: encryption_key }
  - secretKey: DB_PASSWORD
    remoteRef: { key: netpilot/db, property: password }
```

Secrets auto-rotate when Vault rotates them — no pod restarts needed.

#### GitOps with ArgoCD / Flux

For production deployments, the Helm chart values and image tags are committed to a separate GitOps repo. ArgoCD or Flux watches the repo and applies changes:

```
git commit -m "bump netpilot to 1.5.0"
    ↓
ArgoCD detects diff → applies Helm upgrade → rolling restart of api + poller pods
```

This eliminates `kubectl apply` from production CI — the Git repo is the source of truth for cluster state. All deployments are audited via git history.

#### Network Policies

A deny-all default NetworkPolicy ships in the chart, with explicit allow rules:

```yaml
# Only poller pods can reach pgbouncer (not api — api uses same pgbouncer but via separate policy)
# Only api pods can reach external services (Vault, CyberArk, OIDC IdP)
# Frontend pods only receive ingress from the ingress controller
# No pod can make arbitrary egress to the internet
```

This is the K8s equivalent of the Docker bridge network isolation already in the Compose design.

#### Pod Security Standards

All NetPilot pods run with:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

These settings align with the **Kubernetes Restricted Pod Security Standard** — the strictest built-in tier.

---

### Tier 3 — Rootless Podman (Single-Host, No-Root)

For environments where Docker daemon (root) is not acceptable — on-premise RHEL/Rocky Linux hardened servers:

- **Podman** runs all containers as the `netpilot` service user — no root daemon, no root socket
- `podman-compose` (or `podman play kube`) provides the same Compose interface
- Systemd quadlets (`~/.config/containers/systemd/`) start containers at boot without root
- SELinux labels applied automatically by Podman on RHEL — MCS (Multi-Category Security) labels isolate containers from each other at the kernel level

```bash
# Run as non-root user 'netpilot'
podman-compose up -d
# Systemd auto-start
loginctl enable-linger netpilot
```

---

### Deployment Comparison

| | Docker Compose | Kubernetes + Helm | Rootless Podman |
|---|---|---|---|
| Min ops expertise | Low | Medium | Low |
| Auto-scaling pollers | Manual (`--scale`) | Automatic (HPA) | Manual |
| Rolling zero-downtime updates | Manual | Built-in | Manual |
| Secrets management | Docker secrets / .env | ESO + Vault | Podman secrets |
| HA PostgreSQL (Patroni) | etcd container | etcd StatefulSet | etcd container |
| Best for | Dev / ≤500 devices | Prod / enterprise | RHEL / air-gapped |

---

## Docker Compose Services

```yaml
services:
  api:        FastAPI backend (uvicorn), REST + WebSocket only (no polling),
              mounts configs/ volume, depends on pgbouncer
  poller:     netpilot-poller (SNMPEngine + SSHEngine + gNMIEngine), same image as api,
              different CMD; scale with: docker compose scale poller=N
              depends on pgbouncer, api (for coordinator registration)
  frontend:   nginx serving Vite build, proxies /api and /ws to api service
  postgres:   PostgreSQL 16 + TimescaleDB + pgaudit + pg_tde (17+), LUKS-encrypted volume,
              TLS enabled, pg_hba.conf restricts to internal network only
  pgbouncer:  PgBouncer — TLS on both client and server sides; shared by api + poller fleet
  etcd:       Distributed consensus for Patroni HA failover (3-node etcd cluster in prod)
```

**Scaling pollers:**
```bash
# Single-host: run 2 pollers (1000 devices each)
docker compose up -d --scale poller=2

# Check poller fleet health
curl -s http://localhost:8000/api/v1/admin/pollers | jq '.[] | {id, status, devices_assigned}'
```

Each `poller` replica gets a unique `POLLER_ID` via Docker's `{{.Task.Slot}}` template in the compose file — no manual ID management needed.

Single `.env` file drives all secrets and configuration (DB URL, SMTP, Slack webhook URLs, SNMP communities, JWT secret, IdP client IDs and secrets).

**Container hardening:**
- `api` and `frontend` run as non-root (`USER appuser`)
- `postgres` data volume is named and managed by Docker (not a host bind-mount)
- No container exposes ports to the host except `frontend:443` and `api:8000` (or via a reverse proxy)
- All inter-service communication is on an isolated Docker bridge network (`netpilot-internal`)
- Health checks defined for all services; Docker restarts unhealthy containers automatically
