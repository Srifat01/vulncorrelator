# VulnCorrelator

An API-first service that ingests vulnerability scanner output, **normalizes and deduplicates** it across tools,
**enriches** findings with exploit intelligence (CISA KEV, EPSS), ties them to **assets**, and surfaces
**high-risk attack chains** with a plain-English explanation of why each one was flagged.

```
 Nmap XML ─┐                                        ┌─ GET /assets, /vulnerabilities
 Nessus   ─┼─► POST /ingest[/upload] ─► parse ─► normalize ─► enrich ─► upsert ─► PostgreSQL
 JSON     ─┘        │ (sync, or ?async_mode)        (CPE, CVSS,   (catalog,         │
                    ▼                                fingerprint)  KEV, EPSS)       ▼
                Redis queue ─► RQ worker                              correlation engine (rules)
                    ▲                                                          │
                    └──────── Redis cache (chains/stats) ◄─────────────────────┴─► GET /chains, /stats
```

**Stack:** Python 3.10+ · FastAPI · SQLAlchemy 2 + Alembic · PostgreSQL · Redis (RQ + cache) · Docker Compose · pytest

## Quick start

```bash
docker compose up --build        # Postgres + Redis + API (runs migrations) + background worker
open http://localhost:8000/      # operator dashboard (redirects to /ui/)
open http://localhost:8000/docs  # interactive Swagger UI
```

Try it with the bundled sample scans (a web server, an FTP/SMB server, one credentialed Nessus scan):

```bash
# 1. Upload an Nmap scan via the background worker (returns 202 immediately)
curl -F format=nmap -F async_mode=true -F file=@samples/nmap_scan.xml localhost:8000/ingest/upload

# 2. Upload a Nessus scan synchronously. The Apache finding is merged with Nmap's, not duplicated
curl -F format=nessus -F file=@samples/nessus_scan.nessus localhost:8000/ingest/upload

# 3. What did we find?
curl localhost:8000/assets
curl "localhost:8000/vulnerabilities?limit=5"     # network-wide top 5 by risk

# 4. Attack chains. Same-host chains appear straight away...
curl "localhost:8000/chains?min_risk=9"

# 5. ...tell the system web01 is internet-facing and pivot chains appear
curl -X PATCH localhost:8000/assets/1 -H 'content-type: application/json' -d '{"internet_facing": true}'
curl "localhost:8000/chains?rule=lateral-movement"
```

Example chain (abridged):

```json
{
  "rule": "lateral-movement",
  "title": "Pivot from 10.0.1.10 (web01.corp.local) to 10.0.1.20 (ftp01.corp.local)",
  "risk_score": 10.0, "severity": "critical",
  "explanation": "10.0.1.10 is internet-facing and vulnerable to Apache HTTP Server 2.4.49 path traversal and remote code execution (CVE-2021-41773). Once compromised it sits in the same 10.0.1.0/24 network as 10.0.1.20, which runs vsftpd 2.3.4 backdoor command execution (CVE-2011-2523) on port 21 and is not directly exposed - a classic pivot path.",
  "steps": [{"order": 1, "role": "initial-access", "...": "..."}, {"order": 2, "role": "lateral-movement", "...": "..."}]
}
```

Run without Docker: `pip install -r requirements-dev.txt && uvicorn app.main:app --reload`
(SQLite file DB by default; no Redis needed: caching is skipped and `async_mode` returns 503. Create tables with `alembic upgrade head`.)

## Dashboard

`/ui/` (and `/`, which redirects there) serves a static operator dashboard — no separate build step, no
extra service, just files the API already hosts under `app/static/dashboard/`:

- **Overview** — a risk dial and severity spectrum computed from `/stats`.
- **Asset Register** / **Finding Log** — sortable, filterable tables over `/assets` and `/vulnerabilities`.
- **Attack Chain Board** — the chains from `/chains` drawn as a node-and-path map, each with its full
  plain-English explanation underneath.
- **Ingest Scan** — drag-and-drop (or browse) an Nmap/Nessus/JSON report straight into `POST /ingest/upload`,
  with live upload progress and the resulting report ticket.

It talks to the API on the same origin it's served from, so no CORS setup is needed. If `API_KEY` is set,
open **Connection settings** in the sidebar and paste the key in; it's kept in that browser's `localStorage`
only. If the API can't be reached at all, the dashboard falls back to a small bundled sample case file (the
same web01/ftp01 scenario in the example above) so the UI is still inspectable with nothing running — a
banner says plainly when you're looking at that instead of live data.

## API

| Method & path | Purpose |
|---|---|
| `POST /ingest` | JSON report (`{"source": "...", "hosts": [{ip_address, hostname, os, services[], vulnerabilities[]}]}`). `?async_mode=true`, `?internet_facing=true` |
| `POST /ingest/upload` | Multipart: `file` + `format=nmap\|nessus` (+ optional `async_mode`, `internet_facing`) |
| `GET /reports`, `/reports/{id}` | Ingest history and status (`pending/processing/completed/failed`, new vs. updated counts) |
| `GET /assets`, `/assets/{id}` | Assets with vuln count + max risk, riskiest first. Filters: `internet_facing`, `min_risk` |
| `PATCH /assets/{id}` | Override `hostname` / `internet_facing` |
| `GET /assets/{id}/vulnerabilities` | Per-asset findings. Filters: `min_risk`, `severity`, `kev_only` |
| `GET /assets/{id}/services` | Open ports and detected products |
| `GET /vulnerabilities` | Network-wide, by risk (default limit 10 = "top 10"). Filters: `min_risk`, `severity`, `cve_id`, `kev_only` |
| `GET /chains`, `/chains/{id}` | Attack chains with explanations. Filters: `min_risk`, `asset_id`, `rule` |
| `GET /stats` | Totals, severity breakdown, KEV count, chain counts |
| `GET /health` | DB (+ Redis) check, unauthenticated |

All lists are paginated (`limit`, `offset`). Set `API_KEY` to require an `X-API-Key` header everywhere except `/health`.

## How it works

**Normalization.** Scanners disagree on names, so each finding is reduced to a common shape: CPE 2.2/2.3 is parsed into
vendor/product/version; free-text products ("Apache httpd") are mapped to canonical CPE products via an alias table; service
names are unified (`www` → `http`, `microsoft-ds` → `smb`); CVSS is clamped to 0-10, a score is derived from a severity label when a
tool gives only a label, and the qualitative band is recomputed from the number.

**Deduplication.** Every finding gets a deterministic SHA-256 fingerprint, enforced by a unique index and written with
`INSERT … ON CONFLICT DO NOTHING`, so concurrent workers cannot create duplicates. For findings with a CVE the identity is
`(asset, port, protocol, CVE)`. Service name and version are deliberately *attributes*, not identity: otherwise Nmap
(`Apache httpd 2.4.49`) and Nessus (`www`, no version) would each report the same flaw, and upgrading a service would fork the record.
Findings with no CVE fall back to `(asset, port, protocol, service, version, normalized title)`. Re-sightings merge: highest CVSS wins,
tags/sources/evidence accumulate per scanner, `last_seen` moves, `first_seen` never does.

**Enrichment.** Discovered `product + version` is matched against a small CVE catalog (`app/data/cve_catalog.json`) to attach CVEs the
scanner never named (this is how Nmap `-sV` alone yields Apache 2.4.49 → CVE-2021-41773). Each CVE then gets a KEV flag and an
EPSS score. `risk_score = min(10, CVSS + 1.0 if in KEV + EPSS)`.

**Correlation.** `app/services/chains.py` is a small rules engine over in-memory nodes; each rule is a pure function.

| Rule | Fires when |
|---|---|
| `foothold-to-privesc` | One host has a remote foothold (rce/backdoor/auth-bypass/sqli on a port) **and** a local privilege escalation |
| `lateral-movement` | An internet-facing host has a foothold **and** a non-exposed host in the same /24 (/64 for IPv6) has a remote foothold |
| `exploited-on-exposed-service` | An internet-facing service has a CISA-KEV vulnerability |

Chain risk = worst step + 0.5 per extra step + 0.5 if any step is KEV + 0.5 if the entry point is internet-facing (cap 10).
Add a rule by writing one function and appending it to `RULES`.

**Security notes.** XML is parsed with `defusedxml` (XXE / entity-expansion safe), uploads are size-capped (`MAX_UPLOAD_MB`),
payload fields are length- and range-validated, the optional API key uses a constant-time compare, and the container runs as a non-root user.

## Configuration

| Env var | Default | |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./vulncorrelator.db` | Use `postgresql://…` in production (the driver is pinned to psycopg2) |
| `REDIS_URL` | unset | Enables caching and `async_mode` |
| `API_KEY` | unset | Require `X-API-Key` |
| `CACHE_TTL_SECONDS` | `60` | Chain/stats cache TTL. Any ingest or asset PATCH invalidates it immediately |
| `MAX_UPLOAD_MB` | `20` | |
| `INTEL_DIR` | `app/data` | Where `kev.json`, `epss.json`, `cve_catalog.json` live |

## Development

```bash
pip install -r requirements-dev.txt
pytest -q                                        # SQLite
TEST_DATABASE_URL=postgresql://user:pw@localhost/vulntest pytest -q   # same suite on Postgres
ruff check .
alembic revision --autogenerate -m "change"      # after editing app/models.py
python scripts/sync_threat_intel.py              # refresh KEV + EPSS from CISA / FIRST
```

CI (`.github/workflows/ci.yml`) runs lint + tests on Python 3.10-3.12, the suite and migrations against PostgreSQL, and a
`docker compose` smoke test that pushes the sample scans through the real stack, background worker included.

## Known limitations / roadmap

- **The CVE catalog and bundled KEV/EPSS data are a small demo snapshot** (10 well-known CVEs; the EPSS numbers are illustrative).
  Run `scripts/sync_threat_intel.py` for real KEV/EPSS data; for broad CVE coverage, sync NVD into the catalog (not implemented).
- Version matching is a lenient heuristic (`1.0.1f`, `7.2p2`), not a full distro-aware matcher. Backported fixes are not modelled.
- Findings are never auto-closed. A vulnerability that stops appearing keeps its old `last_seen`.
  Filtering on `last_seen`/status is the natural next step.
- Chain rules use a /24 as a stand-in for network adjacency; real segmentation/firewall data would make pivot paths far more precise.
- Ideas: Trivy/Nuclei/OpenVAS parsers, Slack/Jira notifier plugins, per-key auth and RBAC.

## Production readiness

Nothing here is demo-only scaffolding: XML parsing is XXE-safe (`defusedxml`), uploads are size-capped,
every payload field is length/range-validated, the optional API key uses a constant-time compare, the
container runs as a non-root user, CI runs the full suite (lint + tests on Python 3.10-3.12, a real Postgres
pass, and a `docker compose` smoke test) on every change, and `/health` gives an orchestrator a real
liveness/readiness signal. The one thing to swap before a real rollout is the bundled CVE/KEV/EPSS snapshot —
run `scripts/sync_threat_intel.py` (or point `INTEL_DIR` at your own feed) so enrichment reflects current
intel rather than the fixed demo set described above.
