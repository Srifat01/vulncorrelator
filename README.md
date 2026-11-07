# 🛡️ VulnCorrelator

### Vulnerability Intelligence · Risk Analysis · Attack Chain Correlation

[![CI](https://github.com/Srifat01/vulncorrelator/actions/workflows/ci.yml/badge.svg)](https://github.com/Srifat01/vulncorrelator/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1)
![Redis](https://img.shields.io/badge/Redis-Task_Queue-DC382D)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

**VulnCorrelator** is an API-first vulnerability intelligence platform that transforms raw vulnerability scanner output into structured, enriched, and actionable security intelligence.

It ingests vulnerability reports from multiple security tools, normalizes and deduplicates findings across scanners, enriches vulnerabilities with exploit intelligence, associates findings with network assets, and identifies potentially exploitable attack chains.

Rather than treating vulnerabilities as isolated security findings, VulnCorrelator focuses on understanding how individual weaknesses can combine to create broader attack opportunities.

> **From isolated vulnerability findings to correlated attack intelligence.**

---

## 📸 Project Screenshots

VulnCorrelator includes a web-based operator dashboard for inspecting discovered assets, vulnerability findings, risk levels, and correlated attack paths.

### Figure 1. Dashboard Overview

![VulnCorrelator Dashboard](figs/f1.png)

### Figure 2. Vulnerability Intelligence

![Vulnerability Intelligence](figs/f2.png)

### Figure 3. Asset Analysis

![Asset Analysis](figs/f3.png)

### Figure 4. Attack Chain Correlation

![Attack Chain Correlation](figs/f4.png)

### Figure 5. Security Analysis Interface

![Security Analysis Interface](figs/f5.png)

---

## ⚡ Core Features

| Feature | Description |
|---|---|
| Multi-source ingestion | Supports Nmap XML, Nessus and JSON reports |
| Finding normalization | Converts inconsistent scanner output into a unified data model |
| Intelligent deduplication | Uses deterministic SHA-256 fingerprints to identify duplicate findings |
| Vulnerability enrichment | Enriches findings with CVE, CVSS, CISA KEV and EPSS intelligence |
| Asset intelligence | Associates vulnerabilities with hosts, services, ports and network exposure |
| Attack-chain correlation | Identifies potential foothold, privilege escalation and lateral movement paths |
| Asynchronous processing | Uses Redis and RQ workers for background scan ingestion |
| Risk prioritization | Calculates risk scores to prioritize critical vulnerabilities |
| REST API | Provides endpoints for ingestion, asset management and security analysis |
| Web dashboard | Visualizes assets, vulnerabilities, security statistics and attack chains |

---

## 🏗️ System Architecture

VulnCorrelator follows a modular architecture consisting of an API layer, processing pipeline, persistent database, asynchronous task queue, and correlation engine.

```mermaid
flowchart TD
    A[Nmap XML] --> D[FastAPI]
    B[Nessus Report] --> D
    C[JSON Report] --> D

    D --> E[Parser and Normalizer]
    E --> F[Fingerprinting and Deduplication]
    F --> G[Vulnerability Enrichment]

    G --> H[(PostgreSQL)]
    G --> I[Redis Queue]

    I --> J[Background Worker]
    J --> H

    H --> K[Attack Chain Engine]
    K --> L[Risk Analysis]

    L --> M[REST API]
    M --> N[Web Dashboard]
    M --> O[External API Clients]

    H --> P[Redis Cache]
    P --> M
```

### Technology Stack

| Layer | Technologies |
|---|---|
| Programming language | Python 3.10+ |
| Backend framework | FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy 2 |
| Database migrations | Alembic |
| Task queue | Redis, RQ |
| Data validation | Pydantic |
| Containerization | Docker, Docker Compose |
| Testing | Pytest |
| Linting | Ruff |
| Frontend | HTML, CSS, JavaScript |

---

## 🔬 How It Works

### 1. Vulnerability Ingestion

The platform accepts vulnerability scan reports from multiple security tools.

Supported input formats:

- Nmap XML
- Nessus `.nessus`
- JSON vulnerability reports

The ingestion pipeline extracts relevant information, including:

- IP addresses and hostnames
- Operating systems
- Open ports and protocols
- Detected services and products
- Vulnerability identifiers
- Severity and CVSS information

### 2. Normalization

Different vulnerability scanners frequently represent the same service or vulnerability using different names and formats.

VulnCorrelator converts these findings into a common representation.

Examples include:

- Service alias normalization (`www` → `http`)
- Product identification and canonical CPE mapping
- CPE 2.2 and CPE 2.3 parsing
- CVSS score normalization
- Severity classification normalization

This allows findings from different scanners to be compared and correlated.

### 3. Intelligent Deduplication

Every vulnerability finding receives a deterministic SHA-256 fingerprint.

For CVE-based findings, the identity is based on:

`Asset + Port + Protocol + CVE`

For findings without a CVE identifier, the fingerprint uses:

`Asset + Port + Protocol + Service + Version + Normalized Title`

A unique database constraint and PostgreSQL conflict handling prevent duplicate findings, including during concurrent ingestion.

Repeated observations update existing records:

- Highest CVSS score is retained.
- Scanner sources, tags and evidence accumulate.
- `last_seen` is updated.
- `first_seen` remains unchanged.

### 4. Vulnerability Intelligence Enrichment

Vulnerability findings are enriched using available threat intelligence datasets.

| Intelligence Source | Purpose |
|---|---|
| CVE | Identifies publicly disclosed vulnerabilities |
| CVSS | Represents vulnerability severity |
| CISA KEV | Identifies vulnerabilities known to be exploited in the wild |
| EPSS | Estimates the probability of exploitation in the next 30 days |
| CPE | Supports product and version identification |

The system also uses a bundled CVE catalog to identify certain vulnerabilities through product and version matching, even when a scanner does not explicitly report the CVE.

**Risk calculation:**

`Risk = min(10, CVSS + KEV Bonus + EPSS)`

Where:

- CVSS represents the base severity score.
- KEV bonus adds 1.0 when the vulnerability appears in the CISA KEV catalog.
- EPSS contributes its probability value.

The resulting score is capped at 10.

### 5. Attack Chain Correlation

This is the central analytical component of VulnCorrelator.

Instead of displaying vulnerabilities as isolated findings, the correlation engine evaluates combinations of weaknesses to identify potential attack paths.

The current rule-based engine implements three correlation rules:

| Rule | Detection Logic |
|---|---|
| `foothold-to-privesc` | Identifies a remote foothold combined with local privilege escalation on the same host |
| `lateral-movement` | Identifies a potentially compromised internet-facing host and another vulnerable host within the same network |
| `exploited-on-exposed-service` | Identifies CISA KEV vulnerabilities on internet-facing services |

Each detected attack chain contains:

- Risk score
- Severity classification
- Affected assets
- Ordered attack steps
- Plain-English explanation
- Supporting vulnerability evidence

The correlation engine uses modular rules, allowing additional detection logic to be introduced independently.

---

## 🚀 Installation and Quick Start

VulnCorrelator is containerized with Docker Compose.

The entire application can be started with a single command.

### Prerequisites

Install:

- Docker Engine
- Docker Compose v2
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Srifat01/vulncorrelator.git

cd vulncorrelator
```

### 2. Configure environment variables

Create your local environment file:

```bash
cp .env.example .env
```

Edit `.env`:

```env
POSTGRES_PASSWORD=your_strong_database_password
API_KEY=your_private_api_key
MAX_UPLOAD_MB=20
CACHE_TTL_SECONDS=60
```

Keep your `.env` file private. Never upload credentials or API keys to GitHub.

### 3. Start the application

```bash
docker compose up --build -d
```

Docker Compose automatically starts:

| Service | Responsibility |
|---|---|
| PostgreSQL | Persistent vulnerability and asset storage |
| Redis | Background task queue and caching |
| FastAPI | REST API and dashboard |
| RQ Worker | Asynchronous scan processing |

Database migrations are applied automatically when the API starts.

### 4. Verify the services

```bash
docker compose ps
```

Inspect application logs:

```bash
docker compose logs -f
```

### 5. Access the application

| Component | URL |
|---|---|
| Web Dashboard | http://localhost:8000/ui/ |
| Swagger API Documentation | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |

---

## 🧪 Testing with Sample Vulnerability Scans

The repository includes sample Nmap and Nessus reports under the `samples/` directory.

### Upload an Nmap scan

```bash
curl -F format=nmap \
-F async_mode=true \
-F file=@samples/nmap_scan.xml \
http://localhost:8000/ingest/upload
```

The request is processed asynchronously through Redis and the background worker.

### Upload a Nessus scan

```bash
curl -F format=nessus \
-F file=@samples/nessus_scan.nessus \
http://localhost:8000/ingest/upload
```

This example processes the report synchronously.

### Retrieve discovered assets

```bash
curl http://localhost:8000/assets
```

### Retrieve vulnerability findings

```bash
curl "http://localhost:8000/vulnerabilities?limit=10"
```

### Retrieve high-risk attack chains

```bash
curl "http://localhost:8000/chains?min_risk=9"
```

### Mark an asset as internet-facing

```bash
curl -X PATCH http://localhost:8000/assets/1 \
-H "Content-Type: application/json" \
-d '{"internet_facing": true}'
```

### Retrieve lateral movement chains

```bash
curl "http://localhost:8000/chains?rule=lateral-movement"
```

When API authentication is enabled, include:

```bash
-H "X-API-Key: your_private_api_key"
```

---

## 📡 REST API Reference

VulnCorrelator exposes its functionality through a RESTful API built with FastAPI.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/ingest` | Ingest JSON vulnerability reports |
| POST | `/ingest/upload` | Upload Nmap or Nessus reports |
| GET | `/reports` | Retrieve ingestion history |
| GET | `/reports/{id}` | Retrieve individual report status |
| GET | `/assets` | List discovered assets |
| GET | `/assets/{id}` | Retrieve asset information |
| PATCH | `/assets/{id}` | Update asset metadata |
| GET | `/assets/{id}/vulnerabilities` | Retrieve asset vulnerabilities |
| GET | `/assets/{id}/services` | Retrieve detected services |
| GET | `/vulnerabilities` | Retrieve network-wide vulnerability findings |
| GET | `/chains` | Retrieve correlated attack chains |
| GET | `/chains/{id}` | Retrieve individual attack chain |
| GET | `/stats` | Retrieve security statistics |
| GET | `/health` | Check database and Redis health |

### Supported API Filters

**Assets**
- `internet_facing`
- `min_risk`

**Vulnerabilities**
- `min_risk`
- `severity`
- `cve_id`
- `kev_only`

**Attack Chains**
- `min_risk`
- `asset_id`
- `rule`

All list endpoints support pagination through `limit` and `offset`.

Interactive API documentation is available at:

`http://localhost:8000/docs`

---

## 📊 Web Dashboard

The project includes a static operator dashboard served directly by FastAPI.

No separate frontend build process or additional frontend service is required.

### Dashboard Components

**Overview**
- Overall security statistics
- Risk indicators
- Vulnerability severity distribution

**Asset Register**
- Discovered network assets
- Hostnames and IP addresses
- Internet-facing asset information
- Risk-based asset prioritization

**Finding Log**
- Vulnerability findings
- CVE identifiers
- Severity and risk information
- Scanner evidence

**Attack Chain Board**
- Correlated attack paths
- Attack steps and relationships
- Risk scores
- Plain-English explanations

**Scan Ingestion**
- Drag-and-drop report uploads
- Nmap and Nessus support
- Upload progress
- Ingestion report status

The dashboard communicates with the API through the same origin, avoiding the need for separate CORS configuration.

If the API is unavailable, the dashboard can display bundled demonstration data. It indicates when demonstration data is being displayed instead of live results.

---

## 🔐 Security Considerations

Security is considered throughout the ingestion and processing pipeline.

Implemented protections include:

- XML parsing with `defusedxml` to mitigate XML external entity attacks.
- Upload size restrictions through `MAX_UPLOAD_MB`.
- Input validation and field-length constraints.
- Optional API key authentication.
- Constant-time API key comparison.
- Non-root container execution.
- Database-backed persistence.
- Environment-based configuration.

**Deployment recommendation:** Configure strong database credentials and enable API authentication before exposing the service to an external network.

The default Docker Compose database password is intended for local development only.

---

## ⚙️ Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./vulncorrelator.db` | Database connection URL |
| `REDIS_URL` | Unset | Enables caching and asynchronous ingestion |
| `API_KEY` | Unset | Enables API key authentication |
| `CACHE_TTL_SECONDS` | `60` | Cache expiration time |
| `MAX_UPLOAD_MB` | `20` | Maximum upload size |
| `INTEL_DIR` | `app/data` | Threat intelligence dataset directory |
| `POSTGRES_PASSWORD` | `vulnpass` | Docker PostgreSQL password |

Docker Compose configures PostgreSQL and Redis automatically.

When `API_KEY` is configured, requests must include the `X-API-Key` header, except for `/health`.

---

## 🧰 Development

### Run without Docker

Install the development dependencies:

```bash
pip install -r requirements-dev.txt
```

Apply database migrations:

```bash
alembic upgrade head
```

Start the development server:

```bash
uvicorn app.main:app --reload
```

SQLite is used by default for local development.

Without Redis:
- Synchronous ingestion remains available.
- Caching is skipped.
- Asynchronous ingestion is unavailable and returns HTTP 503.

### Run automated tests

```bash
pytest -q
```

### Run linting

```bash
ruff check .
```

### Run tests against PostgreSQL

```bash
TEST_DATABASE_URL=postgresql://user:password@localhost:5432/vulntest pytest -q
```

### Create a database migration

After modifying database models:

```bash
alembic revision --autogenerate -m "describe_change"
```

### Refresh threat intelligence

```bash
python scripts/sync_threat_intel.py
```

This script refreshes the CISA KEV and FIRST EPSS datasets.

---

## 🔄 Continuous Integration

VulnCorrelator includes an automated GitHub Actions workflow.

Workflow location:

`.github/workflows/ci.yml`

The CI pipeline runs automatically on pushes and pull requests.

### CI Jobs

| Job | Description |
|---|---|
| Python Tests | Runs tests and Ruff linting on Python 3.10, 3.11 and 3.12 |
| PostgreSQL Tests | Executes the test suite against PostgreSQL and validates migrations |
| Docker Compose Smoke Test | Builds the complete stack and tests real scan ingestion and attack-chain detection |

The Docker smoke test verifies that the API, PostgreSQL, Redis and background worker operate together.

Workflow status:

[View GitHub Actions](https://github.com/Srifat01/vulncorrelator/actions)

---

## ⚠️ Known Limitations

VulnCorrelator is an evolving engineering project. Its current implementation has several limitations:

- The bundled CVE catalog contains a small demonstration dataset.
- Bundled EPSS values are illustrative rather than live intelligence.
- Broad NVD synchronization is not yet implemented.
- Version matching uses heuristic comparisons and does not fully account for distribution-specific backported fixes.
- Vulnerability auto-closure is not implemented.
- Lateral movement correlation currently uses subnet proximity as a simplified assumption.
- Attack-chain detection relies on predefined rules rather than a complete graph-based attack simulation model.

These limitations provide opportunities for future development.

---

## 🗺️ Future Roadmap

Potential improvements include:

- [ ] OpenVAS, Trivy and Nuclei scanner integrations.
- [ ] Broader NVD vulnerability catalog integration.
- [ ] Advanced asset fingerprinting.
- [ ] Network segmentation and firewall-aware attack-path analysis.
- [ ] MITRE ATT&CK technique mapping.
- [ ] Vulnerability lifecycle tracking and automatic closure.
- [ ] Graph-based attack-path visualization.
- [ ] Role-based access control.
- [ ] Per-user API authentication and authorization.
- [ ] Slack and Jira integrations.
- [ ] Historical risk analysis and security trend visualization.

---

## 🤝 Contributing

Contributions, suggestions and bug reports are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Run the test suite.
5. Submit a pull request.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## 👨‍💻 Author

**Your Name**

Computer Science & Engineering

GitHub: [Srifat01](https://github.com/Srifat01)

---

<p align="center">
  <b>VulnCorrelator</b><br>
  Turning isolated vulnerabilities into actionable security intelligence.
</p>
