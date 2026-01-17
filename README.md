# Unified Threat Intelligence Platform (UTIP)

**Theme Codename:** "Midnight Vulture"

**Version:** 1.0

---

## Overview

UTIP is an on-premises, mission-critical cybersecurity fusion platform that consolidates threat intelligence extraction, vulnerability-to-TTP correlation, and visualization into a single, scalable architecture.

### Core Capabilities

- **Threat Intelligence Extraction (Barracuda)**: Automated extraction of MITRE ATT&CK techniques from unstructured threat reports (PDF, STIX, text)
- **Vulnerability → TTP Correlation (Piranha)**: Maps CVEs to MITRE ATT&CK techniques via CVE→CWE→CAPEC→Technique pipeline
- **Visualization & Attribution**: MITRE ATT&CK Navigator integration with threat actor attribution
- **Remediation Guidance**: Maps critical techniques to mitigations, hardening guidance, and detection rules

### Color-Coded Intelligence

- **Yellow**: Techniques observed in threat intelligence
- **Blue**: Techniques present in your vulnerabilities
- **Red**: CRITICAL OVERLAP - techniques present in BOTH intel and vulnerabilities

---

## Architecture

### Core Components

| Component | Technology | Role |
|-----------|------------|------|
| Core API ("The Brain") | Python / FastAPI | System state, correlation, authorization |
| Intel Worker ("The Hunter") | Python / Celery | Async intel processing, TTP extraction |
| Database | PostgreSQL | System of record |
| Queue | Redis | Async task broker |
| Identity | Keycloak | OIDC / JWT authentication |
| Frontend ("The Console") | Angular SPA / Nginx | Single pane of glass for analysts |

### Trust Boundary

Everything runs on-premises inside the secure enclave. Future Ollama integration (Phase 4) will be outbound-only with full data sanitization.

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI 0.104+, SQLAlchemy 2.0+
- **Database**: PostgreSQL 15+, Alembic migrations
- **Queue**: Redis 7+, Celery
- **Auth**: Keycloak 23+ (OIDC/JWT)
- **Frontend**: Angular (MITRE ATT&CK Navigator fork)
- **Deployment**: Docker Compose (dev), Kubernetes (prod)

---

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Git

### Quick Start (Development)

```bash
# Clone repository
git clone <repository-url>
cd threat-intel-platform

# Start infrastructure services
docker-compose up -d postgres redis keycloak

# Run database migrations
docker-compose exec backend alembic upgrade head

# Start backend
docker-compose up -d backend

# Verify deployment
curl http://localhost:8000/health
```

### Access Points

- **Core API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Keycloak Admin**: http://localhost:8080 (admin/admin)
- **Frontend**: http://localhost:4200 (Phase 8)

---

## Development Workflow

### Running Migrations

```bash
# Create new migration
docker-compose exec backend alembic revision --autogenerate -m "Description"

# Apply migrations
docker-compose exec backend alembic upgrade head

# Rollback migration
docker-compose exec backend alembic downgrade -1
```

### Accessing Services

```bash
# PostgreSQL shell
docker-compose exec postgres psql -U utip -d utip

# Redis CLI
docker-compose exec redis redis-cli

# Backend logs
docker-compose logs -f backend

# Worker logs (Phase 3+)
docker-compose logs -f worker
```

### Testing

```bash
# Run tests
docker-compose exec backend pytest

# Run tests with coverage
docker-compose exec backend pytest --cov=app --cov-report=html
```

---

## Implementation Phases

### ✅ Phase 1: Foundation & Infrastructure (Weeks 1-2)
- [x] Database schema (9 tables)
- [x] Core API skeleton
- [x] Keycloak authentication
- [x] Docker Compose environment

### 🔄 Phase 2: Vulnerability Pipeline (Weeks 3-4)
- [ ] Nessus parser
- [ ] CVE→TTP mapping
- [ ] Vulnerability endpoints

### 📋 Phase 3: Intel Worker (Weeks 5-6)
- [ ] Celery worker setup
- [ ] PDF/STIX parsers
- [ ] Regex-based TTP extraction

### ⏸️ Phase 4: Ollama Integration (DEFERRED)
- Deferred for later implementation

### 📋 Phase 5: Correlation Engine (Week 8)
- [ ] Layer generation logic
- [ ] Red/Yellow/Blue correlation

### 📋 Phase 6: Attribution Engine (Week 9)
- [ ] Threat actor scoring
- [ ] Attribution endpoint

### 📋 Phase 7: Remediation Engine (Week 10)
- [ ] Mitigation mapping
- [ ] Hardening guidance

### 📋 Phase 8: Frontend Integration (Weeks 11-12)
- [ ] Navigator fork modifications
- [ ] Midnight Vulture design system
- [ ] Attribution & remediation UI

### 📋 Phase 9: Deployment & Hardening (Week 13)
- [ ] Kubernetes manifests
- [ ] Security hardening
- [ ] Monitoring stack

---

## Non-Negotiable Constraints

### Deployment
- Core platform MUST run on-premises
- No SaaS dependency for core functionality
- All data sovereignty preserved
- Database is the single source of truth

### AI Usage
- NO public LLMs (OpenAI, Gemini, Anthropic)
- ONLY private, cloud-hosted Ollama (future)
- Payloads MUST be sanitized
- Ollama is stateless, non-training, no data retention

### Authentication
- On-premises Keycloak
- OIDC protocol
- JWT Bearer tokens
- Role-based access control (analyst, admin, hunter)

### Architectural Boundaries
- Core API never parses PDFs or calls LLMs directly
- Core API owns correlation, not extraction
- Intel Worker owns extraction, not correlation
- Layers are immutable artifacts once generated
- Frontend has NO browser localStorage persistence

---

## API Documentation

API documentation is auto-generated and available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints (by Phase)

**Phase 1 - Foundation**
- `GET /health` - Health check

**Phase 2 - Vulnerability Pipeline**
- `POST /api/v1/vuln/upload` - Upload Nessus scan
- `GET /api/v1/vuln/scans` - List vulnerability scans

**Phase 3 - Intel Processing**
- `POST /api/v1/intel/upload` - Upload threat report
- `GET /api/v1/intel/reports` - List threat reports

**Phase 5 - Correlation**
- `POST /api/v1/layers/generate` - Generate ATT&CK layer

**Phase 6 - Attribution**
- `POST /api/v1/attribution` - Attribute to threat actors

---

## Security

### Authentication Flow

1. User authenticates via Keycloak (OIDC)
2. Keycloak issues JWT access token
3. Client includes token in Authorization header: `Bearer <token>`
4. FastAPI validates JWT signature and claims
5. Request processed with user context and roles

### Roles & Permissions

- **analyst**: Read-only access to intel, scans, layers
- **admin**: Full access to all resources
- **hunter**: Upload and processing permissions

---

## Database Schema

### Core Tables

1. **threat_reports** - Raw intel metadata
2. **extracted_techniques** - Barracuda core value
3. **vulnerability_scans** - Scan metadata
4. **vulnerabilities** - Individual vulns
5. **cve_techniques** - Piranha crown jewel (CVE→TTP mapping)
6. **layers** - Generated layers
7. **layer_techniques** - Layer content
8. **threat_actors** - APT definitions
9. **actor_techniques** - Actor TTPs

See `backend/app/models/database.py` for complete schema.

---

## Contributing

This platform intentionally separates extraction, correlation, and decision-making. That separation is what makes it defensible, auditable, and mission-ready.

**Any system extending this MUST preserve those boundaries.**

---

## License

Internal use only. See LICENSE file for details.

---

## Contact

For issues and questions, contact the development team.

**Classification**: INTERNAL USE ONLY
