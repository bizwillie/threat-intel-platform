# UTIP Deployment Guide

## Phase 1: Deployment Steps

### Prerequisites

1. **Install Docker Desktop**
   - Download from: https://www.docker.com/products/docker-desktop/
   - Install and start Docker Desktop
   - Verify installation: `docker --version` and `docker compose version`

2. **Verify Git Installation**
   - Check: `git --version`
   - Repository already initialized with Phase 1 code

---

## Deployment Instructions

### Step 1: Start Infrastructure Services

```bash
# Navigate to project directory
cd /c/Users/matt2/OneDrive/Documents/TIP/threat-intel-platform

# Start PostgreSQL, Redis, and Keycloak
docker compose up -d postgres redis keycloak

# Wait for services to be healthy (may take 1-2 minutes for Keycloak)
docker compose ps

# View logs if needed
docker compose logs -f keycloak
```

**Expected output:** All services should show as "healthy" or "running"

### Step 2: Run Database Migrations

```bash
# Build and start the backend service
docker compose up -d backend

# Run Alembic migrations to create all 9 tables
docker compose exec backend alembic upgrade head

# Verify tables were created
docker compose exec postgres psql -U utip -d utip -c "\dt"
```

**Expected output:** List of 9 tables:
- threat_reports
- extracted_techniques
- vulnerability_scans
- vulnerabilities
- cve_techniques
- layers
- layer_techniques
- threat_actors
- actor_techniques

### Step 3: Verify API is Running

```bash
# Check backend logs
docker compose logs backend

# Test health endpoint
curl http://localhost:8000/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "service": "utip-core-api",
  "version": "1.0.0",
  "theme": "Midnight Vulture"
}
```

### Step 4: Configure Keycloak

1. **Access Keycloak Admin Console**
   - URL: http://localhost:8080
   - Username: `admin`
   - Password: `admin`

2. **Create UTIP Realm**
   - Click "Create Realm"
   - Realm name: `utip`
   - Enable: Yes
   - Save

3. **Create Client**
   - In UTIP realm, go to Clients
   - Click "Create Client"
   - Client ID: `utip-api`
   - Client Protocol: `openid-connect`
   - Save
   - **Settings tab:**
     - Access Type: `confidential`
     - Valid Redirect URIs: `http://localhost:8000/*`
     - Web Origins: `http://localhost:4200`
     - Save
   - **Credentials tab:**
     - Copy the Client Secret (needed for `.env`)

4. **Create Roles**
   - Go to Realm Roles
   - Create role: `analyst` (description: "Read-only access")
   - Create role: `admin` (description: "Full access")
   - Create role: `hunter` (description: "Upload and processing")

5. **Create Test User**
   - Go to Users → Add User
   - Username: `test-analyst`
   - Email: `analyst@utip.local`
   - Save
   - **Credentials tab:**
     - Set Password: `analyst123` (temporary: OFF)
   - **Role Mappings tab:**
     - Assign role: `analyst`

### Step 5: Update Environment Variables

```bash
# Create .env file from example
cp backend/.env.example backend/.env

# Edit backend/.env with actual values:
# - KEYCLOAK_CLIENT_SECRET=<secret from step 4.3>
# - SECRET_KEY=<generate a random 32-character string>
```

### Step 6: Restart Backend

```bash
# Restart backend to pick up new environment variables
docker compose restart backend

# Verify it's running
docker compose logs backend
```

### Step 7: Test Authentication

```bash
# Get JWT token from Keycloak
curl -X POST http://localhost:8080/realms/utip/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=utip-api" \
  -d "client_secret=<YOUR_CLIENT_SECRET>" \
  -d "grant_type=password" \
  -d "username=test-analyst" \
  -d "password=analyst123"

# Extract access_token from response and test protected endpoint
curl http://localhost:8000/api/v1/me \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Expected response:**
```json
{
  "username": "test-analyst",
  "email": "analyst@utip.local",
  "roles": ["analyst"],
  "user_id": "<uuid>"
}
```

---

## Phase 1 Validation Checklist

- [ ] Docker services running (postgres, redis, keycloak, backend)
- [ ] Database migrations applied successfully
- [ ] All 9 tables created in PostgreSQL
- [ ] API health endpoint responds
- [ ] Keycloak realm and client configured
- [ ] Test user created with analyst role
- [ ] JWT token can be obtained from Keycloak
- [ ] Protected endpoint validates JWT correctly
- [ ] `/api/v1/me` returns user information

---

## Troubleshooting

### Keycloak not starting
```bash
# Check logs
docker compose logs keycloak

# Common issue: PostgreSQL not ready yet
# Wait 30 seconds and restart:
docker compose restart keycloak
```

### Backend can't connect to database
```bash
# Check DATABASE_URL in .env
# Verify PostgreSQL is running:
docker compose ps postgres

# Check PostgreSQL logs:
docker compose logs postgres
```

### JWT validation fails
```bash
# Verify Keycloak URL is accessible from backend container:
docker compose exec backend curl http://keycloak:8080/realms/utip

# Check KEYCLOAK_CLIENT_SECRET matches Keycloak configuration
```

### Port conflicts
If ports 5432, 6379, 8000, or 8080 are already in use:
```yaml
# Edit docker-compose.yml and change port mappings:
# Example: "8001:8000" instead of "8000:8000"
```

---

## API Documentation

Once the backend is running, access interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

These provide:
- Complete API endpoint documentation
- Request/response schemas
- "Try it out" functionality
- Authentication testing

---

---

## Phase 2: Vulnerability Pipeline (✅ COMPLETE)

### Overview

Phase 2 implements the vulnerability ingestion pipeline, enabling UTIP to parse Nessus scans and map CVEs to MITRE ATT&CK techniques. This creates the **blue layer** - techniques you're vulnerable to.

### Prerequisites

- Phase 1 deployment complete
- User with `hunter` role created (for uploads)

### Add Hunter Role to Test User

```bash
# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=admin" | \
  python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

# Get test user ID
USER_ID=$(curl -s "http://localhost:8080/admin/realms/utip/users?username=test-analyst" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | \
  python -c "import sys, json; print(json.load(sys.stdin)[0]['id'])")

# Get hunter role ID
ROLE_ID=$(curl -s "http://localhost:8080/admin/realms/utip/roles/hunter" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | \
  python -c "import sys, json; print(json.load(sys.stdin)['id'])")

# Assign hunter role
curl -X POST "http://localhost:8080/admin/realms/utip/users/$USER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\":\"$ROLE_ID\",\"name\":\"hunter\"}]"
```

### Phase 2 Validation

#### 1. Upload a Nessus Scan

```bash
# Get JWT token
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/utip/protocol/openid-connect/token" \
  -d "client_id=utip-api" \
  -d "client_secret=TPVGvZvRD5U73Y8yhZjvR108UTAEkn5d" \
  -d "grant_type=password" \
  -d "username=test-analyst" \
  -d "password=analyst123" | \
  python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

# Upload test scan
curl -X POST "http://localhost:8000/api/v1/vuln/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test_scan.nessus"
```

**Expected response:**
```json
{
  "scan_id": "uuid",
  "filename": "test_scan.nessus",
  "scan_date": "2024-01-18T13:10:00Z",
  "uploaded_by": "test-analyst",
  "vulnerability_count": 8,
  "unique_cve_count": 8,
  "technique_count": 4
}
```

#### 2. View Blue Layer Techniques

```bash
# List all scans
curl -s -X GET "http://localhost:8000/api/v1/vuln/scans" \
  -H "Authorization: Bearer $TOKEN"

# Get techniques for a specific scan (blue layer)
curl -s -X GET "http://localhost:8000/api/v1/vuln/scans/{scan_id}/techniques" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected blue layer response:**
```json
{
  "scan_id": "uuid",
  "techniques": [
    {
      "technique_id": "T1003.006",
      "confidence": 0.98,
      "color": "blue",
      "source_cves": ["CVE-2020-1472"]
    },
    {
      "technique_id": "T1059",
      "confidence": 0.95,
      "color": "blue",
      "source_cves": ["CVE-2021-44228"]
    }
  ],
  "total": 4
}
```

#### 3. Verify Database Mappings

```bash
# Check CVE→Technique mappings
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT cve_id, technique_id, confidence, source FROM cve_techniques ORDER BY confidence DESC;"

# Check vulnerabilities
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT cve_id, severity, cvss_score, asset FROM vulnerabilities ORDER BY cvss_score DESC LIMIT 5;"
```

### Phase 2 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/vuln/upload` | POST | hunter | Upload .nessus file |
| `/api/v1/vuln/scans` | GET | analyst | List all scans |
| `/api/v1/vuln/scans/{id}` | GET | analyst | Get scan details |
| `/api/v1/vuln/scans/{id}/techniques` | GET | analyst | Get blue layer |

### Phase 2 Validation Checklist

- [ ] Hunter role added to test user
- [ ] Nessus scan uploads successfully
- [ ] Vulnerabilities stored in database
- [ ] CVE→Technique mappings created (Piranha engine working)
- [ ] Blue layer techniques queryable via API
- [ ] Confidence scores present for all mappings
- [ ] NVD API integration working (live CVE lookups)

### Troubleshooting Phase 2

#### Upload fails with 403 Forbidden
```bash
# Verify user has hunter role
curl -s "http://localhost:8000/api/v1/me" -H "Authorization: Bearer $TOKEN"

# Response should include "hunter" in roles array
```

#### No technique mappings generated
```bash
# Check backend logs for CVE mapper errors
docker compose logs backend | grep -i "cve_mapper"

# Verify NVD API is accessible
docker compose exec backend curl https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
```

#### Database migration needed
```bash
# If vulnerabilities table is missing new columns:
docker compose exec backend alembic upgrade head
```

---

## Next Steps After Phase 2

Once Phase 2 validation is complete:

**Phase 3: Intel Worker** (Weeks 5-6)
- Set up Celery worker
- Implement PDF/STIX parsers
- Build regex-based TTP extraction (yellow layer)

**Phase 5: Correlation Engine** (Week 8)
- Combine blue (vulnerability) + yellow (intel) = red (critical overlap)

See `PHASE2_COMPLETION_REPORT.md` for detailed Phase 2 documentation.

---

## Phase 2.5: Optional Feature Enhancements (✅ COMPLETE)

### Overview

Phase 2.5 introduces **optional enhancements** to the vulnerability pipeline controlled by feature flags. All features are backward compatible and gracefully degrade when disabled.

**Key Benefits**:
- Control external dependencies (disable for air-gapped environments)
- Scale features based on resources
- Customize mapping coverage (15 core CWEs vs. 400+ extended)
- Maintain data sovereignty

### Feature Flags

| Feature | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| NVD API | `ENABLE_NVD_API` | `true` | Query NVD for live CVE data |
| Redis Cache | `ENABLE_REDIS_CACHE` | `false` | Persistent CVE caching |
| CAPEC Database | `ENABLE_CAPEC_DATABASE` | `false` | Full CAPEC attack patterns |
| STIX Validation | `ENABLE_ATTACK_STIX_VALIDATION` | `false` | Validate techniques vs. ATT&CK |
| Extended CWE | `ENABLE_EXTENDED_CWE_MAPPINGS` | `false` | 400+ CWE mappings vs. core 15 |

### Configuration Examples

**Air-Gapped (No Internet)**:
```env
ENABLE_NVD_API=false
ENABLE_CAPEC_DATABASE=false
ENABLE_ATTACK_STIX_VALIDATION=false
ENABLE_REDIS_CACHE=false
ENABLE_EXTENDED_CWE_MAPPINGS=false
```

**Recommended Production**:
```env
ENABLE_NVD_API=true
NVD_API_KEY=your-api-key-here
ENABLE_REDIS_CACHE=true
ENABLE_ATTACK_STIX_VALIDATION=true
ENABLE_EXTENDED_CWE_MAPPINGS=false
ENABLE_CAPEC_DATABASE=false
```

### Check Feature Status

```bash
curl http://localhost:8000/api/v1/vuln/features \
  -H "Authorization: Bearer $TOKEN"
```

**Response** shows which features are enabled and their statistics:
```json
{
  "phase": "2.5",
  "features": {
    "nvd_api": {
      "enabled": true,
      "has_api_key": true,
      "cache_ttl_days": 7,
      "in_memory_cache_size": 12
    },
    "redis_cache": {
      "enabled": true,
      "connected": true,
      "total_keys": 45,
      "hit_rate": 87.5
    }
  }
}
```

### Enabling Optional Features

#### 1. Enable Redis Cache

Already deployed in `docker-compose.yml`:
```bash
# Update .env
ENABLE_REDIS_CACHE=true

# Restart backend
docker compose restart backend
```

#### 2. Enable STIX Validation

Download ATT&CK STIX data:
```bash
mkdir -p data
wget -O data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Update `docker-compose.yml`:
```yaml
services:
  backend:
    volumes:
      - ./data:/app/data:ro
```

Update `.env`:
```env
ENABLE_ATTACK_STIX_VALIDATION=true
ATTACK_STIX_PATH=/app/data/enterprise-attack.json
```

Restart:
```bash
docker compose build backend
docker compose up -d backend
```

#### 3. Get NVD API Key

Without key: 5 requests / 30 seconds
With key: 50 requests / 30 seconds

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Register and receive key via email
3. Add to `.env`:
   ```env
   NVD_API_KEY=your-api-key-here
   ```
4. Restart backend: `docker compose restart backend`

### Phase 2.5 Validation

```bash
# Check feature status
curl -s http://localhost:8000/api/v1/vuln/features \
  -H "Authorization: Bearer $TOKEN" | jq

# Upload scan - should use enabled features
curl -X POST http://localhost:8000/api/v1/vuln/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test_scan.nessus"
```

### Documentation

See [`PHASE2.5_FEATURE_FLAGS.md`](PHASE2.5_FEATURE_FLAGS.md) for:
- Detailed feature descriptions
- Performance impact analysis
- Security considerations
- Troubleshooting guide
- Migration instructions

---

**Classification**: INTERNAL USE ONLY
**Theme**: Midnight Vulture
