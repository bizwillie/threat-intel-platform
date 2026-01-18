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

## Phase 3: Intel Worker - Threat Intelligence Ingestion (✅ COMPLETE)

### Overview

Phase 3 implements the **Intel Worker** - an asynchronous Celery-based worker that:
- Processes threat intelligence documents (PDF, STIX, text)
- Extracts MITRE ATT&CK techniques using regex patterns
- Generates the **yellow layer** (techniques observed in threat intel)
- Stores extracted techniques in the database

**Key Feature**: Regex-based TTP extraction - high-confidence, deterministic, no LLM required (perfect for air-gapped environments)

### Architecture

```
User uploads PDF/STIX → Core API stores file → Queues Celery task
                                                       ↓
Intel Worker picks up task → Parses document → Runs regex extraction → Stores techniques
```

### Deployment

#### 1. Start Celery Worker

The worker is already configured in `docker-compose.yml`:

```bash
# Build and start the worker
docker compose up -d --build worker

# Verify worker is running
docker compose ps worker

# View worker logs
docker compose logs -f worker
```

**Expected output**: Worker should show as "running" and log:
```
[tasks]
  . tasks.document_processing.process_threat_report
  . tasks.document_processing.get_processing_statistics
```

#### 2. Verify Worker Health

```bash
# Check Celery worker status
docker compose exec worker celery -A celery_app inspect active

# Check registered tasks
docker compose exec worker celery -A celery_app inspect registered

# Check active queues
docker compose exec worker celery -A celery_app inspect active_queues
```

**Expected output**: Worker should be connected to the `intel` queue.

### Testing Phase 3

#### 1. Create Test Document

Create a simple threat intelligence text file:

```bash
cat > test_threat_report.txt <<EOF
APT29 Threat Intelligence Report

The threat actors deployed ransomware to encrypt files across the network.
They used PowerShell to execute malicious scripts and disabled antivirus software.
The attack began with a spear-phishing email containing a weaponized PDF attachment.
The attackers established C2 communication via HTTP beaconing.
They performed network scanning to discover additional systems.
EOF
```

**Expected Techniques to Extract**:
- T1486 (Data Encrypted for Impact) - ransomware
- T1059.001 (PowerShell) - PowerShell
- T1562.001 (Disable Antivirus) - disabled antivirus
- T1566.001 (Spearphishing Attachment) - spear-phishing, weaponized PDF
- T1071.001 (Web Protocols) - HTTP
- T1046 (Network Service Scanning) - network scanning

#### 2. Upload Threat Intelligence

```bash
# Get authentication token (use hunter role)
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/utip/protocol/openid-connect/token" \
  -d "client_id=utip-api" \
  -d "client_secret=<client-secret>" \
  -d "grant_type=password" \
  -d "username=test-hunter" \
  -d "password=<password>" | jq -r '.access_token')

# Upload threat intel document
curl -X POST "http://localhost:8000/api/v1/intel/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@test_threat_report.txt"
```

**Expected response** (202 Accepted):
```json
{
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "test_threat_report.txt",
  "status": "queued",
  "message": "Threat report uploaded and queued for processing"
}
```

#### 3. Check Processing Status

```bash
# Use the report_id from the upload response
REPORT_ID="550e8400-e29b-41d4-a716-446655440000"

# Check status (should transition: queued → processing → complete)
curl -s "http://localhost:8000/api/v1/intel/reports/$REPORT_ID/status" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected response**:
```json
{
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "test_threat_report.txt",
  "status": "complete",
  "created_at": "2024-01-18T14:30:00Z",
  "processed_at": "2024-01-18T14:30:05Z",
  "error_message": null,
  "techniques_count": 6
}
```

#### 4. View Extracted Techniques (Yellow Layer)

```bash
# Get extracted techniques
curl -s "http://localhost:8000/api/v1/intel/reports/$REPORT_ID/techniques" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected response**:
```json
[
  {
    "technique_id": "T1046",
    "confidence": 0.90,
    "evidence": "...performed network scanning to discover...",
    "extraction_method": "regex"
  },
  {
    "technique_id": "T1059.001",
    "confidence": 0.90,
    "evidence": "...used PowerShell to execute malicious scripts...",
    "extraction_method": "regex"
  },
  {
    "technique_id": "T1071.001",
    "confidence": 0.90,
    "evidence": "...C2 communication via HTTP beaconing...",
    "extraction_method": "regex"
  },
  {
    "technique_id": "T1486",
    "confidence": 0.95,
    "evidence": "...deployed ransomware to encrypt files...",
    "extraction_method": "regex"
  },
  {
    "technique_id": "T1562.001",
    "confidence": 0.90,
    "evidence": "...disabled antivirus software...",
    "extraction_method": "regex"
  },
  {
    "technique_id": "T1566.001",
    "confidence": 0.90,
    "evidence": "...spear-phishing email containing a weaponized PDF...",
    "extraction_method": "regex"
  }
]
```

#### 5. View All Reports

```bash
# List all threat intelligence reports
curl -s "http://localhost:8000/api/v1/intel/reports" \
  -H "Authorization: Bearer $TOKEN" | jq
```

#### 6. Get Processing Statistics

```bash
# Get worker processing statistics
curl -s "http://localhost:8000/api/v1/intel/statistics" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected response**:
```json
{
  "status_breakdown": {
    "complete": 1,
    "processing": 0,
    "queued": 0,
    "failed": 0
  },
  "total_techniques_extracted": 6,
  "average_techniques_per_report": 6.0,
  "timestamp": "2024-01-18T14:35:00Z"
}
```

### Phase 3 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/intel/upload` | POST | hunter | Upload threat intel document |
| `/api/v1/intel/reports` | GET | analyst | List all reports |
| `/api/v1/intel/reports/{id}` | GET | analyst | Get report with techniques |
| `/api/v1/intel/reports/{id}/status` | GET | analyst | Get processing status |
| `/api/v1/intel/reports/{id}/techniques` | GET | analyst | Get yellow layer techniques |
| `/api/v1/intel/statistics` | GET | analyst | Get processing statistics |

### Supported File Types

| Extension | Type | Parser |
|-----------|------|--------|
| `.pdf` | PDF Reports | pdfplumber |
| `.json`, `.stix`, `.stix2` | STIX Bundles | stix2 library |
| `.txt` | Plain Text | Built-in |

**Max File Size**: 50 MB

### Phase 3 Validation Checklist

- [ ] Celery worker running and connected to Redis
- [ ] Test threat intel document uploads successfully
- [ ] Report status transitions: queued → processing → complete
- [ ] Techniques extracted and stored in `extracted_techniques` table
- [ ] Yellow layer techniques queryable via API
- [ ] Confidence scores present for all extracted techniques
- [ ] Worker logs show successful processing
- [ ] Uploaded files cleaned up after processing

### Troubleshooting Phase 3

#### Worker not processing tasks

**Symptoms**: Reports stuck in "queued" status

**Check**:
```bash
# Ensure worker is running
docker compose ps worker

# Check worker logs
docker compose logs worker

# Verify Redis connection
docker compose exec worker celery -A celery_app inspect ping
```

**Fix**: Restart worker
```bash
docker compose restart worker
```

#### Processing fails with error

**Symptoms**: Report status = "failed"

**Check**:
```bash
# View worker error logs
docker compose logs worker | grep -i error

# Check specific report error
curl -s "http://localhost:8000/api/v1/intel/reports/$REPORT_ID/status" \
  -H "Authorization: Bearer $TOKEN" | jq '.error_message'
```

**Common Causes**:
- Corrupted PDF file → Use valid PDF
- File too large → Max 50 MB
- Unsupported file type → Only .pdf, .json, .stix, .txt

#### No techniques extracted

**Symptoms**: techniques_count = 0

**Causes**:
- Document doesn't contain technique indicators
- Text extraction failed (scanned PDF with no text)

**Check**: View worker logs for extraction details
```bash
docker compose logs worker | grep "Extracted.*techniques"
```

### Monitoring Worker Performance

```bash
# View active Celery tasks
docker compose exec worker celery -A celery_app inspect active

# View worker stats
docker compose exec worker celery -A celery_app inspect stats

# Monitor queue depth (Redis)
docker compose exec redis redis-cli LLEN intel
```

### Database Queries

```bash
# Check extracted techniques
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT technique_id, COUNT(*) FROM extracted_techniques GROUP BY technique_id ORDER BY COUNT(*) DESC LIMIT 10;"

# Check reports by status
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT status, COUNT(*) FROM threat_reports GROUP BY status;"

# Check average processing time
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT AVG(EXTRACT(EPOCH FROM (processed_at - created_at))) as avg_seconds FROM threat_reports WHERE status = 'complete';"
```

### Regex Extraction Coverage

Phase 3 regex extractor covers **70+ ATT&CK techniques** across all 12 tactics:

- **Initial Access**: 5 techniques (phishing, exploits, remote services)
- **Execution**: 8 techniques (PowerShell, cmd, bash, scripts)
- **Persistence**: 6 techniques (scheduled tasks, services, run keys)
- **Privilege Escalation**: 3 techniques (exploits, token manipulation, UAC bypass)
- **Defense Evasion**: 7 techniques (obfuscation, AV disable, process injection)
- **Credential Access**: 7 techniques (credential dumping, brute force, keylogging)
- **Discovery**: 8 techniques (system info, network scan, process discovery)
- **Lateral Movement**: 5 techniques (RDP, SMB, WinRM, pass-the-hash)
- **Collection**: 5 techniques (data staging, screenshots, file collection)
- **Command and Control**: 6 techniques (C2, beaconing, DNS tunneling)
- **Exfiltration**: 3 techniques (exfil over C2, web service, alternative protocols)
- **Impact**: 6 techniques (ransomware, data destruction, service stop)

### Documentation

See [`PHASE3_INTEL_WORKER.md`](PHASE3_INTEL_WORKER.md) for:
- Complete architecture documentation
- Detailed API reference
- Performance metrics
- Security considerations
- Troubleshooting guide
- Regex pattern library

---

## Next Steps After Phase 3

Once Phase 3 validation is complete:

**Phase 5: Correlation Engine** (Week 8)
- Generate layers combining blue (vulnerability) + yellow (intel)
- Red techniques = critical overlap (threats you're vulnerable to)
- Color-coded MITRE Navigator layers

**Phase 6: Attribution Engine** (Week 9)
- Match layer techniques to threat actor TTPs
- Confidence-based attribution scoring
- Top 10 threat actors for your environment

---

**Classification**: INTERNAL USE ONLY
**Theme**: Midnight Vulture
