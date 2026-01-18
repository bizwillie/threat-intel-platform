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

## Phase 5: Correlation Engine - Layer Generation (✅ COMPLETE)

### Overview

Phase 5 implements the **Correlation Engine** - the core intellectual property of UTIP. This engine:
- Combines **blue layer** (vulnerability techniques) + **yellow layer** (threat intel techniques)
- Identifies **red layer** (critical overlap - threats you're actually vulnerable to)
- Generates color-coded MITRE ATT&CK Navigator layers
- Provides actionable fusion of threat intelligence and vulnerability data

**This is the crown jewel** - where raw data becomes actionable intelligence.

### Color Assignment Rules

| Color | Hex Code | Meaning | Source |
|-------|----------|---------|--------|
| Red | `#EF4444` | **CRITICAL OVERLAP** | Technique present in BOTH intel AND vulns |
| Yellow | `#F59E0B` | Intel Only | Technique observed in threat intel reports |
| Blue | `#3B82F6` | Vulnerability Only | Technique from vulnerability scans (CVE mappings) |

**Confidence Scoring**:
- Red techniques: `max(intel_confidence, vuln_confidence)` - take the highest
- Yellow techniques: `intel_confidence` from extraction
- Blue techniques: `vuln_confidence` from CVE→TTP mapping

### Prerequisites

- Phase 2 complete (vulnerability pipeline working)
- Phase 3 complete (intel worker processing documents)
- At least one vulnerability scan uploaded
- At least one threat intelligence document uploaded

### Testing Phase 5

#### 1. Verify Data Sources

```bash
# Get authentication token
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/utip/protocol/openid-connect/token" \
  -d "client_id=utip-api" \
  -d "client_secret=<client-secret>" \
  -d "grant_type=password" \
  -d "username=test-analyst" \
  -d "password=<password>" | jq -r '.access_token')

# List vulnerability scans (blue layer sources)
curl -s "http://localhost:8000/api/v1/vuln/scans" \
  -H "Authorization: Bearer $TOKEN" | jq

# List threat intel reports (yellow layer sources)
curl -s "http://localhost:8000/api/v1/intel/reports" \
  -H "Authorization: Bearer $TOKEN" | jq
```

Note the UUIDs - you'll need them for layer generation.

#### 2. Generate a Correlation Layer

```bash
# Generate layer combining intel and vulnerability data
curl -X POST "http://localhost:8000/api/v1/layers/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q4 2024 Threat Landscape",
    "description": "Correlation of APT29 intel with current vulnerability posture",
    "intel_report_ids": ["<report-uuid-1>", "<report-uuid-2>"],
    "vuln_scan_ids": ["<scan-uuid-1>"]
  }'
```

**Expected response** (201 Created):
```json
{
  "layer_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Q4 2024 Threat Landscape",
  "breakdown": {
    "red": 12,
    "yellow": 45,
    "blue": 30,
    "total": 87
  },
  "statistics": {
    "intel_reports_used": 2,
    "vuln_scans_used": 1,
    "unique_intel_techniques": 57,
    "unique_vuln_techniques": 42,
    "overlap_percentage": 13.79
  },
  "message": "Layer generated successfully"
}
```

**Key Insights**:
- **12 red techniques** = You are vulnerable to techniques actively being used by threat actors
- **13.79% overlap** = Percentage of techniques that are both observed AND exploitable
- Higher overlap percentage = Higher risk posture

#### 3. View Layer Details

```bash
# Get layer with all techniques
LAYER_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"

curl -s "http://localhost:8000/api/v1/layers/$LAYER_ID" \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected response**:
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Q4 2024 Threat Landscape",
  "description": "Correlation of APT29 intel with current vulnerability posture",
  "created_by": "test-analyst-uuid",
  "created_at": "2024-01-18T15:00:00Z",
  "technique_count": 87,
  "breakdown": {
    "red": 12,
    "yellow": 45,
    "blue": 30
  },
  "techniques": [
    {
      "technique_id": "T1059.001",
      "color": "#EF4444",
      "confidence": 0.95,
      "from_intel": true,
      "from_vuln": true
    },
    {
      "technique_id": "T1486",
      "color": "#F59E0B",
      "confidence": 0.95,
      "from_intel": true,
      "from_vuln": false
    },
    {
      "technique_id": "T1003.006",
      "color": "#3B82F6",
      "confidence": 0.98,
      "from_intel": false,
      "from_vuln": true
    }
  ]
}
```

#### 4. Export to MITRE ATT&CK Navigator

```bash
# Export layer in Navigator JSON format
curl -s "http://localhost:8000/api/v1/layers/$LAYER_ID/export" \
  -H "Authorization: Bearer $TOKEN" > layer.json

# View exported JSON
jq '.' layer.json
```

**Usage**:
1. Open MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
2. Click "Open Existing Layer"
3. Select "Upload from local"
4. Upload `layer.json`

**You should see**:
- Red cells = Critical overlap (prioritize remediation)
- Yellow cells = Threat intel only (monitor)
- Blue cells = Vulnerability only (patch when feasible)

#### 5. List All Layers

```bash
# Get all generated layers
curl -s "http://localhost:8000/api/v1/layers/" \
  -H "Authorization: Bearer $TOKEN" | jq
```

#### 6. Delete a Layer

```bash
# Delete a layer (only creator can delete)
curl -X DELETE "http://localhost:8000/api/v1/layers/$LAYER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

**Expected response**: 204 No Content (success)

### Phase 5 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/layers/generate` | POST | analyst | Generate correlation layer |
| `/api/v1/layers/` | GET | analyst | List all layers |
| `/api/v1/layers/{id}` | GET | analyst | Get layer with techniques |
| `/api/v1/layers/{id}/export` | GET | analyst | Export to Navigator JSON |
| `/api/v1/layers/{id}` | DELETE | analyst | Delete layer (creator only) |

### Use Cases

#### Scenario 1: Identify Critical Overlaps

**Goal**: Find techniques you're vulnerable to that threat actors are actively using

```bash
# Generate layer for latest intel + vulnerability scan
curl -X POST "http://localhost:8000/api/v1/layers/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Critical Overlap Analysis",
    "description": "Latest threats vs. current vulns",
    "intel_report_ids": ["latest-report-uuid"],
    "vuln_scan_ids": ["latest-scan-uuid"]
  }'
```

**Focus on**: Red techniques (from_intel=true, from_vuln=true)

**Action**: Prioritize patching vulnerabilities that map to red techniques

#### Scenario 2: Threat Actor Campaign Analysis

**Goal**: Understand if a specific APT's TTPs match your vulnerabilities

```bash
# Generate layer for APT29 reports + your environment
curl -X POST "http://localhost:8000/api/v1/layers/generate" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "APT29 vs. Our Environment",
    "description": "APT29 campaign techniques against our vulnerability posture",
    "intel_report_ids": ["apt29-report-1", "apt29-report-2"],
    "vuln_scan_ids": ["prod-scan-uuid"]
  }'
```

**Focus on**: Red techniques = APT29 can exploit your environment

**Action**: Emergency patching for red techniques

#### Scenario 3: Trend Analysis

**Goal**: Track overlap percentage over time

```bash
# Generate weekly layers
curl -X POST "http://localhost:8000/api/v1/layers/generate" \
  -d '{"name": "Week 1", "intel_report_ids": [...], "vuln_scan_ids": [...]}'

curl -X POST "http://localhost:8000/api/v1/layers/generate" \
  -d '{"name": "Week 2", "intel_report_ids": [...], "vuln_scan_ids": [...]}'
```

**Compare**: `overlap_percentage` across weeks

**Trend Up** = Risk increasing (more vulnerabilities OR more active threats)
**Trend Down** = Risk decreasing (patching working OR threat landscape shifting)

### Phase 5 Validation Checklist

- [ ] Layer generation succeeds with valid intel/vuln UUIDs
- [ ] Red techniques correctly show overlap (from_intel=true, from_vuln=true)
- [ ] Yellow techniques show intel-only (from_intel=true, from_vuln=false)
- [ ] Blue techniques show vuln-only (from_intel=false, from_vuln=true)
- [ ] Breakdown statistics are accurate (red + yellow + blue = total)
- [ ] Overlap percentage calculated correctly
- [ ] Navigator export produces valid JSON
- [ ] Exported layer displays correctly in ATT&CK Navigator
- [ ] Layer list endpoint returns all layers
- [ ] Layer delete works (403 if not creator)

### Troubleshooting Phase 5

#### No red techniques generated

**Symptoms**: breakdown.red = 0, all yellow/blue

**Causes**:
- Intel reports and vulnerability scans have no common techniques
- Data sources are from different threat domains (e.g., Linux threats vs. Windows vulns)

**Check**:
```bash
# View intel techniques
curl "http://localhost:8000/api/v1/intel/reports/<report-id>/techniques" -H "Authorization: Bearer $TOKEN"

# View vuln techniques
curl "http://localhost:8000/api/v1/vuln/scans/<scan-id>/techniques" -H "Authorization: Bearer $TOKEN"

# Look for common technique IDs
```

**Fix**: Upload more diverse intel reports or vulnerability scans

#### Layer generation fails with 400 Bad Request

**Symptoms**: "At least one intel report or vulnerability scan must be provided"

**Cause**: Empty `intel_report_ids` or `vuln_scan_ids` arrays

**Fix**: Provide at least one UUID in either array

#### Navigator JSON won't import

**Symptoms**: Navigator shows error when uploading layer.json

**Check**:
```bash
# Validate JSON structure
jq '.' layer.json

# Check Navigator version field
jq '.versions' layer.json
```

**Expected**:
```json
{
  "attack": "14",
  "navigator": "4.5",
  "layer": "4.5"
}
```

**Fix**: Re-export layer (may have been corrupted during download)

### Database Queries

```bash
# Check layer statistics
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT l.name, COUNT(lt.technique_id) as total_techniques, l.created_at FROM layers l LEFT JOIN layer_techniques lt ON l.id = lt.layer_id GROUP BY l.id ORDER BY l.created_at DESC;"

# Check technique color distribution
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT color, COUNT(*) FROM layer_techniques WHERE layer_id = '<layer-uuid>' GROUP BY color;"

# Check overlap techniques
docker compose exec postgres psql -U utip -d utip \
  -c "SELECT technique_id, confidence FROM layer_techniques WHERE layer_id = '<layer-uuid>' AND from_intel = true AND from_vuln = true ORDER BY confidence DESC;"
```

### Performance Metrics

Layer generation is **synchronous** and completes in:
- Small datasets (< 100 techniques): < 100ms
- Medium datasets (100-500 techniques): < 500ms
- Large datasets (500+ techniques): < 2 seconds

**Database Impact**: 1 INSERT per technique + layer metadata (minimal)

### Security Considerations

- **Layer Isolation**: Each layer is tied to a creator (created_by UUID)
- **Delete Permission**: Only the layer creator can delete their layers
- **Read Access**: Any authenticated analyst can view any layer
- **Audit Trail**: All layer generations logged with user ID and timestamp

---

## Phase 6: Attribution Engine - Threat Actor Attribution (✅ COMPLETE)

### Overview

Phase 6 implements deterministic threat actor attribution using technique overlap analysis. The attribution engine analyzes generated layers and matches them against known APT group TTPs to identify potential threat actors.

**Core Capability**: "Which threat actor does this attack surface profile match?"

### Architecture

```
┌─────────────────────┐
│   Generated Layer   │
│   (from Phase 5)    │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ Attribution Service │ ← Deterministic scoring algorithm
│ (deterministic)     │ ← Weighted technique matching
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│  Threat Actor DB    │
│  (8 APT groups)     │
│  (128 techniques)   │
└─────────────────────┘
```

### Algorithm

**Deterministic Scoring** (no LLM, fully auditable):

1. **Get layer techniques**: Extract all techniques from the target layer
2. **For each threat actor**:
   - Get actor's known techniques with weights (0.0-1.0)
   - Calculate overlap with layer techniques
   - Sum weights of matching techniques
   - Normalize by total actor weight → confidence score (0.0-1.0)
3. **Sort by confidence**: Return top N actors with highest confidence
4. **Include evidence**: Show which techniques matched

**Confidence Interpretation**:
- **0.8-1.0**: Strong match (actor's signature techniques present)
- **0.5-0.8**: Moderate match (significant technique overlap)
- **0.2-0.5**: Weak match (some techniques match, but not distinctive)
- **0.0-0.2**: Minimal match (very few overlapping techniques)

### Threat Actors Seeded

The database includes 8 major APT groups:

| Actor ID | Name | Description | Techniques |
|----------|------|-------------|------------|
| **APT29** | Cozy Bear | Russian SVR cyber espionage | 18 |
| **APT28** | Fancy Bear | Russian GRU military intelligence | 19 |
| **APT1** | Comment Crew | Chinese PLA Unit 61398 | 14 |
| **Lazarus** | Lazarus Group | North Korean state-sponsored | 15 |
| **FIN7** | Carbanak | Russian cybercrime group | 17 |
| **APT41** | Double Dragon | Chinese dual-mandate group | 16 |
| **Sandworm** | Sandworm Team | Russian GRU destructive ops | 13 |
| **Turla** | Snake/Uroburos | Russian FSB sophisticated espionage | 16 |

**Total**: 128 actor-technique mappings with weighted confidence

### API Endpoints

#### 1. POST /api/v1/attribution - Attribute Layer

**Purpose**: Attribute a layer to threat actors

**Request**:
```json
{
  "layer_id": "550e8400-e29b-41d4-a716-446655440000",
  "top_n": 10,
  "min_confidence": 0.1
}
```

**Response**:
```json
{
  "layer_id": "550e8400-e29b-41d4-a716-446655440000",
  "layer_name": "Q4 2024 Threat Landscape",
  "attributions": [
    {
      "actor_id": "APT29",
      "actor_name": "Cozy Bear (APT29)",
      "description": "Russian cyber espionage group...",
      "confidence": 0.847,
      "matching_techniques": [
        "T1059.001",
        "T1566.001",
        "T1071.001"
      ],
      "match_count": 15,
      "total_actor_techniques": 18
    },
    {
      "actor_id": "APT28",
      "actor_name": "Fancy Bear (APT28)",
      "description": "Russian military intelligence...",
      "confidence": 0.632,
      "matching_techniques": [
        "T1566.001",
        "T1071.001"
      ],
      "match_count": 12,
      "total_actor_techniques": 19
    }
  ],
  "total_actors_evaluated": 8,
  "message": "Attribution analysis complete"
}
```

#### 2. GET /api/v1/attribution/actors - List Threat Actors

**Purpose**: Get all threat actors in database

**Response**:
```json
[
  {
    "actor_id": "APT29",
    "actor_name": "Cozy Bear (APT29)",
    "description": "Russian cyber espionage group..."
  }
]
```

#### 3. GET /api/v1/attribution/actors/{actor_id} - Get Actor Details

**Purpose**: Get detailed information about a specific threat actor

**Example**: `GET /api/v1/attribution/actors/APT29`

**Response**:
```json
{
  "actor_id": "APT29",
  "actor_name": "Cozy Bear (APT29)",
  "description": "Russian cyber espionage group...",
  "techniques": [
    {
      "technique_id": "T1059.001",
      "weight": 0.95
    },
    {
      "technique_id": "T1566.001",
      "weight": 0.90
    }
  ],
  "technique_count": 18
}
```

### Testing Phase 6

#### Prerequisites

1. Phase 5 layer generated
2. Threat actor data seeded (run on first deployment)

#### Test 1: Attribute Layer to Threat Actors

```bash
# 1. Generate a layer (from Phase 5)
LAYER_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/layers/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Attribution Layer",
    "description": "Layer for testing threat actor attribution",
    "intel_report_ids": ["<intel_report_uuid>"],
    "vuln_scan_ids": ["<vuln_scan_uuid>"]
  }')

LAYER_ID=$(echo $LAYER_RESPONSE | jq -r '.layer_id')
echo "Generated layer: $LAYER_ID"

# 2. Attribute the layer
curl -X POST http://localhost:8000/api/v1/attribution \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"layer_id\": \"$LAYER_ID\",
    \"top_n\": 5,
    \"min_confidence\": 0.1
  }" | jq '.'
```

**Expected Output**:
- Top 5 threat actors sorted by confidence
- Each actor shows matching techniques
- Confidence scores between 0.0 and 1.0
- Match count shows how many techniques overlapped

#### Test 2: List All Threat Actors

```bash
curl -X GET http://localhost:8000/api/v1/attribution/actors \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**Expected Output**:
- 8 threat actors (APT29, APT28, APT1, Lazarus, FIN7, APT41, Sandworm, Turla)
- Each with ID, name, and description

#### Test 3: Get Actor Details

```bash
# Get details for APT29
curl -X GET http://localhost:8000/api/v1/attribution/actors/APT29 \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

**Expected Output**:
- Actor metadata
- 18 techniques with weights
- Signature techniques (weight > 0.8): PowerShell, Spearphishing

#### Test 4: Verify Database Seeding

```bash
# Check threat actors table
docker-compose exec postgres psql -U utip -d utip -c \
  "SELECT id, name FROM threat_actors ORDER BY id;"

# Check actor techniques count
docker-compose exec postgres psql -U utip -d utip -c \
  "SELECT actor_id, COUNT(*) as technique_count
   FROM actor_techniques
   GROUP BY actor_id
   ORDER BY actor_id;"
```

**Expected Output**:
- 8 threat actors
- 128 total actor-technique mappings

### Use Cases

#### 1. APT Campaign Identification

**Scenario**: An organization detects suspicious activity and generates a correlation layer.

**Workflow**:
1. Generate layer from recent threat intel + vulnerability scans
2. Attribute layer to identify potential APT groups
3. Review top matches (> 0.5 confidence)
4. Cross-reference with geopolitical context
5. Adjust detection rules based on APT TTPs

**Example Attribution**:
- **APT29 (0.85 confidence)**: PowerShell usage, spearphishing, DNS C2
- **APT28 (0.67 confidence)**: Spearphishing, drive-by compromise
- **Turla (0.54 confidence)**: Supply chain compromise indicators

#### 2. Threat Intelligence Validation

**Scenario**: Validate if observed TTPs match reported threat actor profiles.

**Workflow**:
1. Extract techniques from threat report
2. Generate layer (intel-only, no vulnerabilities)
3. Run attribution
4. Compare top match with report's attribution
5. Confidence score validates/challenges report's claims

**Example**:
- Report claims: APT29
- Attribution shows: APT29 (0.92) ← Strong validation
- Attribution shows: FIN7 (0.91) ← Possible misattribution

#### 3. Proactive Threat Hunting

**Scenario**: Hunt for specific threat actor activity.

**Workflow**:
1. Get actor details: `GET /api/v1/attribution/actors/APT29`
2. Review signature techniques (weight > 0.8)
3. Query logs/SIEM for those techniques
4. If found, generate layer and re-attribute
5. Confidence score shows similarity to known APT29 behavior

### Troubleshooting

#### No Attributions Returned

**Symptom**: Attribution returns empty list

**Causes**:
1. **Threat actor database not seeded**
   ```bash
   docker-compose exec backend python -m scripts.seed_threat_actors
   ```

2. **Layer has no techniques**
   ```bash
   # Check layer techniques
   docker-compose exec postgres psql -U utip -d utip -c \
     "SELECT COUNT(*) FROM layer_techniques WHERE layer_id = '<layer_uuid>';"
   ```

3. **min_confidence too high**
   - Lower the threshold: `"min_confidence": 0.0`

#### Low Confidence Scores

**Symptom**: All attributions < 0.2 confidence

**Causes**:
1. **Layer techniques don't match any actor profiles**
   - Normal for custom/unknown threat actors
   - May indicate novel TTPs

2. **Limited technique overlap**
   - Layer may have very few techniques
   - Actors may have niche TTPs not in your layer

**Action**: Review matching_techniques array to see what overlapped

#### Attribution Doesn't Match Expectations

**Symptom**: Expected APT29, got APT28 with higher confidence

**Explanation**:
- Attribution is **deterministic and mathematical**
- Based purely on technique overlap and weights
- Does NOT consider:
  - Geopolitical context
  - Targeting patterns
  - Temporal factors
  - Tool sophistication

**Use attribution as ONE data point**, not definitive identification.

### Performance Metrics

**Response Times**:
- Attribution for layer with 50 techniques: ~200ms
- Attribution for layer with 200 techniques: ~500ms
- Listing all actors: ~50ms
- Actor details: ~30ms

**Scalability**:
- Currently: 8 threat actors, 128 techniques
- Scales linearly: 100 actors, 2000 techniques → ~2-3 seconds
- Database indexes ensure fast lookups

### Security Considerations

- **No Data Leakage**: Attribution runs on layer IDs (internal), not raw intel
- **Read-Only Attribution**: Doesn't modify layers or threat actor data
- **Audit Trail**: All attribution requests logged with user ID
- **Actor Data**: Publicly known APT groups (no sensitive intel)

### Re-seeding Threat Actors

To update threat actor data:

```bash
# Edit backend/scripts/seed_threat_actors.py
# Add/modify THREAT_ACTORS dictionary

# Re-run seeding (clears existing data)
docker-compose exec backend python -m scripts.seed_threat_actors

# Verify
curl -X GET http://localhost:8000/api/v1/attribution/actors \
  -H "Authorization: Bearer $TOKEN" | jq '. | length'
```

**Note**: Seeding clears ALL existing threat actor data.

### Next Steps

Once Phase 6 validation is complete:

**Phase 7: Remediation Engine**
- Map red techniques to MITRE mitigations
- Generate prioritized remediation guidance
- Link to detection rules (Sigma, YARA)
- "How do we fix these critical gaps?"

**Phase 8: Frontend Integration**
- Fork MITRE ATT&CK Navigator
- Add attribution panel to UI
- Display threat actor matches with confidence
- Interactive threat actor drill-down

---

**Classification**: INTERNAL USE ONLY
**Theme**: Midnight Vulture
