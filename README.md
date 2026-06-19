# API Auth Proxy — Douyin/TikTok Download API

A self-hosted API key authentication gateway that wraps the `douyin_tiktok_download_api` service.  
**Plug-and-play** on any remote server with Docker installed.

## Architecture

```
Internet → [Nginx / Cloudflare] → [Auth Proxy :8000] → [douyin-api (internal only)]
```

- **auth-proxy** — FastAPI service: validates API keys, enforces rate limits, and transparently forwards requests.
- **douyin-api** — completely hidden from the outside; accessible only through the proxy via Docker's internal network.
- **Storage** — SQLite database stored in `./data/` (persists across container restarts via Docker volume).

---

## Requirements

- Docker ≥ 24.x
- Docker Compose plugin (`docker compose`, not the legacy `docker-compose`)

---

## First-Time Deployment (Remote Server)

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd API-Parser-douyin

# 2. Configure secrets
cp .env.example .env
nano .env
# Required: set ADMIN_SECRET to a strong random string
# Tip: generate one with → openssl rand -hex 32

# 3. Build and start all services
docker compose up -d --build

# 4. Verify services are running
docker compose ps
docker compose logs -f auth-proxy

# 5. Create your first API key
curl -X POST http://localhost:8000/admin/keys \
  -H "X-Admin-Secret: YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name": "client-A", "note": "Production key"}'
```

---

## Nginx Configuration (Example)

Point your existing Nginx virtual host to the proxy's local port:

```nginx
server {
    listen 443 ssl;
    server_name api.yourdomain.com;

    # SSL managed by Certbot or a Cloudflare Origin Certificate
    ssl_certificate     /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }
}
```

---

## Client Usage

### Calling the API with an API key

```bash
# Option 1: Header (recommended)
curl -H "X-API-Key: ag_xxxxxxxxxxxx" \
     "https://api.yourdomain.com/api/douyin/web/fetch_one_video?url=..."

# Option 2: Query parameter
curl "https://api.yourdomain.com/api/douyin/web/fetch_one_video?url=...&api_key=ag_xxxxxxxxxxxx"
```

### Rate limit response headers

| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Maximum requests allowed per hour (default: 100) |
| `X-RateLimit-Remaining` | Requests remaining in the current hour window |

### Error codes

| HTTP Code | Reason |
|---|---|
| `401 Unauthorized` | Missing or invalid API key |
| `403 Forbidden` | Key is disabled or has expired |
| `429 Too Many Requests` | Rate limit exceeded (100 req/hour) |

---

## Admin API

All admin endpoints require the header: `X-Admin-Secret: <ADMIN_SECRET>`

### Interactive Swagger UI

```
http://localhost:8000/admin/docs
```

### Quick Reference

```bash
BASE="http://localhost:8000"
SECRET="YOUR_ADMIN_SECRET"

# List all keys
curl -H "X-Admin-Secret: $SECRET" $BASE/admin/keys

# Create a new key
curl -X POST -H "X-Admin-Secret: $SECRET" \
  -H "Content-Type: application/json" \
  -d '{"name": "client-B", "note": "Dev environment"}' \
  $BASE/admin/keys

# Disable a key (reversible)
curl -X PATCH -H "X-Admin-Secret: $SECRET" \
  $BASE/admin/keys/ag_xxxx/disable

# Enable a key
curl -X PATCH -H "X-Admin-Secret: $SECRET" \
  $BASE/admin/keys/ag_xxxx/enable

# Renew a key's expiry (+30 days from now)
curl -X POST -H "X-Admin-Secret: $SECRET" \
  $BASE/admin/keys/ag_xxxx/renew

# Delete a key permanently
curl -X DELETE -H "X-Admin-Secret: $SECRET" \
  $BASE/admin/keys/ag_xxxx

# View usage statistics
curl -H "X-Admin-Secret: $SECRET" $BASE/admin/stats
```

---

## Deploying on a New Server (Plug-and-Play)

```bash
git clone <repo-url>
cd API-Parser-douyin
cp .env.example .env && nano .env    # Set ADMIN_SECRET
docker compose up -d --build
```

No additional dependencies beyond Docker. Recreate API keys via the admin API after deployment.

---

## Configuration Reference (`.env`)

| Variable | Default | Description |
|---|---|---|
| `ADMIN_SECRET` | *(required)* | Secret used to authenticate admin endpoint calls |
| `PROXY_PORT` | `8000` | Host port exposed to Nginx / Cloudflare |
| `RATE_LIMIT_PER_HOUR` | `100` | Max requests per hour per API key |
| `KEY_EXPIRY_DAYS` | `30` | Number of days a key remains valid after creation |
| `LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Project Structure

```
API-Parser-douyin/
├── auth-proxy/
│   ├── Dockerfile           # Python 3.12-slim image
│   ├── requirements.txt     # Pinned dependencies
│   └── main.py              # FastAPI application (proxy + admin)
├── config/                  # (optional) douyin-api config overrides
├── data/                    # SQLite database — auto-created, gitignored
├── docker-compose.yml       # Service orchestration
├── .env                     # Secrets — gitignored, created from .env.example
├── .env.example             # Config template — safe to commit
├── .gitignore
└── README.md
```
