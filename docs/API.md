# Vigitra API Reference
**Version**: 1.0.0 | **Vendor**: CypherNest | **Base URL**: `http://localhost:5000`

## Authentication
All `/api/*` endpoints require the `X-Vigitra-Key` header except:
- `GET /api/health` — unauthenticated
- `GET /api/manifest` — unauthenticated

**Header**: `X-Vigitra-Key: <your_key>`

## Response Envelope
All responses follow this structure:
```json
{
  "ok": true,
  "version": "1.0.0",
  "timestamp": "2025-01-01T00:00:00Z",
  "data": { ... }
}
```
On error: `"ok"` is false and `"error"` replaces `"data"`.

## Endpoints

### GET /api/health — No auth required
Returns system status. Used by extension to detect Vigitra is running.

### GET /api/manifest — No auth required
Returns capability list and endpoint map for auto-discovery.

### GET /api/stats
Returns total query counts and threat type aggregations.

### GET /api/alerts
Returns last 20 security threat alerts.

### GET /api/queries
Returns last 50 DNS query records with threat scores.

### GET /api/clients
Returns risk matrix grouped by client IP address.

### GET /api/timeline
Returns time-series data: queries vs blocked over time.

### GET /api/settings
Returns current detection toggles and risk threshold.

### POST /api/settings
Update settings. Body: `{"dga_enabled": 1, "risk_threshold": 80.0}`

### GET /api/whitelist
Returns all whitelisted domains.

### POST /api/whitelist
Add domain. Body: `{"domain": "example.com"}`

### DELETE /api/whitelist
Remove domain. Body: `{"domain": "example.com"}`

### GET /api/extension/status
Returns engine status and version metadata.

### POST /api/analyze_domain
Multi-agent AI + ML assessment for a single domain.
Body: `{"domain": "suspicious-domain.com"}`
Returns ML scores, AI consensus, and threat classification.

## Extension Quick Start
```javascript
const VIGITRA = 'http://localhost:5000';
const KEY = 'your_key_here';

// 1. Check if Vigitra is running
const health = await fetch(`${VIGITRA}/api/health`).then(r => r.json());
if (!health.ok) return; // not running

// 2. Discover capabilities
const manifest = await fetch(`${VIGITRA}/api/manifest`).then(r => r.json());

// 3. Get live stats
const stats = await fetch(`${VIGITRA}/api/stats`, {
  headers: { 'X-Vigitra-Key': KEY }
}).then(r => r.json());

console.log(stats.data);
```
