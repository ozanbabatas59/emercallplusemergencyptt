# Production Deployment Guide

## EmercallPlus Emergency PTT Server

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `NODE_ENV` | `production` | Environment mode |
| `DATA_FILE` | `./data.json` | Data file path |

## Health Checks

- **Health**: `GET /health` - Returns server status, uptime, client count
- **Ready**: `GET /ready` - For K8s/Docker readiness probes

## Data Persistence

The `data.json` file contains:
- Admin token
- Channels
- Banned device IDs
- Banned usernames

**Important**: Mount this as a volume in production to persist data across deployments.

## Deploy Services

### Railway
```bash
railway up
```

### Render
```bash
render deploy
```

### Fly.io
```bash
fly launch
fly deploy
```

### VPS/Dedicated Server
```bash
# Install dependencies
npm install

# Start with PM2
npm install -g pm2
pm2 start serve.mjs --name emercall
pm2 save
pm2 startup
```

### Docker
```bash
docker build -t emercall-server .
docker run -d -p 4000:4000 -v $(pwd)/data.json:/app/data.json --name emercall emercall-server
```

## First Run

1. Deploy the application
2. Visit the deployed URL
3. Copy the admin token displayed on the welcome screen
4. Save it securely - this is your only chance to see it!

## Security Notes

- Admin token is generated on first run
- Rate limiting enabled (100 req/min per IP)
- Security headers enabled (CSP, X-Frame-Options, etc.)
- CORS restricted to same-origin
- Input validation on all endpoints
