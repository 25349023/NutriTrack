# NutriTrack – Daily Food & Protein Tracker




## Quick Start (Local / Self-Hosted)

### 1 – Install Python dependencies
```bash
uv sync
```

### 2 – Start the server
```bash
uvicorn main:app --reload
# Or specify any port you prefer, e.g.:
# uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The server hosts both the Web App and the API:
- Web App UI: `http://127.0.0.1:8000/` (or whatever port uvicorn is running on)


## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs` | List all logs (optional `?date_filter=YYYY-MM-DD`) |
| `GET` | `/api/logs/summary` | Per-day totals for the past 30 days |
| `POST` | `/api/logs` | Add a food log entry |
| `DELETE` | `/api/logs/{id}` | Remove a log entry |
| `GET` | `/health` | Health check |


## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NUTRITION_DB_PATH` | `nutrition.db` | Path to the SQLite database file |
| `ALLOWED_ORIGINS` | `http://localhost:5500,...` | Comma-separated CORS-allowed origins |

## Disclaimer

This application was developed primarily through "vibe-coding" (AI-assisted rapid prototyping). While fully functional, the codebase has not undergone formal security audits. Please be aware of potential security risks and vulnerabilities—particularly when hosting in multi-user environments. Use at your own risk.