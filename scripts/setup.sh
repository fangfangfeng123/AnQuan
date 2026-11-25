#!/bin/bash
set -e
cp .env.example .env 2>/dev/null || true
docker compose -f docker-compose.dev.yml up -d --build
sleep 10
docker exec sec_eval_backend python -m app.init_db
echo "Setup complete. Frontend: http://localhost:5173  API: http://127.0.0.1:8001/docs"
