#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  echo ""
  echo "Shutting down..."
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
  wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
  echo "Done."
}
trap cleanup EXIT INT TERM

# Backend
echo "Starting Django backend on :8000 ..."
cd "$DIR/backend"
python3 manage.py runserver 8000 &
BACKEND_PID=$!

# Frontend
echo "Starting React frontend on :3000 ..."
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "========================================="
echo "  Backend  → http://localhost:8000/api/"
echo "  Frontend → http://localhost:3000"
echo "  Press Ctrl+C to stop both"
echo "========================================="
echo ""

wait
