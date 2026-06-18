#!/bin/bash

# Function to kill child processes on exit
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill $(jobs -p) 2>/dev/null
}
trap cleanup EXIT

# Get absolute path of project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Start backend
echo "Starting Backend API (Uvicorn)..."
cd "$PROJECT_ROOT/backend"
./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload &

# Start frontend
echo "Starting Frontend App (Vite)..."
cd "$PROJECT_ROOT/frontend"
npm run dev &

# Wait for all background jobs to finish
wait
