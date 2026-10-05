#!/usr/bin/env bash
set -e

echo "Starting MailSherlock ML service..."
python3 -m ml.inference.service &
ML_PID=$!

echo "Starting MailSherlock API..."
npm start &
NODE_PID=$!

cleanup() {
    echo "Stopping MailSherlock services..."
    kill "${ML_PID:-}" 2>/dev/null || true
    kill "${NODE_PID:-}" 2>/dev/null || true
}

trap cleanup SIGTERM SIGINT

wait "$NODE_PID"
NODE_STATUS=$?

cleanup
wait "$ML_PID" 2>/dev/null || true

exit "$NODE_STATUS"
