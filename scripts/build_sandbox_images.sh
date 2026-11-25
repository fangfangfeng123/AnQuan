#!/bin/bash
set -e
cd "$(dirname "$0")/.."
docker build -f sandbox-images/python-scanner.Dockerfile -t sec-eval/python-scanner:latest .
docker build -f sandbox-images/node-scanner.Dockerfile -t sec-eval/node-scanner:latest .
echo "Sandbox images built."
