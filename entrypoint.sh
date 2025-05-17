#!/bin/sh

set -euo pipefail

mkdir -p /app/certs

# Check if PUBLIC_KEY_CONTENT and PRIVATE_KEY_CONTENT are set
if [ -z "$PUBLIC_KEY_CONTENT" ] || [ -z "$PRIVATE_KEY_CONTENT" ]; then
  echo "Public or Private key is not set. Exiting."
  exit 1
fi

echo "$PUBLIC_KEY_CONTENT" > /app/certs/public.pem
echo "$PRIVATE_KEY_CONTENT" > /app/certs/private.pem

exec java -jar app.jar
