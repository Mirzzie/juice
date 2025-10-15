#!/bin/bash
set -e

SERVER_FILE="server.ts"

if ! grep -q "@aikidosec/firewall" "$SERVER_FILE"; then
  echo "Injecting Aikido Zen Firewall require into $SERVER_FILE"
  sed -i '1irequire("@aikidosec/firewall");' "$SERVER_FILE"
else
  echo "Aikido Zen Firewall already present in $SERVER_FILE"
fi
