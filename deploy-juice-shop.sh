#!/bin/bash
set -e

# System prep, Docker install, user group... (same as before)

echo "=== Setup Juice Shop ==="
rm -rf juice-shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop || exit 1

echo "=== Inject Zen Firewall in server.ts ==="
server_file="server.ts"
if ! grep -q "require('@aikidosec/firewall')" "$server_file"; then
  sed -i "1i require('@aikidosec/firewall');" "$server_file"
fi

echo "=== Build & package Juice Shop ==="
npm install
npm run build

echo "=== Clean old docker containers/images ==="
container_ids=$(docker container ls -aq || true)
if [ -n "$container_ids" ]; then
  docker container stop $container_ids || true
  docker container rm $container_ids || true
fi

image_ids=$(docker image ls -aq || true)
if [ -n "$image_ids" ]; then
  docker image rm -f $image_ids || true
fi

docker volume prune -f || true
docker network prune -f || true

echo "=== Build and run Docker container ==="
cat > Dockerfile <<'DOCKER'
# Dockerfile content from above multi-stage example
DOCKER

docker build -t juice-shop-zen .
docker run -d \
  --name juice-shop \
  -p 3000:3000 \
  -e AIKIDO_TOKEN="$AIKIDO_TOKEN" \
  -e AIKIDO_BLOCK=false \
  juice-shop-zen

echo "=== Verify Juice Shop startup ==="
for i in {1..60}; do
  if curl -f http://localhost:3000 >/dev/null 2>&1; then
    echo "✅ Juice Shop is running"
    break
  fi
  sleep 3
done
