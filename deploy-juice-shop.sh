#!/bin/bash
set -e

echo "=== System Prep ==="
sudo apt-get update -qq
sudo apt-get install -y curl jq git docker.io
sudo systemctl enable --now docker

echo "=== Adding user to docker group ==="
sudo usermod -aG docker $USER || sudo usermod -aG docker ubuntu || true
newgrp docker || true

echo "=== Restarting Docker service ==="
sudo systemctl restart docker

echo "=== Cleaning APT cache ==="
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
sudo apt-get update

echo "=== Checking disk and memory ==="
df -h
free -m

echo "=== Fix broken installs if any ==="
sudo dpkg --configure -a || true
sudo apt-get install -f -y || true

echo "=== Install Datadog Agent if missing ==="
if ! command -v datadog-agent &>/dev/null; then
  DD_API_KEY="$DD_API_KEY" DD_SITE="$DD_SITE" \
    bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"
fi
sudo systemctl restart datadog-agent

echo "=== Setup Juice Shop ==="
rm -rf juice-shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop || exit 1

echo "=== Inject Zen Firewall into server.ts ==="
server_file="server.ts"
if ! grep -q "require('@aikidosec/firewall')" "$server_file"; then
  sed -i "1i require('@aikidosec/firewall');" "$server_file"
fi

echo "=== Clean old Docker containers and images ==="
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
echo "Cleanup complete."

echo "=== Write Dockerfile ==="
cat > Dockerfile <<'DOCKER'
# Build Stage
FROM node:24-bullseye as build

WORKDIR /juice-shop

COPY package*.json ./

RUN apt-get update && apt-get install -y git python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

RUN npm install

COPY . .

RUN npm run build

# Production Stage
FROM node:24-bullseye

WORKDIR /juice-shop

COPY --from=build /juice-shop/dist ./dist
COPY --from=build /juice-shop/node_modules ./node_modules
COPY package*.json ./

EXPOSE 3000

USER node

CMD ["node", "dist/server.js"]
DOCKER

echo "=== Build & Run Juice Shop container ==="
docker build -t juice-shop-zen .
docker run -d \
  --name juice-shop \
  -p 3000:3000 \
  -e AIKIDO_TOKEN="$AIKIDO_TOKEN" \
  -e AIKIDO_BLOCK=false \
  -e DD_AGENT_HOST=$(hostname -I | awk '{print $1}') \
  -e DD_SERVICE=juice-shop \
  -e DD_ENV=benchmark \
  -e DD_VERSION=latest \
  juice-shop-zen

echo "=== Verify Startup ==="
for i in {1..60}; do
  if curl -f http://localhost:3000 >/dev/null 2>&1; then
    echo "✅ Juice Shop is running"
    break
  fi
  sleep 3
done
