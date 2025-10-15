#!/bin/bash
set -e

echo "=== System Prep ==="
sudo apt-get update -qq
sudo apt-get install -y curl jq git docker.io
sudo systemctl enable --now docker

echo "=== Exporting environment variables ==="
echo "DD_API_KEY=$DD_API_KEY"
echo "DD_APP_KEY=$DD_APP_KEY"
echo "DD_SITE=$DD_SITE"
echo "AIKIDO_TOKEN=$AIKIDO_TOKEN"

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

echo "=== Juice Shop Setup ==="
rm -rf juice-shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop || exit 1

echo "=== Inject Zen Firewall (Aikido) ==="
cat > Dockerfile <<'DOCKER'
FROM node:18-alpine
WORKDIR /juice-shop
COPY . .
RUN npm install --save-exact @aikidosec/firewall
RUN npm install
RUN npm run build
EXPOSE 3000
ENV AIKIDO_TOKEN=${AIKIDO_TOKEN}
ENV AIKIDO_BLOCK=false
CMD ["npm", "start"]
DOCKER

echo "=== Build & Run Juice Shop ==="
docker stop juice-shop || true
docker rm juice-shop || true
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
