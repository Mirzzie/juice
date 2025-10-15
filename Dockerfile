# Build Stage
FROM node:24-bullseye as build

WORKDIR /juice-shop

COPY package*.json ./

RUN apt-get update && apt-get install -y git python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

RUN npm install

COPY . .

RUN npm run build

# Production Stage (lighter final image)
FROM node:24-bullseye

WORKDIR /juice-shop

COPY --from=build /juice-shop/dist ./dist
COPY --from=build /juice-shop/node_modules ./node_modules
COPY package*.json ./

EXPOSE 3000

USER node

CMD ["node", "dist/server.js"]
