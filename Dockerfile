FROM node:24.17.0-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig*.json ./
COPY apps/api/package.json ./apps/api/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY packages/core/package.json ./packages/core/package.json
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY packages/core ./packages/core
COPY apps/api ./apps/api
RUN npm run build --workspace=@edy-scanurl/core && npm run build --workspace=@edy-scanurl/api
RUN npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24.17.0-bookworm-slim
ENV NODE_ENV=production FAMILY_HOST=0.0.0.0 PORT=8788 FAMILY_DB_PATH=/data/family.sqlite
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/packages/core ./packages/core
COPY --from=build --chown=node:node /app/apps/api ./apps/api
COPY --from=build --chown=node:node /app/package.json ./package.json
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8788
CMD ["node", "apps/api/dist/src/family/server.js"]
