FROM node:22.17.1-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.base.json vitest.config.ts ./
COPY apps ./apps
COPY packages ./packages
COPY spec ./spec
RUN npm ci && npm run build && npm prune --omit=dev

FROM node:22.17.1-alpine AS runtime
ENV NODE_ENV=production \
    SECUREIT_MODE=demo
WORKDIR /app
RUN addgroup -S secureit && adduser -S -G secureit secureit
COPY --from=build --chown=secureit:secureit /app/node_modules ./node_modules
COPY --from=build --chown=secureit:secureit /app/apps ./apps
COPY --from=build --chown=secureit:secureit /app/packages ./packages
COPY --from=build --chown=secureit:secureit /app/spec ./spec
COPY --from=build --chown=secureit:secureit /app/package.json ./package.json
USER secureit
EXPOSE 3000
ENTRYPOINT ["node", "apps/mcp/dist/http-entry.js"]
