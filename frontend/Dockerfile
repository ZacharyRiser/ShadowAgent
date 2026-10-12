# Shadow Agent console — Next.js production image.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* vars are inlined at build time; pass the public backend URL
# the browser will use (default matches docker-compose port mapping).
ARG NEXT_PUBLIC_SHADOW_AGENT_API_BASE=http://localhost:8000
ENV NEXT_PUBLIC_SHADOW_AGENT_API_BASE=$NEXT_PUBLIC_SHADOW_AGENT_API_BASE
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
USER nextjs
EXPOSE 3000
CMD ["npm", "run", "start", "--", "-H", "0.0.0.0"]
