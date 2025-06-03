# Build stage
FROM node:lts-slim AS build

WORKDIR /app

# Copy package.json first
COPY package.json ./
# Use npm install instead of npm ci since there's no package-lock.json
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the application with GUAC_CLIENT_URL as an empty string for relative paths
ARG GUAC_CLIENT_URL=""
ENV GUAC_CLIENT_URL=${GUAC_CLIENT_URL}
RUN npm run build

# Production stage
FROM caddy:alpine

# Copy the Caddyfile
COPY Caddyfile /etc/caddy/Caddyfile

# Copy the built application from the build stage to Caddy's default static file directory /srv
COPY --from=build /app/dist /srv

# Caddy's default port is 80 for HTTP. The Caddyfile also specifies listening on port 80.
# EXPOSE 80 is already handled by the base caddy image.

# The default CMD for the caddy image will run caddy using the Caddyfile.
