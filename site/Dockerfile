FROM caddy:2.10-alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY . /srv
RUN rm -f /srv/Caddyfile /srv/Dockerfile /srv/README.md /srv/.dockerignore
