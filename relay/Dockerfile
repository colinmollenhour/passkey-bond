# strfry, pinned by digest, with a write policy that admits only Passkey.bond
# sync events. See relay/README.md.
FROM ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3
USER root
RUN apk add --no-cache jq su-exec
COPY strfry.conf /etc/strfry.conf
COPY write-policy.jq write-policy.sh start.sh /app/
RUN chmod 755 /app/write-policy.sh /app/start.sh
EXPOSE 7777
ENTRYPOINT ["/app/start.sh"]
