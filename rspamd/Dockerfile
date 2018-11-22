FROM alpine:latest

LABEL description "Rspamd server" \
      maintainer="Sacha Trémoureux <sacha@tremoureux.fr>"

ENV HOSTNAME=

RUN \
  apk update && \
  apk add --no-cache rspamd rspamd-controller rspamd-proxy rspamd-utils && \
  rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

COPY override/* /etc/rspamd/override.d/
COPY conf/* /etc/rspamd/local.d/

EXPOSE 11332 11334

CMD ["/usr/sbin/rspamd", "-c", "/etc/rspamd/rspamd.conf", "-f", "-u", "rspamd", "-g", "rspamd"]