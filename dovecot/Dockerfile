FROM alpine:latest

LABEL description "Dovecot server" \
      maintainer="Sacha Trémoureux <sacha@tremoureux.fr>"

ENV HOSTNAME=

RUN \
  apk update && \
  apk add --no-cache dovecot dovecot-ldap dovecot-pigeonhole-plugin supervisor rsyslog rspamd-client && \
  rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

COPY conf/dovecot.conf /etc/dovecot/dovecot.conf
COPY conf/dovecot-ldap.conf.ext.template /etc/dovecot/dovecot-ldap.conf.ext.template
COPY conf/conf.d/* /etc/dovecot/conf.d/

COPY conf/ldap.conf.template /etc/ldap/ldap.conf.template
COPY conf/rsyslog.conf /etc/rsyslog.conf
COPY conf/supervisord.conf /etc/supervisord.conf

COPY       run.sh /run.sh
RUN chmod +x /run.sh

VOLUME ["/var/vmails", "/etc/dovecot/certs", "/var/lib/dovecot"]

EXPOSE 993 4190

ENTRYPOINT ["/run.sh"]
