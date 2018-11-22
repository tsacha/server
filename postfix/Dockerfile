FROM alpine:latest

LABEL description "Postfix server" \
      maintainer="Sacha Trémoureux <sacha@tremoureux.fr>"

ENV HOSTNAME=

RUN \
  apk update && \
  apk add --no-cache postfix postfix-ldap rsyslog supervisor openssl && \
  rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*

COPY conf/*cf* /etc/postfix/
COPY conf/supervisord.conf /etc/supervisord.conf
COPY conf/rsyslog.conf /etc/rsyslog.conf

COPY       run.sh /run.sh
RUN chmod +x /run.sh

VOLUME ["/var/spool/postfix", "/etc/postfix/certs", "/var/vmails"]

EXPOSE 25 587
ENTRYPOINT ["/run.sh"]
