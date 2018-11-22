FROM alpine:latest

RUN \
  apk update && \
  apk add openldap openldap-back-mdb openldap-overlay-memberof openldap-overlay-refint openldap-overlay-ppolicy python3 py3-ldap3 supervisor && \
  mkdir /run/openldap /etc/openldap/scripts /etc/openldap/certs && \
  rm -rf /var/cache/apk/*

COPY scripts/ /etc/openldap/scripts
COPY conf/supervisord.conf /etc/supervisord.conf
COPY       run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 389

VOLUME ["/var/lib/openldap/openldap-data", "/etc/openldap/traefik-certs"]
ENTRYPOINT ["/run.sh"]
