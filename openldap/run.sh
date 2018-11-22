#!/bin/sh
/etc/openldap/scripts/bootstrap.py
cp /etc/openldap/traefik-certs/certs/$LDAP_HOSTNAME.crt /etc/openldap/certs/
cp /etc/openldap/traefik-certs/private/$LDAP_HOSTNAME.key /etc/openldap/certs/
chown 100:101 /etc/openldap/certs/*
chmod 440 /etc/openldap/certs/*
exec supervisord -c /etc/supervisord.conf
