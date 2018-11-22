#!/bin/sh
if [ ! -d /var/spool/postfix/pid ]; then
    mkdir /var/spool/postfix/pid
fi
if [ ! -d /var/spool/postfix/dev ]; then
    mkdir /var/spool/postfix/dev
fi

chown root: /var/spool/postfix
chown root: /var/spool/postfix/pid
chown root: /var/spool/postfix/dev

chown root:adm /var/log/mail.log
chown root:adm /var/log/mail.err
chown root:adm /var/log/mail.info
chown root:adm /var/log/mail.warn


postconf -e myhostname="$HOSTNAME"
if [ ! -f /etc/postfix/certs/dhparam.pem ]; then
    pushd /etc/postfix/certs
    openssl dhparam -out dhparam.pem 4096
    popd
fi

sed 's@{{LDAP_HOSTNAME}}@'"$LDAP_HOSTNAME"'@g' /etc/postfix/ldap-accounts.cf.template > /etc/postfix/ldap-accounts.cf
sed -i 's@{{LDAP_DN}}@'"$LDAP_DN"'@g' /etc/postfix/ldap-accounts.cf
sed -i 's@{{LDAP_PASSWORD}}@'"$LDAP_PASSWORD"'@g' /etc/postfix/ldap-accounts.cf
sed -i 's@{{LDAP_USERS}}@'"$LDAP_USERS"'@g' /etc/postfix/ldap-accounts.cf

sed 's@{{LDAP_HOSTNAME}}@'"$LDAP_HOSTNAME"'@g' /etc/postfix/ldap-domains.cf.template > /etc/postfix/ldap-domains.cf
sed -i 's@{{LDAP_DN}}@'"$LDAP_DN"'@g' /etc/postfix/ldap-domains.cf
sed -i 's@{{LDAP_PASSWORD}}@'"$LDAP_PASSWORD"'@g' /etc/postfix/ldap-domains.cf
sed -i 's@{{LDAP_DOMAINS}}@'"$LDAP_DOMAINS"'@g' /etc/postfix/ldap-domains.cf


sed 's@{{LDAP_HOSTNAME}}@'"$LDAP_HOSTNAME"'@g' /etc/postfix/ldap-aliases.cf.template > /etc/postfix/ldap-aliases.cf
sed -i 's@{{LDAP_DN}}@'"$LDAP_DN"'@g' /etc/postfix/ldap-aliases.cf
sed -i 's@{{LDAP_PASSWORD}}@'"$LDAP_PASSWORD"'@g' /etc/postfix/ldap-aliases.cf
sed -i 's@{{LDAP_ALIASES}}@'"$LDAP_ALIASES"'@g' /etc/postfix/ldap-aliases.cf


postconf -e smtpd_tls_cert_file="/etc/postfix/certs/certs/$HOSTNAME.crt"
postconf -e smtpd_tls_key_file="/etc/postfix/certs/private/$HOSTNAME.key"

echo "- Staring rsyslog and postfix"
exec supervisord -c /etc/supervisord.conf
