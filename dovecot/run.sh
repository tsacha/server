#!/bin/sh
chown root:adm /var/log/mail.log
chown root:adm /var/log/mail.err
chown root:adm /var/log/mail.info
chown root:adm /var/log/mail.warn
chown 5000:5000 /var/vmails

sed -i "s#%{HOSTNAME}#$HOSTNAME#g" /etc/dovecot/dovecot.conf
sed -i "s#%{HOSTNAME}#$HOSTNAME#g" /etc/dovecot/conf.d/10-ssl.conf
sed -i "s#%{HOSTNAME}#$HOSTNAME#g" /etc/dovecot/conf.d/15-lda.conf

sed 's@{{LDAP_HOSTNAME}}@'"$LDAP_HOSTNAME"'@g' /etc/dovecot/dovecot-ldap.conf.ext.template > /etc/dovecot/dovecot-ldap.conf.ext
sed -i 's@{{LDAP_DN}}@'"$LDAP_DN"'@g' /etc/dovecot/dovecot-ldap.conf.ext
sed -i 's@{{LDAP_PASSWORD}}@'"$LDAP_PASSWORD"'@g' /etc/dovecot/dovecot-ldap.conf.ext
sed -i 's@{{LDAP_USERS}}@'"$LDAP_USERS"'@g' /etc/dovecot/dovecot-ldap.conf.ext

sed 's@{{LDAP_HOSTNAME}}@'"$LDAP_HOSTNAME"'@g' /etc/ldap/ldap.conf.template > /etc/ldap/ldap.conf

echo "- Staring rsyslog and dovecot"
exec supervisord -c /etc/supervisord.conf
