#!/usr/bin/python3
import os
from pathlib import Path
from shutil import chown
import subprocess

if __name__ == "__main__":
    root_ldap = 'dc='+',dc='.join(os.getenv('LDAP_HOSTNAME').split('.'))    
    bootstrap_ldif = Path("/etc/openldap/scripts/bootstrap.ldif.template").read_text()
    bootstrap_ldif = bootstrap_ldif.replace('{{ROOT_LDAP}}', root_ldap)

    Path("/etc/openldap/scripts/bootstrap.ldif").write_text(bootstrap_ldif)
    
    if Path("/etc/openldap/slapd.conf").is_file():
        Path("/etc/openldap/slapd.conf").unlink()
    if not Path("/etc/openldap/slapd.d").is_dir():
        Path("/etc/openldap/slapd.d").mkdir()
        bootstrap_slapd = subprocess.Popen("/usr/sbin/slapadd -n0 -F /etc/openldap/slapd.d -l /etc/openldap/scripts/bootstrap.ldif", shell=True, stdout=subprocess.PIPE)
        bootstrap_slapd.wait()

    chown(str(Path("/etc/openldap/slapd.d")), user="ldap", group="ldap")
    for s in Path("/etc/openldap/slapd.d").glob("**/*"):
        chown(str(s), user="ldap", group="ldap")
