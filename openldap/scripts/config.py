#!/usr/bin/python3
import os
import ldap3
import re
import crypt
from pathlib import Path
from time import sleep

def ldap_connect():
    s = ldap3.Server('ldapi:///var/run/openldap/slapd.sock')
    c = ldap3.Connection(s,
                         authentication=ldap3.SASL,
                         sasl_mechanism=ldap3.EXTERNAL,
                         sasl_credentials='',
                         auto_bind = True,
                         version=3)
    return s, c

if __name__ == "__main__":
    while True:
        try:
            s, c = ldap_connect()
            break
        except ldap3.core.exceptions.LDAPSocketOpenError:
            sleep(0.1)

    domain = os.getenv('LDAP_HOSTNAME')
    root = 'dc='+',dc='.join(domain.split('.'))
    password = '{CRYPT}' + crypt.crypt(os.getenv('LDAP_PASSWORD'), "$6$.16s")
    
    ### --- Modules management ---
    ldap_modules = [
        'memberof',
        'refint',
        'ppolicy'
    ]
    current_modules = []
    ldap_modules_modification = []
    c.search(search_base = 'cn=module{0},cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.SUBTREE,
             attributes=['olcModuleLoad']
    )
    for response in c.response:
        for module in response['raw_attributes']['olcModuleLoad']:
            module = re.sub('\{\d+\}', '', module.decode())
            current_modules.append(module)

    for module in ldap_modules:
        if module not in current_modules:
            ldap_modules_modification.append((ldap3.MODIFY_ADD, [module]))

    if ldap_modules_modification:
        c.modify('cn=module{0},cn=config', {
            'olcModuleLoad': ldap_modules_modification
        })
        if c.result['description'] != 'success':
            print("Error while adding module")
            exit(1)
        s, c = ldap_connect()

    ### --- PPolicy ---
    # Add ppolicy entry
    c.search(search_base = 'olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE
    )
    if not c.response:
        c.add('olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config',
              attributes={'objectClass': ['olcOverlayConfig', 'olcPPolicyConfig']})
        if c.result['description'] != 'success':
            print("Error while adding ppolicy overlay entry")
            exit(1)

    c.search(search_base = 'olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.SUBTREE,
             attributes=['olcPPolicyHashCleartext']
    )
    if not c.response[0]['attributes']:
        c.modify('olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config',
                 {
                     'olcPPolicyHashCleartext': [(ldap3.MODIFY_ADD, ['TRUE'])]
                 })
        if c.result['description'] != 'success':
            print("Error while adding ppolicy overlay configuration")
            exit(1)

    ### --- Security features ---
    security_features = {
        'olcLocalSSF': '256',
        'olcPasswordHash': '{CRYPT}',
        'olcPasswordCryptSaltFormat': '$6$%.16s',
        'olcTLSCertificateFile': '/etc/openldap/certs/' + domain + '.crt',
        'olcTLSCertificateKeyFile': '/etc/openldap/certs/' + domain + '.key',
        'olcTLSCACertificateFile': '/etc/openldap/certs/' + domain + '.crt',
        'olcTLSProtocolMin': '3.3'
    }

    current_features = {}
    ldap_modules_modification = []
    c.search(search_base = 'cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE,
             attributes=ldap3.ALL_ATTRIBUTES
    )
    for response in c.response:
        for k,v in response['raw_attributes'].items():
            current_features[k] = v[0].decode()

    ldap_features_modification = {}
    for name, value in security_features.items():
        if name not in current_features or current_features[name] != value:
            ldap_features_modification[name] = [(ldap3.MODIFY_REPLACE, [value])]

    if ldap_features_modification:
        c.modify('cn=config',
                 ldap_features_modification)
        if c.result['description'] != 'success':
            print("Error while adding security configuration")
            exit(1)

    # Security connection
    ldap_security = [
        'simple_bind=0',
        'update_ssf=0',
        'ssf=0',
        'tls=0'
    ]
    current_security = []
    ldap_security_modification = []
    c.search(search_base = 'olcDatabase={1}mdb,cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE,
             attributes=['olcSecurity']
    )
    for response in c.response:
        if 'olcSecurity' in response['raw_attributes']:
            for security in response['raw_attributes']['olcSecurity']:
                current_security.append(security.decode())

    for security in ldap_security:
        if security not in current_security:
            ldap_security_modification.append((ldap3.MODIFY_ADD, [security]))

    if ldap_security_modification:
        c.modify('olcDatabase={1}mdb,cn=config', {
            'olcSecurity': ldap_security_modification
        })
        if c.result['description'] != 'success':
            print("Error while adding security")
            exit(1)    

    # Indexes
    ldap_indexes = [
        'objectClass eq',
        'cn eq,pres',
        'gn eq,pres',
        'sn eq,pres',
        'uid eq',
        'uidNumber eq',
        'gidNumber eq',
        'memberUid eq',
        'uniqueMember eq',
        'mail eq',
        'mozillaSecondEmail eq',
        'dc eq',
        'host eq',
        'entryCSN eq',
        'entryUUID eq'
    ]

    ### --- Indexes ---
    current_index = []
    c.search(search_base = 'olcDatabase={1}mdb,cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE,
             attributes=['olcDbIndex']
    )
    for response in c.response:
        if 'olcDbIndex' in response['raw_attributes']:
            for index in response['raw_attributes']['olcDbIndex']:
                current_index.append(index.decode())

    edit_indexes = False
    for index in ldap_indexes:
        if index not in current_index:
            edit_indexes = True

    if edit_indexes:
        c.modify('olcDatabase={1}mdb,cn=config', {
            'olcDbIndex': [(ldap3.MODIFY_REPLACE, ldap_indexes)]})
        if c.result['description'] != 'success':
            print("Error while adding index")
            exit(1)

    ### --- ACLs ---
    ldap_acls = [
        '{0}to attrs=userPassword,shadowLastChange' +
        ' by anonymous auth' +
        ' by dn.exact="gidNumber =0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage' +
        ' by self write' +
        ' by * none',
        '{1}to dn.sub="ou=users,ou=virtual,'+root+'"' +
        ' by anonymous auth' +
        ' by dn.exact="gidNumber =0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage' +
        ' by self write' +
        ' by * none',
        '{2}to *' +
        ' by dn.exact="gidNumber =0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage' +
        ' by dn.base="cn=admin,'+root+'" read' +
        ' by * none'
    ]
    current_acls = []
    c.search(search_base = 'olcDatabase={1}mdb,cn=config',
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE,
             attributes=['olcAccess']
    )
    for response in c.response:
        if 'olcAccess' in response['raw_attributes']:
            for acl in response['raw_attributes']['olcAccess']:
                current_acls.append(acl.decode())

    edit_acls = False
    for acl in ldap_acls:
        if acl not in current_acls:
            edit_acls = True

    if edit_acls:
        c.modify('olcDatabase={1}mdb,cn=config', {
            'olcAccess': [(ldap3.MODIFY_REPLACE, ldap_acls)]})
        if c.result['description'] != 'success':
            print("Error while adding ACL")
            exit(1)

    # Root structure
    c.search(search_base = root,
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE
    )
    if not c.response:
        c.add(root,
              attributes={'objectClass': ['organization', 'dcObject', 'top'], 'o': domain, 'dc': domain.split('.')[0]})


    # Admin User
    c.search(search_base = 'cn=admin,' + root,
             search_filter = '(objectClass=*)',
             search_scope = ldap3.BASE
    )
    if not c.response:
        c.add('cn=admin,' + root,
              attributes={'objectClass': ['simpleSecurityObject', 'organizationalRole'], 'cn': 'admin', 'userPassword': password})
    
    # Structure
    for base in [
            'ou=virtual',
            'ou=users,ou=virtual',
            'ou=groups,ou=virtual',
            'ou=domains,ou=virtual',
            'ou=aliases,ou=virtual'
    ]:

        c.search(search_base = base+','+root,
                 search_filter = '(objectClass=*)',
                 search_scope = ldap3.BASE
        )
        if not c.response:
            c.add(base+','+root,
                  attributes={'objectClass': ['organizationalUnit']})
            if c.result['description'] != 'success':
                print("Error while adding structure")
                exit(1)
