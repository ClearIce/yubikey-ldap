import ldap

SCOPE_SUBTREE = 2
l = ldap.initialize('ldap://192.168.159.131:389')
result = l.search_s('ou=People,dc=testldap,dc=com', SCOPE_SUBTREE)
print(result[1][1]['credential'])
