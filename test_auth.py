from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from fido2.ctap2 import AttestedCredentialData
from getpass import getpass
from fido2.utils import websafe_encode, websafe_decode

import sys
import ldap

use_prompt = False
pin = None
uv = "discouraged"

if WindowsClient.is_available():
    # Use the Windows WebAuthn API if available
    client = WindowsClient("https://testrandomdomainthatsurelydoesntexist123.com")
else:
    print("No client available")


server = Fido2Server({"id": "testrandomdomainthatsurelydoesntexist.com", "name": "Example RP"}, attestation="direct")

#LDAP Query
SCOPE_SUBTREE = 2
l = ldap.initialize('ldap://192.168.159.131:389')
result = l.search_s('ou=People,dc=testldap,dc=com', SCOPE_SUBTREE)
print(result[1][1]['credential'])
ldap_encoded = result[1][1]['credential'][0]

credentials = [AttestedCredentialData(websafe_decode(ldap_encoded))] # authenticate_begin requires array

print("CREDENTIALS: ", credentials)

request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
# if use_prompt:
#     print("\nTouch your authenticator device now...\n")

assertions, client_data = client.get_assertion(request_options["publicKey"], pin=pin)
assertion = assertions[0]  # Only one cred in allowCredentials, only one response.

# Complete authenticator
# This would raise an exception if it couldn't be authenticated
server.authenticate_complete(
    state,
    credentials,
    assertion.credential["id"],
    client_data,
    assertion.auth_data,
    assertion.signature,
)

print("Credential authenticated!")

print("CLIENT DATA:", client_data)
print()
print("ASSERTION DATA:", assertion)