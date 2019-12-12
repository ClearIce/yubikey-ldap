from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from fido2.ctap2 import AttestedCredentialData
from getpass import getpass
from fido2.utils import websafe_encode, websafe_decode

import sys

use_prompt = False
pin = None
uv = "discouraged"

if WindowsClient.is_available():
    # Use the Windows WebAuthn API if available
    client = WindowsClient("https://example.com")
else:
    print("No client available")


server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="direct")
user = {"id": b"user_id", "name": "A. User"}

# AttestedCredentialData(aaguid: h'fa2b99dc9e3942578f924a30d23c4118', credential_id: h'06053914f45d1f4632ad727ac04211aabff3cdd8aba3d9a519e259802fefb2f70bf9e982efdf6fff1ba89bb944e281b075f11df3010eb5d5d5efad5abc0cc508', public_key: {1: 2, 3: -7, -1: 1, -2: b'\xc3\xe3\xcf>\x9c\xed\x1f1\xa9a\x80P\xaa\xbb\xbe\xf5\xfd\x0e\x84\xa3^\x83!?\xc21\xca\x86\xfe\xf0\x867', -3: b'\xa1M|B\xb1\x01\xac&\xbco\xafU\xb5\xb5\xbcU\xda\x99\xf0\x7f\xa0\xa4\xa1\x0fV\x82\x8e\x17\x83\xbb\xe1\xcd'}
encoded = b"-iuZ3J45QlePkkow0jxBGABABgU5FPRdH0YyrXJ6wEIRqr_zzdiro9mlGeJZgC_vsvcL-emC799v_xuom7lE4oGwdfEd8wEOtdXV761avAzFCKUBAgMmIAEhWCDD488-nO0fMalhgFCqu771_Q6Eo16DIT_CMcqG_vCGNyJYIKFNfEKxAawmvG-vVbW1vFXamfB_oKShD1aCjheDu-HN"
credentials = [AttestedCredentialData(websafe_decode(encoded))] 

print("CREDENTIALS: ", credentials)

request_options, state = server.authenticate_begin(credentials, user_verification=uv)

# Authenticate the credential
# if use_prompt:
#     print("\nTouch your authenticator device now...\n")

assertions, client_data = client.get_assertion(request_options["publicKey"], pin=pin)
assertion = assertions[0]  # Only one cred in allowCredentials, only one response.

# Complete authenticator
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