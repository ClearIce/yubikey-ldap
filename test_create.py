"""
Connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and authenticates the credential.
This works with both FIDO 2.0 devices as well as with U2F devices.
On Windows, the native WebAuthn API will be used.
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from getpass import getpass
from fido2.utils import websafe_encode, websafe_decode

import sys

use_prompt = False
pin = None
uv = "discouraged"

if WindowsClient.is_available():
    # Use the Windows WebAuthn API if available
    client = WindowsClient("https://testrandomdomainthatsurelydoesntexist.com")
else:
    # Locate a device
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
        use_prompt = True
    else:
        try:
            from fido2.pcsc import CtapPcscDevice

            dev = next(CtapPcscDevice.list_devices(), None)
            print("Use NFC channel.")
        except Exception as e:
            print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin https://example.com
    client = Fido2Client(dev, "https://testrandomdomainthatsurelydoesntexist.com")

    # Prefer UV if supported
    if client.info.options.get("uv"):
        uv = "preferred"
        print("Authenticator supports User Verification")
    elif client.info.options.get("clientPin"):
        # Prompt for PIN if needed
        pin = getpass("Please enter PIN: ")
    else:
        print("PIN not set, won't use")


server = Fido2Server({"id": "testrandomdomainthatsurelydoesntexist.com", "name": "Example RP"}, attestation="direct")

# id stored in DB, queried via user name
user = {"id": b"user_id", "name": "A. User"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)

# Create a credential
if use_prompt:
    print("\nTouch your authenticator device now...\n")

attestation_object, client_data = client.make_credential(
    create_options["publicKey"], pin=pin
)

# Complete registration
auth_data = server.register_complete(state, client_data, attestation_object)
credentials = [auth_data.credential_data]
# Credentials is what needs to be stored

print("New credential created!")

# https://github.com/Yubico/python-fido2/issues/31
encoded = websafe_encode(auth_data.credential_data)  # Store this value

print("Credentials: ")
print(auth_data.credential_data)
print()
print("Encoded: ")
print(encoded)
#credential_data = AttestedCredentialData(websafe_decode(encoded))  # Restored from serialized value
