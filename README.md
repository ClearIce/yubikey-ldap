# https://github.com/Yubico/python-fido2

Udev rule for allowing HID access to Yubico devices for FIDO support:

KERNEL=="hidraw*", SUBSYSTEM=="hidraw", \
  MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"

python_ldap-3.2.0-cp38-cp38-win32.whl downloaded from:
https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-ldap