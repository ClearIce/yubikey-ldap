# https://github.com/Yubico/python-fido2

Udev rule for allowing HID access to Yubico devices for FIDO support:

KERNEL=="hidraw*", SUBSYSTEM=="hidraw", \
  MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"