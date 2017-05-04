from __future__ import absolute_import, division, print_function, unicode_literals

import socket
from ctypes import *

error = socket.error

HCI_CHANNEL_USER = 1

cdll = LibraryLoader(CDLL)
cdll.LoadLibrary("libc.so.6")
libc = CDLL("libc.so.6", use_errno=True)

socket_c = libc.socket
socket_c.argtypes = (c_int, c_int, c_int)
socket_c.restype = c_int


class SockAddrHCI(Structure):
    _fields_ = [
        ("sin_family",      c_ushort),
        ("hci_dev",         c_ushort),
        ("hci_channel",     c_ushort),
    ]

sockaddr_hci_pointer = POINTER(SockAddrHCI)
bind = libc.bind
bind.argtypes = (c_int, POINTER(SockAddrHCI), c_int)
bind.restype = c_int


def create_bt_socket_hci_channel_user(hci_device_number=0):
    s = socket_c(socket.AF_BLUETOOTH, socket.SOCK_RAW, HCI_CHANNEL_USER)
    if s < 0:
        raise error("Could not open socket")

    sock_addr = SockAddrHCI()
    sock_addr.sin_family = socket.AF_BLUETOOTH
    sock_addr.hci_dev = hci_device_number
    sock_addr.hci_channel = HCI_CHANNEL_USER

    r = bind(s, sockaddr_hci_pointer(sock_addr), sizeof(sock_addr))
    if r != 0:
        raise error("Could not bind bind socket")

    return socket.fromfd(s, socket.AF_BLUETOOTH, socket.SOCK_RAW, HCI_CHANNEL_USER)
