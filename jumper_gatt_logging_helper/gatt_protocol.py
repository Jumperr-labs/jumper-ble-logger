from __future__ import absolute_import, division, print_function, unicode_literals

import logging
from construct import *
import hci_protocol
from hci_protocol_acldata import ATT_CID

NOTIFY_ON = 1


def parse_characteristic_declaration(value):
    if len(value) < 4:
        raise ValueError('Size of value for characteristic declaration must be > 4')
    CharacteristicDeclarationConstruct = "characteristic_delaration" / Struct(
        "properties" / Int8ul,
        "value_handle" / Int16ul,
        "uuid" / BytesInteger(len(value) - 3, swapped=True)
    )

    return CharacteristicDeclarationConstruct.parse(value)


def create_start_notifying_on_handle_packet(connection_handle, handle):
    hci_protocol.create_write_request_packet(connection_handle, handle+1, NOTIFY_ON)
