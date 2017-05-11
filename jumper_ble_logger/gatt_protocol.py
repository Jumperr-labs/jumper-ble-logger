from __future__ import absolute_import, division, print_function, unicode_literals

from .hci_protocol.hci_protocol import *

NOTIFY_ON = 1


def parse_characteristic_declaration(value):
    if len(value) < 4:
        raise ValueError('Size of value for characteristic declaration must be > 4')

    characteristic_declaration = "characteristic_delaration" / Struct(
        "properties" / Int8ul,
        "value_handle" / Int16ul,
        "uuid" / BytesInteger(len(value) - 3, swapped=True)
    )

    return characteristic_declaration.parse(value)


def create_start_notifying_on_handle_packet(connection_handle, handle):
    return create_write_request_packet(connection_handle, handle + 1, NOTIFY_ON, 2)


def create_write_request_packet(connection_handle, handle, data, num_bytes_for_data):
    return HciPacket.build(
        dict(
            type='ACL_DATA_PACKET',
            payload=dict(
                flags=0,
                handle=connection_handle,
                payload=dict(
                    length=3 + num_bytes_for_data,
                    cid=ATT_CID,
                    payload=dict(
                        opcode='ATT_OP_WRITE_REQUEST',
                        payload=dict(
                            handle=handle,
                            data=data
                        )
                    )
                )
            )
        )
    )


def create_read_request_packet(connection_handle, handle):
    return HciPacket.build(
        dict(
            type='ACL_DATA_PACKET',
            payload=dict(
                flags=0,
                handle=connection_handle,
                payload=dict(
                    length=3,
                    cid=ATT_CID,
                    payload=dict(
                        opcode='ATT_OP_READ_REQUEST',
                        payload=dict(
                            handle=handle
                        )
                    )
                )
            )
        )
    )
