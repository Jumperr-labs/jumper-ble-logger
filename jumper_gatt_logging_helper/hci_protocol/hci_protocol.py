from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from construct import *

log = logging.getLogger(__name__)


def ByteSwappedKnownSize(subcon, size):
    r"""
    WARNING: this is a hack for using ByteSwapped on ocf which is created by switch, better to avoid this when you can
    Swap the byte order within boundaries of the given subcon.
    
    :param subcon: the subcon on top of byte swapped bytes
    
    :param size: The size of returned item in Bytes
    
    Example::
    
        Int24ul <--> ByteSwapped(Int24ub)
    """
    return Restreamed(
        subcon,
        lambda s: s[::-1], size,
        lambda s: s[::-1], size,
        lambda n: n
    )


# ============================================================================
# COMMON
# ============================================================================
MacAddress = ExprAdapter(Byte[6],
                         encoder=lambda obj, ctx: [x for x in reversed([int(part, 16) for part in obj.split(":")])],
                         decoder=lambda obj, ctx: ":".join("%02x" % b for b in reversed(obj)),
                         )


# ============================================================================
# HCI COMMAND PACKET
# ============================================================================
ogf = Enum(BitsInteger(6),
           INFORMATIONAL_PARAMETERS=0x04,
           default=Pass
           )

ocf = Switch(
    this.ogf,
    {
        'INFORMATIONAL_PARAMETERS': Enum(BitsInteger(10), READ_BD_ADDRESS_COMMAND=0x0009, default=Pass)
    },
    default=BitsInteger(10)
)

OgfOcfPair = ByteSwappedKnownSize(
    BitStruct(
        "ogf" / ogf,
        "ocf" / ocf
    ),
    2
)

HciCommandPacket = "hci_command_packet" / Struct(
    Embedded(OgfOcfPair),
    "length" / Int8ul,
    "payload" / Array(this.length, Byte),
)


# ============================================================================
# ACL DATA PACKET
# ============================================================================
ATT_CID = 4

AttMtuRequestPacket = "att_mtu_request_packet" / Struct(
    "client_mtu" / Int16ul
)

AttMtuResponsePacket = "att_mtu_response_packet" / Struct(
    "server_mtu" / Int16ul
)

AttributeHandleValuePair = "attribute_handle_value_pair" / Struct(
    "handle" / Int16ul,
    "value" / Bytes(this._.length - 2)
)

AttReadByTypeResponse = "read_by_type_response" / Struct(
    "length" / Int8ul,
    "attribute_data_list" / AttributeHandleValuePair[(this._._.length - 2) / this.length]
)

AttReadByGroupResponse = "read_by_group_response" / Struct(

)

HandleValueNotification = "handle_value_notification" / Struct(
    "handle" / Int16ul,
    "data" / Bytes(this._._.length - 3)
)

AttWriteRequest = "att_write_request" / Struct(
    "handle" / Int16ul,
    "data" / BytesInteger(this._._.length - 3, swapped=True)
)

AttCommandPacket = "att_command_packet" / Struct(
    "opcode" / Enum(Int8ul,
                    ATT_OP_ERROR_RESPONSE=0x01,
                    ATT_OP_MTU_REQUEST=0x02,
                    ATT_OP_MTU_RESPONSE=0x03,
                    ATT_OP_READ_BY_TYPE_REQUEST=0x08,
                    ATT_OP_READ_BY_TYPE_RESPONSE=0x09,
                    ATT_OP_READ_REQUEST=0x0A,
                    ATT_OP_READ_RESPPONSE=0x0B,
                    ATT_OP_READ_BLOB_REQUEST=0x0C,
                    ATT_OP_READ_BLOB_RESPPONSE=0x0D,
                    ATT_OP_READ_MULTIPLE_REQUEST=0x0E,
                    ATT_OP_READ_MULTIPLE_RESPPONSE=0x0F,
                    ATT_OP_READ_BY_GROUP_REQUEST=0x010,
                    ATT_OP_READ_BY_GROUP_RESPPONSE=0x11,
                    ATT_OP_HANDLE_NOTIFY=0x1B,
                    ATT_OP_WRITE_REQUEST=0x12,
                    ATT_OP_WRITE_RESPPONSE=0x13,
                    default=Pass
                    ),
    "payload" / Switch(this.opcode, {
        "ATT_OP_MTU_REQUEST": AttMtuRequestPacket,
        "ATT_OP_MTU_RESPONSE": AttMtuResponsePacket,
        "ATT_OP_READ_BY_TYPE_RESPONSE": AttReadByTypeResponse,
        "ATT_OP_READ_BY_GROUP_RESPPONSE": AttReadByGroupResponse,
        "ATT_OP_HANDLE_NOTIFY": HandleValueNotification,
        "ATT_OP_WRITE_REQUEST": AttWriteRequest,
        "ATT_OP_WRITE_RESPPONSE": Pass
    }, default=Array(this._.length - 1, Byte))
)

L2CapPacket = "l2cap_packet" / Struct(
    "length" / Int16ul,
    "cid" / Int16ul,
    "payload" / Switch(this.cid, {
        ATT_CID: AttCommandPacket
    }, default=Array(this.length, Byte))
)

AclDataPacket = "hci_acl_data_packet" / Struct(
    Embedded(ByteSwapped(
        BitStruct(
            "flags" / BitsInteger(4),
            "handle" / BitsInteger(12)
        )
    )),
    "length" / Rebuild(Int16ul, this.payload.length + 4),
    "payload" / L2CapPacket
)


# ============================================================================
# HCI EVENT PACKET
# ============================================================================
CommandCompletedEvent = "command_complete_event" / Struct(
    "ncmd" / Int8ul,
    Embedded(OgfOcfPair),
    "status" / Int8ul,
    "payload" / Switch(
        this.ogf,
        {
            'INFORMATIONAL_PARAMETERS': Switch(this.ocf,
                                               {'READ_BD_ADDRESS_COMMAND': MacAddress},
                                               default=Array(this._.length - 4, Byte)
                                               ),
        },
        default=Array(this._.length - 4, Byte),
    )
)

DisconnectEvent = "hci_disconnect_event" / Struct(
    "status" / Int8ul,
    "handle" / Int16ul,
    "reason" / Int8ul
)

LeConnectionCompleteEvent = "connection_complete_event" / Struct(
    "status" / Int8ul,
    "handle" / Int16ul,
    "role" / Int8ul,
    "peer_bdaddr_type" / Int8ul,
    "peer_bdaddr" / MacAddress,
    "interval" / Int16ul,
    "latency" / Int16ul,
    "supervision_timeout" / Int16ul,
    "master_clock_accuracy" / Int8ul
)

LeConnectionUpdateCompleteEvent = "hci_evt_le_conn_update_complete" / Struct(
    "status" / Int8ul,
    "handle" / Int16ul,
    "interval" / Int16ul,
    "latency" / Int16ul,
    "supv_timeout" / Int16ul
)

LeMetaEvent = "hci_le_meta_event" / Struct(
    "subevent" / Enum(Int8ul,
                      LE_CONNECTION_COMPLETED=0x01,
                      LE_CONNECTION_UPDATE_COMPLETED=0x03,
                      default=Pass
                      ),
    "payload" / Switch(this.subevent,
                       {
                           "LE_CONNECTION_COMPLETED": LeConnectionCompleteEvent,
                           "LE_CONNECTION_UPDATE_COMPLETED": LeConnectionUpdateCompleteEvent
                       }, default=Array(this._.length - 1, Byte)
                       )
)


NumberOfCompletedPpacketsEvent = "hci_num_comp_packets_event" / Struct(
    "num_handles" / Int8ul,
    "results" / Array(this.num_handles, Struct(
        "handle" / Int16ul,
        "packets" / Int16ul
    )),
)

HciEventPacketConstruct = "hci_event_packet" / Struct(
    "event" / Enum(Int8ul,
                   DISCONNECTION_COMPLETE=0x05,
                   COMMAND_COMPLETE=0x0E,
                   COMMAND_STATUS=0x0F,
                   NUMBER_OF_COMPLETED_PACKETS=0x13,
                   LE_META_EVENT=0x3E,
                   default=Pass
                   ),
    "length" / Rebuild(Int8ul, lambda x: CommandCompletedEvent.sizeof(x.payload)),
    "payload" / Switch(this.event,
                       {
                           "DISCONNECTION_COMPLETE": DisconnectEvent,
                           "COMMAND_COMPLETE": CommandCompletedEvent,
                           "NUMBER_OF_COMPLETED_PACKETS": NumberOfCompletedPpacketsEvent,
                           "LE_META_EVENT": LeMetaEvent
                       }, default=Array(this.length, Byte),
                       ),
)


# ============================================================================
# HCI SYNCHRONOUS DATA PACKET
# ============================================================================
HciSynchronousDataPacket = "hci_synchronous_data_packet" / Struct(
    Embedded(
        ByteSwapped(
            Struct(
                "connection_handle" / BytesInteger(12),
                "packet_status_flag" / BitsInteger(2),
                "RFU" / BitsInteger(2)
            )
        )
    ),
    "data_total_length" / Int8ul,
    "data" / Bytes(this.length)
)

# ============================================================================
# HCI PACKET
# ============================================================================
HciPacket = "hci_packet" / Struct(
    "type" / Enum(Int8ul,
                  COMMAND_PACKET=0x01,
                  ACL_DATA_PACKET=0x02,
                  SYNCHRONOUS_DATA_PACKET=0x03,
                  EVENT_PACKET=0x04,
                  default=Pass
                  ),
    "payload" / Switch(this.type,
                       {
                           "COMMAND_PACKET": HciCommandPacket,
                           "ACL_DATA_PACKET": AclDataPacket,
                           "EVENT_PACKET": HciEventPacketConstruct,
                           "SYNCHRONOUS_DATA_PACKET": HciSynchronousDataPacket
                       }, default=Pass
                       ),
)
