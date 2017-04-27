from __future__ import absolute_import, division, print_function, unicode_literals

import logging
from construct import *
from hci_protocol_acldata import HciAclDataPacketConstruct, create_write_request_acl_packet

log = logging.getLogger(__name__)


def ByteSwappedKnownSize(subcon, size):
    return Restreamed(subcon,
        lambda s: s[::-1], size,
        lambda s: s[::-1], size,
        lambda n: n)


MacAddress = ExprAdapter(Byte[6],
                         encoder=lambda obj, ctx: [x for x in reversed([int(part, 16) for part in obj.split(":")])],
                         decoder=lambda obj, ctx: ":".join("%02x" % b for b in reversed(obj)), )


ogf = Enum(BitsInteger(6), INFORMATIONAL_PARAMETERS=0x04, default=Pass)
ocf = Switch(
    this.ogf,
    {
        'INFORMATIONAL_PARAMETERS': Enum(BitsInteger(10), READ_BD_ADDR_CMD=0x0009, default=Pass)
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

HciEventPacketCompleteConstruct = "hci_event_packet_complete" / Struct(
    "ncmd" / Int8ul,
    Embedded(OgfOcfPair),
    "status" / Int8ul,
    "payload" / Switch(
        this.ogf,
        {
            'INFORMATIONAL_PARAMETERS': Switch(this.ocf, {'READ_BD_ADDR_CMD': MacAddress}, default=Array(this._.length - 4, Byte)),
        },
        default=Array(this._.length - 4, Byte),
    )
)

HciCommandPacket = "hci_command_packet" / Struct(
    Embedded(OgfOcfPair),
    "length" / Int8ul,
    "payload" / Array(this.length, Byte),
)

HciLeMetaEventConnectionCompleteConstruct = "hci_le_meta_event_connection_complete" / Struct(
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

HciLeConnectionUpdateCompleteConstruct = "hci_evt_le_conn_update_complete" / Struct(
    "status" / Int8ul,
    "handle" / Int16ul,
    "interval" / Int16ul,
    "latency" / Int16ul,
    "supv_timeout" / Int16ul
)

HciLeMetaEventConstruct = "hci_le_meta_event" / Struct(
    "subevent" / Enum(Int8ul,
                      EVT_LE_CONN_COMPLETE=0x01,
                      EVT_LE_CONN_UPDATE_COMPLETE=0x03,
                      default=Pass
                      ),
    "payload" / Switch(this.subevent,
                       {
                           "EVT_LE_CONN_COMPLETE": HciLeMetaEventConnectionCompleteConstruct,
                           "EVT_LE_CONN_UPDATE_COMPLETE": HciLeConnectionUpdateCompleteConstruct
                       }, default=Array(this._.length - 1, Byte)
                       )
)

HciDisconnectEventConstruct = "hci_disconnect_event" / Struct(
    "status" / Int8ul,
    "handle" / Int16ul,
    "reason" / Int8ul
)

HciNumCompPktsEventConstruct = "hci_num_comp_packets_event" / Struct(
    "num_handles" / Int8ul,
    "results" / Array(this.num_handles, Struct(
        "handle" / Int16ul,
        "packets" / Int16ul
    )),
)

HciEventPacketConstruct = "hci_event_packet" / Struct(
    "event" / Enum(Int8ul,
                   EVT_DISCONN_COMPLETE=0x05,
                   EVT_CMD_COMPLETE=0x0E,
                   EVT_INQUIRY_COMPLETE=0x0F,
                   EVT_NUM_COMP_PKTS=0x13,
                   EVT_LE_META_EVENT=0x3E,
                   default=Pass
                   ),
    "length" / Rebuild(Int8ul, lambda x: HciEventPacketCompleteConstruct.sizeof(x.payload)),
    "payload" / Switch(this.event,
                       {
                           "EVT_CMD_COMPLETE": HciEventPacketCompleteConstruct,
                           "EVT_LE_META_EVENT": HciLeMetaEventConstruct,
                           "EVT_DISCONN_COMPLETE": HciDisconnectEventConstruct,
                           "EVT_NUM_COMP_PKTS": HciNumCompPktsEventConstruct,
                       }, default=Array(this.length, Byte),
                       ),
)

HciPacketConstruct = "hci_packet" / Struct(
    "type" / Enum(Int8ul,
                  HCI_COMMAND_PKT=0x01,
                  HCI_ACLDATA_PKT=0x02,
                  HCI_SCODATA_PKT=0x03,
                  HCI_EVENT_PKT=0x04,
                  default=Pass
                  ),
    "payload" / Switch(this.type,
                       {
                           "HCI_COMMAND_PKT": HciCommandPacket,
                           "HCI_EVENT_PKT": HciEventPacketConstruct,
                           "HCI_ACLDATA_PKT": HciAclDataPacketConstruct
                       }, default=Pass
                       ),
)


def create_write_request_packet(connection_handle, handle, data):
    HciPacketConstruct.build(
        dict(
            type='HCI_ACLDATA_PKT',
            payload=create_write_request_acl_packet(connection_handle, handle, data)
        )
    )
