from __future__ import absolute_import, division, print_function, unicode_literals

from construct import *

ATT_CID = 4

HandleValueNotificationConstruct = "handle_value_notification" / Struct(
    "handle" / Int16ul,
    "data" / Bytes(this._._.length - 3)
)

AttMtuReqPacketConstruct = "att_mtu_req_packet" / Struct(
    "req_mtu" / Int16ul
)

AttOpWriteRequestConstruct = "attribute_write_request" / Struct(
    "handle" / Int16ul,
    "data" / BytesInteger(this._._.length - 3, swapped=True)
    # "data" / Bytes(this._._.length - 3)
)


AttOpReadByGroupRespConstruct = "read_by_group_response" / Struct(

)

AttributeHandleValuePairConstruct = "attribute_handle_value_pair" / Struct(
    "handle" / Int16ul,
    "value" / Bytes(this._.length - 2)
)

AttOpReadByTypeRespConstruct = "read_by_type_response" / Struct(
    "length" / Int8ul,
    "attribute_data_list" / AttributeHandleValuePairConstruct[(this._._.length - 2)/this.length]
)

AttCmdPacketConstruct = "att_cmd_packet" / Struct(
    "opcode" / Enum(Int8ul,
                    ATT_OP_ERROR_RESP=0x01,
                    ATT_OP_MTU_REQ=0x02,
                    ATT_OP_MTU_RESP=0x03,
                    ATT_OP_READ_BY_TYPE_REQ=0x08,
                    ATT_OP_READ_BY_TYPE_RESP=0x09,
                    ATT_OP_READ_REQ=0x0A,
                    ATT_OP_READ_RESP=0x0B,
                    ATT_OP_READ_BLOB_REQ=0x0C,
                    ATT_OP_READ_BLOB_RESP=0x0D,
                    ATT_OP_READ_MULTIPLE_REQ=0x0E,
                    ATT_OP_READ_MULTIPLE_RESP=0x0F,
                    ATT_OP_READ_BY_GROUP_REQ=0x010,
                    ATT_OP_READ_BY_GROUP_RESP=0x11,
                    ATT_OP_HANDLE_NOTIFY=0x1B,
                    ATT_OP_WRITE_REQ=0x12,
                    ATT_OP_WRITE_RESP=0x13,
                    default=Pass
                    ),
    "payload" / Switch(this.opcode, {
        "ATT_OP_MTU_REQ": AttMtuReqPacketConstruct,
        "ATT_OP_MTU_RESP": AttMtuReqPacketConstruct,
        "ATT_OP_READ_BY_TYPE_RESP": AttOpReadByTypeRespConstruct,
        "ATT_OP_READ_BY_GROUP_RESP": AttOpReadByGroupRespConstruct,
        "ATT_OP_HANDLE_NOTIFY": HandleValueNotificationConstruct,
        "ATT_OP_WRITE_REQ": AttOpWriteRequestConstruct,
        "ATT_OP_WRITE_RESP": Pass
    }, default=Array(this._.length - 1, Byte))
)

L2CapPacketConstruct = "l2cap_packet" / Struct(
    "length" / Int16ul,
    # "length" / Rebuild(Int16ul, lambda x: AttCmdPacketConstruct.sizeof(x.payload)),
    "cid" / Int16ul,
    "payload" / Switch(this.cid, {
        ATT_CID: AttCmdPacketConstruct
    }, default=Array(this.length, Byte))
)

HciAclDataPacketConstruct = "hci_acl_data_packet" / Struct(
    Embedded(ByteSwapped(
        BitStruct(
            "flags" / BitsInteger(4),
            "handle" / BitsInteger(12)
        )
    )),
    # "length" / Int16ul, #Rebuild(Int16ul, len_(this.payload)),
    "length" / Rebuild(Int16ul, this.payload.length + 4),
    "payload" / L2CapPacketConstruct
)


# def create_write_request_acl_packet(connection_handle, handle, data, num_bytes_for_data):
#     return HciAclDataPacketConstruct.build(
#         dict(
#             flags=0,
#             handle=connection_handle,
#             payload=dict(
#                 length=3 + num_bytes_for_data,
#                 cid=ATT_CID,
#                 payload=dict(
#                     opcode='ATT_OP_WRITE_REQ',
#                     payload=dict(
#                         handle=handle,
#                         data=data
#                     )
#                 )
#             )
#         )
#     )
