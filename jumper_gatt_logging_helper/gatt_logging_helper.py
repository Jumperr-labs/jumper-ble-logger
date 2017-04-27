from __future__ import absolute_import, division, print_function, unicode_literals

import socket
import pty
import os
import subprocess
import select
import struct
import logging
import argparse
from StringIO import StringIO
from io import SEEK_CUR

import collections
import construct
from construct import FieldError, RawCopy, Rebuffered
from hci_protocol import HciPacketConstruct
from hci_protocol_acldata import ATT_CID
import gatt_protocol

CHARACTARISTIC_TO_NOTIFY = int('8ff456780a294a73ab8db16ce0f1a2df', 16)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class HciProxy(object):
    def __init__(self, hci_device_number=0):
        self._hci_socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
        self._hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP, 1)
        self._hci_socket.setsockopt(
            socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIH2x", 0xffffffffL, 0xffffffffL, 0xffffffffL, 0)
        )
        self._hci_socket.bind((hci_device_number,))

        self._pty_master, pty_slave = pty.openpty()
        self.pty_f = os.fdopen(self._pty_master, 'rwb')
        hci_tty = os.ttyname(pty_slave)
        log.info('TTY Slave: {}'.format(hci_tty))
        raw_input("Enter to continue")
        output = subprocess.check_output(['hciattach', hci_tty, 'any'])
        if output != 'Device setup complete\n':
            raise RuntimeError("Could not run hciattach on PTY device. Output from call command is: {}".format(output))

        # output = subprocess.check_output(['hciconfig', 'hci1', 'up'])
        self._inputs = [self.pty_f, self._hci_socket]
        self._hci_device_number = hci_device_number

        self._pty_buffer = StringIO()

        self.state = State(
            connection_handle=None, log_handle=None, awaiting_my_write_response=False, pending_write_requests=[]
        )

    def run(self):
        while True:
            readable, _, _ = select.select(self._inputs, [], [])
            for s in readable:
                if s is self.pty_f:
                    data = os.read(self._pty_master, 4096)
                    log.debug('Raw PTY data: %s', repr(data))
                    self._pty_buffer.write(data)
                    self._pty_buffer.seek(-len(data), SEEK_CUR)
                    parsed_packet = RawCopy(HciPacketConstruct).parse_stream(self._pty_buffer)
                    # packet = HciPacketConstruct.parse_stream(self._pty_buffer)
                    # packet = os.read(self._pty_master, 4096)
                    log.debug('PTY: %s', parsed_packet)
                    self._hci_socket.sendall(parsed_packet.data)
                elif s is self._hci_socket:
                    packet = self._hci_socket.recv(4096)
                    log.debug('SOCKET: %s', RawCopy(HciPacketConstruct).parse(packet))
                    action = handle_packet(packet, self.state)
                    log.debug('Action: %s', action)
                    self.state = action.new_state

                    if action.packet_to_send_to_socket is not None:
                        log.debug(
                            'Sending additional packet: %s',
                            RawCopy(HciPacketConstruct).parse(action.packet_to_send_to_socket)
                        )
                        self._hci_socket.sendall(action.packet_to_send_to_socket)

                    if action.packet_to_send_to_pty is not None:
                        log.debug(
                            'Sending additional PTY: %s',
                            RawCopy(HciPacketConstruct).parse(action.packet_to_send_to_pty)
                        )
                        os.write(self._pty_master, action.packet_to_send_to_pty)

                    if not action.should_block_current_packet:
                        log.debug('Sending packet to PTY')
                        os.write(self._pty_master, packet)


class State(collections.namedtuple('_State', [
    'connection_handle',
    'log_handle',
    'awaiting_my_write_response',
    'pending_write_requests',
])):
    def modify(self, **kwargs):
        key_values = {k: getattr(self, k) for k in self._fields}
        key_values.update(kwargs)
        return State(**key_values)


Action = collections.namedtuple(
    'Action', 'new_state should_block_current_packet packet_to_send_to_socket packet_to_send_to_pty'
)


def handle_packet(packet, state):
    try:
        parsed_packet = HciPacketConstruct.parse(packet)
    except:
        log.warn('parsing exception')
        parsed_packet = None
        raise

    if parsed_packet:
        if is_read_bd_addr_command_complete_event_packet(parsed_packet):
            new_packet = parsed_packet
            new_packet.payload.payload.payload = '00:1a:7d:da:71:01'
            new_packet_encoded = HciPacketConstruct.build(new_packet)
            return Action(
                new_state=state,
                should_block_current_packet=True,
                packet_to_send_to_socket=None,
                packet_to_send_to_pty=new_packet_encoded
            )

        if is_read_by_type_response_packet(parsed_packet):
            log.debug('read by type response')
            jumper_handle = find_jumper_handle_in_read_by_type_response_packet(parsed_packet)
            connection_handle = get_connection_handle_from_acl_data_packet(parsed_packet)
            if jumper_handle is not None:
                log.info('found jumper handle')
                new_state = state.modify(
                    connection_handle=connection_handle, log_handle=jumper_handle, awaiting_my_write_response=True
                )
                return Action(
                    new_state=new_state,
                    should_block_current_packet=False,
                    packet_to_send_to_socket=
                    gatt_protocol.create_start_notifying_on_handle_packet(connection_handle, jumper_handle),
                    packet_to_send_to_pty=None
                )

        # elif is_write_request_packet(packet) and state.awaiting_my_write_response:
        #     new_state = state.modify(pending_write_responses=(state.pending_write_responses or []).append(packet))
        #     return Action(new_state, True, None)

        elif is_write_response_packet(parsed_packet) and state.awaiting_my_write_response:
            log.info('write response packet while awaiting')
            new_state = state.modify(awaiting_my_write_response=False)
            return Action(new_state, True, None, None)

    return Action(state, False, None, None)


def is_read_bd_addr_command_complete_event_packet(parsed_packet):
    return parsed_packet.type == 'HCI_EVENT_PKT' and \
        parsed_packet.payload.event == 'EVT_CMD_COMPLETE' and \
        parsed_packet.payload.payload.ogf == 'INFORMATIONAL_PARAMETERS' and \
        parsed_packet.payload.payload.ocf == 'READ_BD_ADDR_CMD'


def is_read_by_type_response_packet(parsed_packet):
    try:
        return parsed_packet.type == 'HCI_ACLDATA_PKT' and \
               parsed_packet.payload.payload.cid == ATT_CID and \
               parsed_packet.payload.payload.payload.opcode == 'ATT_OP_READ_BY_TYPE_RESP'
    except AttributeError:
        log.warn('Attribute error on packet: {}'.format(parsed_packet))
        raise


def find_jumper_handle_in_read_by_type_response_packet(parsed_packet):
    for handle_value_pair in parsed_packet.payload.payload.payload.payload.attribute_data_list:
        characteristic_declaration = gatt_protocol.parse_characteristic_declaration(handle_value_pair.value)
        try:
            if characteristic_declaration.uuid == CHARACTARISTIC_TO_NOTIFY:
                return characteristic_declaration.value_handle
        except ValueError:
            pass
    return None


def get_connection_handle_from_acl_data_packet(parsed_packet):
    return parsed_packet.payload.handle


def is_write_response_packet(parsed_packet):
    try:
        return parsed_packet.type == 'HCI_ACLDATA_PKT' and \
               parsed_packet.payload.payload.cid == ATT_CID and \
               parsed_packet.payload.payload.payload.opcode == 'ATT_OP_WRITE_RESP'
    except AttributeError:
        print(parsed_packet)
        raise


def main():
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser()
    parser.add_argument('--hci', type=int, default=0, help='The number of HCI device to connect to')
    parser.add_argument('--verbose', '-v', action='count', help='Verbosity, call this flag twice for ultra verbose')
    parser.add_argument('--log-file', type=str, default=None, help='Dumps log to file')
    args = parser.parse_args()
    if args.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif args.verbose > 1:
        logging.basicConfig(level=logging.DEBUG)
    if args.log_file is not None:
        log.addHandler(logging.FileHandler(args.log_file))
    hci_proxy = HciProxy(args.hci)
    try:
        hci_proxy.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
