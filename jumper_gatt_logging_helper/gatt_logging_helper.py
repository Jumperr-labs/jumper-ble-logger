from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import logging
import collections
import os
import pty
import select
import subprocess
from StringIO import StringIO
from io import SEEK_CUR

import gatt_protocol
from hci_channel_user_socket import create_bt_socket_hci_channel_user
from hci_protocol.hci_protocol import *

CHARACTERISTIC_TO_NOTIFY = int('8ff456780a294a73ab8db16ce0f1a2df', 16)

# log.setLevel(logging.DEBUG)


class HciProxy(object):
    def __init__(self, hci_device_number=0, logger=None):
        self._logger = logger or logging.getLogger(__name__)

        self._hci_device_number = hci_device_number
        try:
            subprocess.check_call(['hciconfig', self.hci_device_name, 'down'])
        except subprocess.CalledProcessError:
            self._logger.error('Could not run hciconfig down command for HCI device')
            raise
        self._hci_socket = create_bt_socket_hci_channel_user(hci_device_number)
        self._logger.info('bind to %s complete', self.hci_device_name)

        self._pty_master, pty_slave = pty.openpty()
        self._pty_fd = os.fdopen(self._pty_master, 'rwb')
        hci_tty = os.ttyname(pty_slave)
        self._logger.info('TTY slave for the virtual HCI: %s', hci_tty)
        try:
            subprocess.check_call(['hciattach', hci_tty, 'any'])
        except subprocess.CalledProcessError:
            self._logger.error('Could not run hciattach on PTY device')
            raise

        self._inputs = [self._pty_fd, self._hci_socket]

        self._pty_buffer = StringIO()
        self._gatt_logger = GattLogger(self._logger)

    @property
    def hci_device_name(self):
        return 'hci{}'.format(self._hci_device_number)

    def run(self):
        while True:
            readable, _, _ = select.select(self._inputs, [], [])
            for s in readable:
                if s is self._pty_fd:
                    source = 'pty'
                    data = os.read(self._pty_master, 4096)
                    self._logger.debug('Raw PTY data: %s', repr(data))

                    self._pty_buffer.write(data)
                    self._pty_buffer.seek(-len(data), SEEK_CUR)

                    parsed_packet = RawCopy(HciPacket).parse_stream(self._pty_buffer)
                    packet = parsed_packet.data
                    self._logger.debug('PTY: %s', parsed_packet)

                elif s is self._hci_socket:
                    source = 'socket'
                    packet = self._hci_socket.recv(4096)
                    self._logger.debug('SOCKET: %s', RawCopy(HciPacket).parse(packet))

                else:
                    self._logger.warn('Unknown readable returned by select')
                    continue

                action = self._gatt_logger.handle_message(packet, source)
                self._logger.debug('Action: %s', action)

                for packet in action.packets_to_send_to_socket:
                    self._logger.debug(
                        'Sending to socket: %s',
                        RawCopy(HciPacket).parse(packet)
                    )
                    self._hci_socket.sendall(packet)

                if len(action.packets_to_send_to_pty) == 0:
                    self._logger.debug('Skipping PTY')
                for packet in action.packets_to_send_to_pty:
                    self._logger.debug(
                        'Sending to PTY: %s',
                        RawCopy(HciPacket).parse(packet)
                    )
                    os.write(self._pty_master, packet)


Action = collections.namedtuple(
    'Action', 'packets_to_send_to_socket packets_to_send_to_pty'
)


def get_default_action(packet, source):
    if source == 'socket':
        return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[packet])
    elif source == 'pty':
        return Action(packets_to_send_to_socket=[packet], packets_to_send_to_pty=[])


class GattLogger(object):
    def __init__(self, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        self._peripherals_loggers = dict()

    def parse_hci_packet(self, packet):
        try:
            return RawCopy(HciPacket).parse(packet)
        except:
            self._logger.error('Exception during packet parsing')
            return None

    def handle_message(self, packet, source):
        parsed_packet_with_raw_data = self.parse_hci_packet(packet)

        if parsed_packet_with_raw_data is not None:
            parsed_packet = parsed_packet_with_raw_data.value

            if is_acl_data_packet(parsed_packet):
                connection_handle = get_connection_handle_from_acl_data_packet(parsed_packet)
                if connection_handle in self._peripherals_loggers:
                    peripheral_logger = self._peripherals_loggers[connection_handle]
                    return peripheral_logger.handle_message(parsed_packet_with_raw_data, source)
                else:
                    self._logger.warn(
                        'Received ACL data packet for an unfamiliar connection handle: %d. \
This packet will be ignored by the logger',
                        connection_handle
                    )

            elif is_le_connection_complete_event(parsed_packet):
                connection_handle = get_connection_handle_from_connection_complete_event_packet(parsed_packet)
                self._logger.info('Connected to device. Connection handle: %d', connection_handle)
                self._peripherals_loggers[connection_handle] = GattPeripheralLogger(connection_handle, self._logger)

            elif is_le_disconnection_complete_event(parsed_packet):
                connection_handle = get_connection_handle_from_disconnection_complete_event_packet(parsed_packet)
                if connection_handle in self._peripherals_loggers:
                    self._peripherals_loggers.pop(connection_handle)
                else:
                    self._logger.warn(
                        'Received disconnection event for an unfamiliar connection handle: %d', connection_handle
                    )

            return get_default_action(packet, source)


class GattPeripheralLogger(object):
    def __init__(self, connection_handle, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        self._connection_handle = connection_handle
        self._jumper_handle = None
        self._awaiting_my_write_response = False
        self._notifying = False
        self._queued_pty_packets = []

    def handle_message(self, parsed_packet_with_raw_data, source):
        parsed_packet = parsed_packet_with_raw_data.value
        packet = parsed_packet_with_raw_data.data

        if is_read_by_type_response_packet(parsed_packet):
            self._logger.debug('read by type response')
            self._jumper_handle = find_jumper_handle_in_read_by_type_response_packet(parsed_packet)
            if self._jumper_handle is not None:
                self._connection_handle = get_connection_handle_from_acl_data_packet(parsed_packet)
                self._logger.info(
                    'Found jumper handle: %d on connection: %d', self._jumper_handle, self._connection_handle
                )
                self._awaiting_my_write_response = True

                return Action(
                    packets_to_send_to_socket=[gatt_protocol.create_start_notifying_on_handle_packet(
                        self._connection_handle, self._jumper_handle
                    )],
                    packets_to_send_to_pty=[packet]
                )

        elif self._is_jumper_notify_message(parsed_packet):
            self._logger.info('Received data from logger: %s', repr(get_data_from_notify_message(parsed_packet)))
            return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[])

        elif self._awaiting_my_write_response:
            if source == 'socket' and is_write_response_packet(parsed_packet):
                self._logger.info('Received write response packet')
                self._awaiting_my_write_response = False
                self._notifying = True
                self._logger.debug('Releasing queued PTY packets')
                queued_pty_packets = list(self._queued_pty_packets)
                self._queued_pty_packets = []
                return Action(packets_to_send_to_socket=queued_pty_packets, packets_to_send_to_pty=[])
            elif source == 'pty':
                self._logger.debug('Queuing PTY packet: %s', parsed_packet)
                self._queued_pty_packets.append(packet)
                return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[])

        return get_default_action(packet, source)

    def _is_jumper_notify_message(self, parsed_packet):
        return parsed_packet.type == 'ACL_DATA_PACKET' and \
               parsed_packet.payload.payload.cid == ATT_CID and \
               parsed_packet.payload.payload.payload.opcode == 'ATT_OP_HANDLE_NOTIFY' and \
               parsed_packet.payload.payload.payload.payload.handle == self._jumper_handle


def find_jumper_handle_in_read_by_type_response_packet(parsed_packet):
    for handle_value_pair in parsed_packet.payload.payload.payload.payload.attribute_data_list:
        characteristic_declaration = gatt_protocol.parse_characteristic_declaration(handle_value_pair.value)
        try:
            if characteristic_declaration.uuid == CHARACTERISTIC_TO_NOTIFY:
                return characteristic_declaration.value_handle
        except ValueError:
            pass
    return None


def get_data_from_notify_message(parsed_packet):
    return parsed_packet.payload.payload.payload.payload.data


def is_read_bd_address_command_complete_event_packet(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
        parsed_packet.payload.event == 'COMMAND_COMPLETE' and \
        parsed_packet.payload.payload.ogf == 'INFORMATIONAL_PARAMETERS' and \
        parsed_packet.payload.payload.ocf == 'READ_BD_ADDRESS_COMMAND'


def is_read_by_type_response_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET' and \
           parsed_packet.payload.payload.cid == ATT_CID and \
           parsed_packet.payload.payload.payload.opcode == 'ATT_OP_READ_BY_TYPE_RESPONSE'


def is_acl_data_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET'


def get_connection_handle_from_acl_data_packet(parsed_packet):
    return parsed_packet.payload.handle


def is_le_connection_complete_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
           parsed_packet.payload.event == 'LE_META_EVENT' and \
           parsed_packet.payload.payload.subevent == 'LE_CONNECTION_COMPLETED'


def get_connection_handle_from_connection_complete_event_packet(parsed_packet):
    return parsed_packet.payload.payload.payload.handle


def is_le_disconnection_complete_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
           parsed_packet.payload.event == 'DISCONNECTION_COMPLETED'


def get_connection_handle_from_disconnection_complete_event_packet(parsed_packet):
    return parsed_packet.payload.payload.handle


def is_write_response_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET' and \
           parsed_packet.payload.payload.cid == ATT_CID and \
           parsed_packet.payload.payload.payload.opcode == 'ATT_OP_WRITE_RESPONSE'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hci', type=int, default=0, help='The number of HCI device to connect to')
    parser.add_argument('--verbose', '-v', action='count', help='Verbosity, call this flag twice for ultra verbose')
    parser.add_argument('--log-file', type=str, default=None, help='Dumps log to file')
    args = parser.parse_args()

    if args.verbose == 1:
        logging_level = logging.INFO
    elif args.verbose > 1:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.WARN

    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging_level)

    logger = logging.getLogger(__file__)

    if args.log_file is not None:
        logger.addHandler(logging.FileHandler(args.log_file, mode='w'))

    hci_proxy = HciProxy(args.hci, logger)

    try:
        hci_proxy.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
