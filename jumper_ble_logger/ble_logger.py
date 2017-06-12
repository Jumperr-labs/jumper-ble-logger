from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import atexit
import logging
import collections
import os
import pty
import select
import subprocess
from StringIO import StringIO
from io import SEEK_CUR
import json
import errno
from datetime import datetime, timedelta
import threading

from jumper_logging_agent.agent import \
    Agent, DEFAULT_FLUSH_PRIORITY, DEFAULT_FLUSH_INTERVAL, DEFAULT_FLUSH_THRESHOLD, DEFAULT_EVENT_TYPE
from . import gatt_protocol
from .hci_channel_user_socket import create_bt_socket_hci_channel_user
from .hci_protocol.hci_protocol import *
from .event_parser_middleware import EventParser, EventParserException

JUMPER_DATA_CHARACTERISTIC_UUID = int('8ff456780a294a73ab8db16ce0f1a2df', 16)
JUMPER_TIME_CHARACTERISTIC_UUID = int('8ff456790a294a73ab8db16ce0f1a2df', 16)

DEFAULT_INPUT_FILENAME = '/var/run/jumper_ble_logger/events'

DataToSendToAgent = collections.namedtuple('DataToSendToAgent', 'mac_address payload boot_time')


class AgentEventsSender(object):
    def __init__(self, filename=DEFAULT_INPUT_FILENAME, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        self._filename = filename
        self._fifo = self.open_fifo_readwrite(self._filename)

    @staticmethod
    def open_fifo_readwrite(filename):
        if not os.path.exists(filename):
            dirname = os.path.dirname(filename)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
        try:
            os.mkfifo(filename)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        fd = os.open(filename, os.O_RDWR | os.O_NONBLOCK)
        return os.fdopen(fd, 'wb')

    def send_data(self, data):
        event = json.dumps(data).encode() + b'\n'
        self._logger.debug('Sending event to agent')
        self._fifo.write(event)
        self._fifo.flush()
        self._logger.info('Event sent to agent: %s', repr(event))


class HciProxy(object):
    def __init__(self, hci_device_number=0, logger=None, events_config=None):
        self._logger = logger or logging.getLogger(__name__)

        self._event_parser = EventParser(config=events_config, logger=self._logger)
        self._agent_events_sender = AgentEventsSender(logger=self._logger)

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
        self._logger.debug('TTY slave for the virtual HCI: %s', hci_tty)
        try:
            subprocess.check_call(['hciattach', hci_tty, 'any'])
        except subprocess.CalledProcessError:
            self._logger.error('Could not run hciattach on PTY device')
            raise

        self._inputs = [self._pty_fd, self._hci_socket]

        self._pty_buffer = StringIO()  # Used as a seekable stream
        self._gatt_logger = GattLogger(self._logger)
        self._should_stop = False

    @property
    def hci_device_name(self):
        return 'hci{}'.format(self._hci_device_number)

    def handle_packet(self, packet, source):
        action = self._gatt_logger.handle_message(packet, source)
        self._logger.debug('Action: %s', action)

        for packet in action.packets_to_send_to_socket:
            self._logger.debug(
                'Sending to socket: %s',
                RawCopy(HciPacket).parse(packet)
            )
            self._hci_socket.sendall(packet)

        if source == 'socket' and len(action.packets_to_send_to_pty) == 0:
            self._logger.debug('Skipping PTY')
        for packet in action.packets_to_send_to_pty:
            self._logger.debug(
                'Sending to PTY: %s',
                RawCopy(HciPacket).parse(packet)
            )
            os.write(self._pty_master, packet)

        if action.data_to_send_to_agent is not None:
            try:
                parsed_data = self._event_parser.parse(
                    action.data_to_send_to_agent.mac_address,
                    action.data_to_send_to_agent.payload,
                    action.data_to_send_to_agent.boot_time
                )
            except EventParserException as e:
                self._logger.warning('Error parsing packet from BLE device: %s', e)
            else:
                self._agent_events_sender.send_data(parsed_data)

    def run(self):
        try:
            while not self._should_stop:
                readable, _, _ = select.select(self._inputs, [], [], 1)

                if self._hci_socket in readable:
                    source = 'socket'
                    packet = self._hci_socket.recv(4096)
                    self._logger.debug('SOCKET: %s', RawCopy(HciPacket).parse(packet))
                    self.handle_packet(packet, source)

                if self._pty_fd in readable:
                    data = os.read(self._pty_master, 4096)
                    self._logger.debug('Raw PTY data: %s', repr(data))
                    self._pty_buffer.write(data)
                    self._pty_buffer.seek(-len(data), SEEK_CUR)

                    source = 'pty'
                    while True:
                        if self._pty_buffer.pos == self._pty_buffer.len:
                            break
                        parsed_packet = RawCopy(HciPacket).parse_stream(self._pty_buffer)
                        if not parsed_packet:
                            break
                        self._logger.debug('PTY: %s', parsed_packet)
                        packet = parsed_packet.data
                        self.handle_packet(packet, source)
        except KeyboardInterrupt:
            log.info("Received SIGTERM, exiting")

    def stop(self):
        self._should_stop = True

Action = collections.namedtuple(
    'Action', 'packets_to_send_to_socket packets_to_send_to_pty data_to_send_to_agent'
)


def get_default_action(packet, source):
    if source == 'socket':
        return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[packet], data_to_send_to_agent=None)
    elif source == 'pty':
        return Action(packets_to_send_to_socket=[packet], packets_to_send_to_pty=[], data_to_send_to_agent=None)


class GattLogger(object):
    def __init__(self, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        self._peripherals_loggers = dict()
        self._connection_handle_to_mac_map = dict()

    def parse_hci_packet(self, packet):
        try:
            return RawCopy(HciPacket).parse(packet)
        except:
            self._logger.error('Exception during packet parsing')
            return None

    def handle_acl_data_packet(self, parsed_packet_with_raw_data, source):
        connection_handle = get_connection_handle_from_acl_data_packet(parsed_packet_with_raw_data.value)
        try:
            mac_address = self._connection_handle_to_mac_map[connection_handle]
        except KeyError:
            self._logger.warning(
                'Received ACL data packet for an unmapped connection handle: %d. \
This packet will be ignored by the logger', connection_handle
            )
        else:
            try:
                peripheral_logger = self._peripherals_loggers[mac_address]
            except KeyError:
                self._logger.warning(
                    'Received ACL data packet for a connection handle without a logger: %d. \
This packet will be ignored by the logger', connection_handle
                )
            else:
                return peripheral_logger.handle_message(parsed_packet_with_raw_data, source)

    def handle_num_of_completed_packets_event(self, parsed_packet_with_raw_data, source):
        parsed_packet = parsed_packet_with_raw_data.value
        new_connection_handles = []
        new_number_of_completed_packets = []

        for i in range(parsed_packet.payload.payload.number_of_handles):
            connection_handle = parsed_packet.payload.payload.connection_handles[i]
            try:
                mac_address = self._connection_handle_to_mac_map[connection_handle]
            except KeyError:
                pass
            else:
                if mac_address in self._peripherals_loggers:
                    number_of_hidden_packets = \
                        self._peripherals_loggers[mac_address].reset_number_of_hidden_data_packets_to_sockets()
                    number_of_completed_packets = \
                        parsed_packet.payload.payload.number_of_completed_packets[i] - number_of_hidden_packets
                    if number_of_completed_packets != 0:
                        new_connection_handles.append(connection_handle)
                        new_number_of_completed_packets.append(number_of_completed_packets)

        if len(new_connection_handles) > 0:
            new_packet = build_number_of_completed_packets_event_packet(
                new_connection_handles, new_number_of_completed_packets
            )

            return Action(
                packets_to_send_to_socket=[],
                packets_to_send_to_pty=[new_packet],
                data_to_send_to_agent=None
            )

    def hadle_command_status_event(self, parsed_packet_with_raw_data, source):
        block_packet = False
        for peripheral_logger in self._peripherals_loggers:
            if peripheral_logger.awaiting_response:
                block_packet = True
                break
        if block_packet:
            return Action(
                packets_to_send_to_socket=[],
                packets_to_send_to_pty=[],
                data_to_send_to_agent=None
            )

    def handle_le_connection_complete_event(self, parsed_packet_with_raw_data, source):
        parsed_packet = parsed_packet_with_raw_data.value
        mac_address, connection_handle = get_meta_data_from_connection_complete_event_packet(parsed_packet)
        self._logger.info('Connected to device. MAC: %s Connection handle: %d', mac_address, connection_handle)
        self._connection_handle_to_mac_map[connection_handle] = mac_address

        if mac_address not in self._peripherals_loggers:
            self._peripherals_loggers[mac_address] = \
                GattPeripheralLogger(mac_address, self._logger)

        self._peripherals_loggers[mac_address].on_connect(connection_handle)

        return None

    def handle_disconnection_complete_event(self, parsed_packet_with_raw_data, source):
        parsed_packet = parsed_packet_with_raw_data.value
        connection_handle = get_connection_handle_from_disconnection_complete_event_packet(parsed_packet)
        log.info('Disconnection event on handle: {}'.format(connection_handle))
        try:
            mac_address = self._connection_handle_to_mac_map[connection_handle]
        except KeyError:
            self._logger.warning(
                'Received disconnection event for an unmapped connection handle: %d', connection_handle
            )
            return None

        del self._connection_handle_to_mac_map[connection_handle]

        try:
            self._peripherals_loggers[mac_address].on_disconnect()
        except KeyError:
            self._logger.warning(
                'Received disconnection event for a connection handle without a logger: %d', connection_handle
            )
        return None

    def handle_message(self, packet, source):
        parsed_packet_with_raw_data = self.parse_hci_packet(packet)
        action = None

        if parsed_packet_with_raw_data is not None:
            parsed_packet = parsed_packet_with_raw_data.value

            if is_acl_data_packet(parsed_packet):
                action = None or self.handle_acl_data_packet(parsed_packet_with_raw_data, source)

            elif is_num_of_completed_packets_event(parsed_packet) and source == 'socket':
                action = None or self.handle_num_of_completed_packets_event(parsed_packet_with_raw_data, source)

            elif is_command_status_packet(parsed_packet):
                action = None or self.hadle_command_status_event(parsed_packet_with_raw_data, source)

            elif is_le_connection_complete_event(parsed_packet):
                action = None or self.handle_le_connection_complete_event(parsed_packet_with_raw_data, source)

            elif is_le_disconnection_complete_event(parsed_packet) or is_disconnection_complete_event(parsed_packet):
                action = None or self.handle_disconnection_complete_event(parsed_packet_with_raw_data, source)

        return action or get_default_action(packet, source)


class GattPeripheralLogger(object):
    def __init__(self, mac_address, logger=None):
        self._logger = logger or logging.getLogger(__name__)
        self._mac_address = mac_address
        self._connection_handle = None
        self._jumper_data_handle = None
        self._jumper_time_handle = None
        self.awaiting_response = False
        self._queued_pty_packets = []
        self._number_of_hidden_data_packets_to_socket = 0
        self._state = None
        self._boot_time = None

    def reset_number_of_hidden_data_packets_to_sockets(self):
        result = self._number_of_hidden_data_packets_to_socket
        self._number_of_hidden_data_packets_to_socket = 0
        return result

    def start_time_sync(self, packet):
        self._state = 'TIME_SYNC'
        self._logger.debug('State = %s', self._state)
        self._number_of_hidden_data_packets_to_socket = self._number_of_hidden_data_packets_to_socket + 1
        self.awaiting_response = True
        self._logger.debug('Sending request for "time from boot"')
        return Action(
            packets_to_send_to_socket=[gatt_protocol.create_read_request_packet(
                self._connection_handle, self._jumper_time_handle
            )],
            packets_to_send_to_pty=[packet],
            data_to_send_to_agent=None
        )

    def on_connect(self, connection_handle):
        self._connection_handle = connection_handle
        self._jumper_data_handle = None
        self._jumper_time_handle = None
        self.awaiting_response = False
        self._state = 'INIT'
        self._boot_time = None

    def on_disconnect(self):
        self._state = 'DISCONNECTED'

    def handle_message(self, parsed_packet_with_raw_data, source):
        parsed_packet = parsed_packet_with_raw_data.value
        packet = parsed_packet_with_raw_data.data

        if self._state == 'INIT':
            if is_read_by_type_response_packet(parsed_packet):
                self._logger.debug('read by type response')

                self._jumper_data_handle = \
                    self._jumper_data_handle or \
                    find_handle_in_read_by_type_response_packet(parsed_packet, JUMPER_DATA_CHARACTERISTIC_UUID)
                self._jumper_time_handle = \
                    self._jumper_time_handle or \
                    find_handle_in_read_by_type_response_packet(parsed_packet, JUMPER_TIME_CHARACTERISTIC_UUID)

                if self._jumper_data_handle and self._jumper_time_handle:
                    return self.start_time_sync(packet)

        elif self._state == 'TIME_SYNC':
            if source == 'socket' and is_read_response_packet(parsed_packet):
                self._boot_time = \
                    datetime.utcnow() - timedelta(0, get_value_from_read_response_packet(parsed_packet))

                self._state = 'STARTING_NOTIFICATIONS'
                self._logger.debug('State = %s', self._state)
                self._number_of_hidden_data_packets_to_socket = self._number_of_hidden_data_packets_to_socket + 1
                self.awaiting_response = True
                return Action(
                    packets_to_send_to_socket=[gatt_protocol.create_start_notifying_on_handle_packet(
                        self._connection_handle, self._jumper_data_handle
                    )],
                    packets_to_send_to_pty=[],
                    data_to_send_to_agent=None
                )
            elif source == 'pty':
                self._logger.debug('Queuing PTY packet: %s', parsed_packet)
                self._queued_pty_packets.append(packet)
                return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[], data_to_send_to_agent=None)

        elif self._state == 'STARTING_NOTIFICATIONS':
            if source == 'socket' and is_write_response_packet(parsed_packet):
                self._logger.info('Received write response packet')
                self._logger.debug('Releasing queued PTY packets')
                queued_pty_packets = list(self._queued_pty_packets)
                self.awaiting_response = False
                self._queued_pty_packets = []
                self._state = 'RUNNING'
                self._logger.debug('State = %s', self._state)
                return Action(
                    packets_to_send_to_socket=queued_pty_packets, packets_to_send_to_pty=[], data_to_send_to_agent=None
                )
            elif source == 'pty':
                self._logger.debug('Queuing PTY packet: %s', parsed_packet)
                self._queued_pty_packets.append(packet)
                return Action(packets_to_send_to_socket=[], packets_to_send_to_pty=[], data_to_send_to_agent=None)

        elif self._state == 'RUNNING':
            if self._is_jumper_notify_message(parsed_packet):
                data_to_send_to_agent = DataToSendToAgent(
                    mac_address=self._mac_address,
                    payload=get_data_from_notify_message(parsed_packet),
                    boot_time=self._boot_time
                )
                self._logger.info('Received data from logger: %s', repr(data_to_send_to_agent))
                return Action(
                    packets_to_send_to_socket=[], packets_to_send_to_pty=[], data_to_send_to_agent=data_to_send_to_agent
                )

        elif self._state == 'DISCONNECTED':
            log.warning('Received packet while disconnected: %s', parsed_packet)

        return get_default_action(packet, source)

    def _is_jumper_notify_message(self, parsed_packet):
        return parsed_packet.type == 'ACL_DATA_PACKET' and \
               parsed_packet.payload.payload.cid == ATT_CID and \
               parsed_packet.payload.payload.payload.opcode == 'ATT_OP_HANDLE_NOTIFY' and \
               parsed_packet.payload.payload.payload.payload.handle == self._jumper_data_handle


def find_handle_in_read_by_type_response_packet(parsed_packet, characteristics_uuid):
    for handle_value_pair in parsed_packet.payload.payload.payload.payload.attribute_data_list:
        characteristic_declaration = gatt_protocol.parse_characteristic_declaration(handle_value_pair.value)
        try:
            if characteristic_declaration.uuid == characteristics_uuid:
                return characteristic_declaration.value_handle
        except ValueError:
            pass
    return None


def get_data_from_notify_message(parsed_packet):
    return parsed_packet.payload.payload.payload.payload.data


def get_value_from_read_response_packet(parsed_packet):
    return parsed_packet.payload.payload.payload.payload.value


def is_read_bd_address_command_complete_event_packet(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
        parsed_packet.payload.event == 'COMMAND_COMPLETE' and \
        parsed_packet.payload.payload.ogf == 'INFORMATIONAL_PARAMETERS' and \
        parsed_packet.payload.payload.ocf == 'READ_BD_ADDRESS_COMMAND'


def is_read_by_type_response_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET' and \
           parsed_packet.payload.payload.cid == ATT_CID and \
           parsed_packet.payload.payload.payload.opcode == 'ATT_OP_READ_BY_TYPE_RESPONSE'


def is_read_response_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET' and \
           parsed_packet.payload.payload.cid == ATT_CID and \
           parsed_packet.payload.payload.payload.opcode == 'ATT_OP_READ_RESPONSE'


def is_acl_data_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET'


def get_connection_handle_from_acl_data_packet(parsed_packet):
    return parsed_packet.payload.handle


def is_le_connection_complete_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
           parsed_packet.payload.event == 'LE_META_EVENT' and \
           parsed_packet.payload.payload.subevent == 'LE_CONNECTION_COMPLETED'


def get_meta_data_from_connection_complete_event_packet(parsed_packet):
    return parsed_packet.payload.payload.payload.peer_bdaddr, parsed_packet.payload.payload.payload.handle


def is_le_disconnection_complete_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
           parsed_packet.payload.event == 'DISCONNECTION_COMPLETED'


def is_disconnection_complete_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and \
           parsed_packet.payload.event == 'DISCONNECTION_COMPLETE'


def get_connection_handle_from_disconnection_complete_event_packet(parsed_packet):
    return parsed_packet.payload.payload.handle


def is_write_response_packet(parsed_packet):
    return parsed_packet.type == 'ACL_DATA_PACKET' and \
           parsed_packet.payload.payload.cid == ATT_CID and \
           parsed_packet.payload.payload.payload.opcode == 'ATT_OP_WRITE_RESPONSE'


def is_num_of_completed_packets_event(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and parsed_packet.payload.event == 'NUMBER_OF_COMPLETED_PACKETS'


def is_command_status_packet(parsed_packet):
    return parsed_packet.type == 'EVENT_PACKET' and parsed_packet.payload == 'COMMAND_STATUS'


def get_list_of_handle_and_num_of_completed_packets_pairs_from_num_of_completed_packets_event(parsed_packet):
    result = []
    for i in range(parsed_packet.payload.payload.number_of_handles):
        result.append(
            (
                parsed_packet.payload.payload.connection_handles[i],
                parsed_packet.payload.payload.number_of_completed_packets[i]
            )
        )
    return result


def build_number_of_completed_packets_event_packet(connection_handles, number_of_completed_packets):
    return HciPacket.build(
        dict(
            type='EVENT_PACKET',
            payload=dict(
                event='NUMBER_OF_COMPLETED_PACKETS',
                payload=dict(
                    number_of_handles=len(connection_handles),
                    connection_handles=connection_handles,
                    number_of_completed_packets=number_of_completed_packets
                )
            )
        )
    )


def change_dictionary_keys_from_str_to_int(d):
    return {int(k): v for k, v in d.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--flush-threshold', help='Number of events buffered until flushing', type=int, default=DEFAULT_FLUSH_THRESHOLD
    )
    parser.add_argument(
        '--flush-priority', help='Event priority (integer) upon which to flush pending events', type=int,
        default=DEFAULT_FLUSH_PRIORITY
    )
    parser.add_argument(
        '--flush-interval', help='Interval in seconds after which pending events will be flushed', type=float,
        default=DEFAULT_FLUSH_INTERVAL
    )
    parser.add_argument(
        '--default-event-type', help='Default event type if not specified in the event itself', type=str,
        default=DEFAULT_EVENT_TYPE
    )
    parser.add_argument(
        '--events-config-file',
        type=str,
        help='Path of the events config file in JSON format.',
        default='/etc/jumper_ble_logger/events_config.json'
    )
    parser.add_argument(
        '--config-file',
        type=str,
        help='Path of the config file in JSON format.',
        default='/etc/jumper_ble_logger/config.json'
    )
    parser.add_argument('--hci', '-i', type=int, default=0, help='The number of HCI device to connect to')
    parser.add_argument('--verbose', '-v', action='count', help='Verbosity, call this flag twice for ultra verbose mode')
    parser.add_argument('--log-file', '-l', type=str, default=None, help='Dumps log to file')
    parser.add_argument('-d', '--dev-mode', help='Sends data to development BE', action='store_true')
    args = parser.parse_args()

    if args.verbose == 1:
        logging_level = logging.INFO
    elif args.verbose > 1:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.WARN

    logging.basicConfig(format='%(asctime)s %(levelname)8s %(name)10s: %(message)s', level=logging_level)

    logger = logging.getLogger(__file__)

    if args.log_file is not None:
        logger.addHandler(logging.FileHandler(args.log_file, mode='w'))

    if not os.path.isfile(args.config_file):
        print('Config file is missing: {}'.format(args.config_file))
        return 3

    with open(args.config_file) as fd:
        try:
            config = json.load(fd)
        except ValueError:
            print('Config file must be in JSON format: {}'.format(args.config_file))
            return 4
    try:
        project_id = config['project_id']
        write_key = config['write_key']
    except KeyError as e:
        print('Missing entry in config file: {}. {}'.format(args.config_file, e))
        return 5

    if not os.path.isfile(args.events_config_file):
        print('Config file is missing: {}'.format(args.events_config_file))
        return 1

    with open(args.events_config_file) as fd:
        try:
            events_config = change_dictionary_keys_from_str_to_int(json.load(fd))

        except ValueError:
            print('Config file must be in JSON format: {}'.format(args.events_config_file))
            return 2

    print('Starting agent')

    agent_started_event = threading.Event()

    def on_listening():
        print('Agent listening on named pipe %s' % (agent.input_filename,))
        agent_started_event.set()

    agent = Agent(
        input_filename=DEFAULT_INPUT_FILENAME,
        project_id=project_id,
        write_key=write_key,
        flush_priority=args.flush_priority,
        flush_threshold=args.flush_threshold,
        flush_interval=args.flush_interval,
        default_event_type=args.default_event_type,
        event_store=None,
        on_listening=on_listening,
        dev_mode=args.dev_mode
    )

    atexit.register(agent.cleanup)

    logging_agent_thread = threading.Thread(target=agent.start)
    logging_agent_thread.start()

    agent_started_event.wait()

    hci_proxy = HciProxy(args.hci, logger, events_config)

    try:
        hci_proxy.run()
    except KeyboardInterrupt:
        pass

    agent.stop()
    logging_agent_thread.join()
    agent.cleanup()
    print('Exiting')
    return 0


if __name__ == '__main__':
    x = main()
    exit(x)
