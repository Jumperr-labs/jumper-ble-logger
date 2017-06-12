from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import os
import json
from datetime import datetime
from jumper_ble_logger.event_parser_middleware import EventParser
from jumper_ble_logger.ble_logger import change_dictionary_keys_from_str_to_int, GattPeripheralLogger
from jumper_ble_logger.hci_protocol.hci_functions import *
from jumper_ble_logger.hci_protocol.hci_protocol import *

ROOT_DIR = os.path.join(os.path.dirname(__file__), '..')
VALID_CONFIG_FILE = os.path.join(ROOT_DIR, 'events_config.json')
DEFAULT_MAC = 'aa:bb:cc:dd:ee:ff'
DEFAULT_CONNECTION_HANDLE = 10
CONNECTION_PACKET = create_le_connection_comlete_packet(DEFAULT_MAC, DEFAULT_CONNECTION_HANDLE)


def create_packet(time_from_boot=0, version=1, event_type=2, data_length=1, data=b'\x01'):
    return struct.pack('<BBIB{}s'.format(data_length), version, event_type, time_from_boot, data_length, data)


def dict_from_config_file(config_file):
    with open(config_file) as fd:
        config_file = change_dictionary_keys_from_str_to_int(json.load(fd))
        return {int(k): v for k, v in config_file.items()}


valid_config = dict_from_config_file(VALID_CONFIG_FILE)
invalid_config = {
    2: {
        "type": "eveny_type",
        "strings": ["value"],
        "data": {
            "value": "H"
        }
    }
}


class EventParserTests(unittest.TestCase):
    def setUp(self):
        self.events_parser = EventParser(valid_config)

    def tearDown(self):
        pass

    def test_invalid_config(self):
        self.assertRaises(ValueError, EventParser, invalid_config)

    def check_parser_result(self, expected_result, input_packet, boot_time):
        event_dict = self.events_parser.parse(DEFAULT_MAC, input_packet, boot_time)
        self.assertDictEqual(expected_result, event_dict)

    def test_sanity(self):
        boot_time = datetime.utcnow()
        packet = create_packet(time_from_boot=0)
        expected_dict = dict(
            timestamp=boot_time.isoformat() + 'Z', type='advertising_state', is_on=1, device_id=DEFAULT_MAC
        )
        self.check_parser_result(expected_dict, packet, boot_time)

    def test_boot_event(self):
        boot_time = datetime.utcnow()
        data = b'v1.1.2\x00'
        packet = create_packet(time_from_boot=0, version=1, event_type=0, data_length=len(data), data=data)
        expected_dict = dict(
            timestamp=boot_time.isoformat() + 'Z', type='boot', firmware_version='v1.1.2', device_id=DEFAULT_MAC
        )
        self.check_parser_result(expected_dict, packet, boot_time)

    def test_string_event(self):
        boot_time = datetime.utcnow()
        data = b'HELLO\x00'
        packet = create_packet(time_from_boot=0, version=1, event_type=5, data_length=len(data), data=data)
        expected_dict = dict(
            timestamp=boot_time.isoformat() + 'Z', type='custom_string', custom_string='HELLO', device_id=DEFAULT_MAC
        )
        self.check_parser_result(expected_dict, packet, boot_time)


class GattPeripheralLoggerTests(unittest.TestCase):
    def setUp(self):
        self.peripheral_logger = GattPeripheralLogger(DEFAULT_MAC, DEFAULT_CONNECTION_HANDLE)

    def tearDown(self):
        pass

    def simulate_connection(self):
        packet_with_raw_data = RawCopy(HciPacket).parse(CONNECTION_PACKET)
        action = self.peripheral_logger.handle_message(packet_with_raw_data, 'socket')
        self.assertTrue(len(action.packets_to_send_to_socket) == 0)
        self.assertTrue(len(action.packets_to_send_to_pty) == 1)
        self.assertFalse(action.data_to_send_to_agent)
        self.assertTrue(action.packets_to_send_to_pty[0] == CONNECTION_PACKET)

    def test_just_connection(self):
        self.simulate_connection()


def main():
    unittest.main()

if __name__ == '__main__':
    main()
