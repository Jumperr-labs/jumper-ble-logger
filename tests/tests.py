from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import os
import json
import struct
import time
from jumper_ble_logger.event_parser_middleware import EventParser
from jumper_ble_logger.ble_logger import change_dictionary_keys_from_str_to_int

ROOT_DIR = os.path.join(os.path.dirname(__file__), '..')
VALID_CONFIG_FILE = os.path.join(ROOT_DIR, 'events_config.json')
DEFAULT_MAC = 'AA:BB:CC:DD:EE:FF'


def create_packet(timestamp=None, version=1, event_type=2, data_length=1, data=b'\x01'):
    timestamp = timestamp or round(time.time())
    return struct.pack('<BBIB{}s'.format(data_length), version, event_type, timestamp, data_length, data)


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

    def test_sanity(self):
        timestamp = int(round(time.time()))
        packet = create_packet(timestamp)
        event_dict = self.events_parser.parse(DEFAULT_MAC, packet, 0)

        expected_dict = dict(timestamp=timestamp, type='ADVERTISING_STATE', is_on=1, device_id=DEFAULT_MAC)
        self.assertDictEqual(expected_dict, event_dict)

    def test_boot_event(self):
        timestamp = int(round(time.time()))
        data = b'v1.1.2\x00'
        packet = create_packet(timestamp=timestamp, version=1, event_type=0, data_length=len(data), data=data)
        event_dict = self.events_parser.parse(DEFAULT_MAC, packet, 0)
        expected_dict = dict(timestamp=timestamp, type='DEVICE_BOOT', version='v1.1.2', device_id=DEFAULT_MAC)
        self.assertDictEqual(expected_dict, event_dict)

    def test_string_event(self):
        timestamp = int(round(time.time()))
        data = b'HELLO\x00'
        packet = create_packet(timestamp=timestamp, version=1, event_type=5, data_length=len(data), data=data)
        event_dict = self.events_parser.parse(DEFAULT_MAC, packet, 0)
        expected_dict = dict(timestamp=timestamp, type='CUSTOM_STRING', custom_string='HELLO', device_id=DEFAULT_MAC)
        self.assertDictEqual(expected_dict, event_dict)



def main():
    unittest.main()

if __name__ == '__main__':
    main()

