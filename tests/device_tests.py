from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import os
import json
import threading
import subprocess
import logging
from time import sleep
from multiprocessing import Process

import pygatt
from pygatt.backends.backend import BLEAddressType

from jumper_ble_logger.ble_logger import HciProxy, change_dictionary_keys_from_str_to_int, DEFAULT_INPUT_FILENAME

TARGET_MAC_ADDRESS = b'C6:45:82:23:11:44'
HCI_DEVICE = b'hci1'

ROOT_DIR = os.path.join(os.path.dirname(__file__), '..')
EVENTS_CONFIG_FILE = os.path.join(ROOT_DIR, 'events_config.json')

logging.basicConfig(format='%(asctime)s %(levelname)8s %(name)10s: %(message)s', level=logging.INFO)

hci_adapter = pygatt.GATTToolBackend(hci_device=HCI_DEVICE)
hci_adapter.start()

with open(EVENTS_CONFIG_FILE) as fd:
    events_config = change_dictionary_keys_from_str_to_int(json.load(fd))


def hci_proxy_runner():
    hci_proxy = HciProxy(0, None, events_config)
    hci_proxy.run()

hci_proxy_process = Process(target=hci_proxy_runner)
hci_proxy_process.start()


class DeviceTests(unittest.TestCase):
    def setUp(self):
        sleep(3)
        print('Calling hciconfig')
        self.gatt_device = None
        try:
            subprocess.check_call(['hciconfig', HCI_DEVICE, 'up'])
        except subprocess.CalledProcessError as e:
            print('Output: {}'.format(e.output))
            self.disconnect()
            raise

        # sleep(1000)

    def test_sanity(self):
        print('connecting')
        self.gatt_device = hci_adapter.connect(TARGET_MAC_ADDRESS, timeout=10, address_type=BLEAddressType.random)
        print('connected')
        self.gatt_device.discover_characteristics()
        sleep(10)

    def test_reconnect(self):
        self.gatt_device = hci_adapter.connect(TARGET_MAC_ADDRESS, timeout=10, address_type=BLEAddressType.random)
        self.gatt_device.discover_characteristics()
        sleep(3)
        self.gatt_device.disconnect()
        self.gatt_device = hci_adapter.connect(TARGET_MAC_ADDRESS, timeout=10, address_type=BLEAddressType.random)
        sleep(3)

    def disconnect(self):
        if self.gatt_device:
            print("disconnecting")
            self.gatt_device.disconnect()

    def tearDown(self):
        print('Tear Down')
        self.disconnect()
        sleep(10)
        print('Tear down finished')
