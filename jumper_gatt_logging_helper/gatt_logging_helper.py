from __future__ import absolute_import, division, print_function, unicode_literals

import socket
import pty
import os
import subprocess
import select
import struct
import logging
import argparse

log = logging.getLogger(__name__)

class HciProxy(object):
    def __init__(self, hci_device_number=0):
        self.hci_socket = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
        self.hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
        self.hci_socket.setsockopt(socket.SOL_HCI, socket.HCI_TIME_STAMP, 1)
        self.hci_socket.setsockopt(
            socket.SOL_HCI, socket.HCI_FILTER, struct.pack("IIIH2x", 0xffffffffL, 0xffffffffL, 0xffffffffL, 0)
        )
        self.hci_socket.bind((hci_device_number,))

        self.pty_master, pty_slave = pty.openpty()
        self.pty_f = os.fdopen(self.pty_master, 'rwb')
        hci_tty = os.ttyname(pty_slave)
        log.info('TTY Slave: {}'.format(hci_tty))

        output = subprocess.check_output(['hciattach', hci_tty, 'any'])
        if output != 'Device setup complete\n':
            raise RuntimeError("Could not run hciattach on PTY device. Output from call command is: {}".format(output))

        self.inputs = [self.pty_f, self.hci_socket]

    def run(self):
        while True:
            log.debug('SELECT')
            readable, _, _ = select.select(self.inputs, [], [])
            for s in readable:
                if s is self.pty_f:
                    log.debug('PTY')
                    val = os.read(self.pty_master, 4096)
                    log.debug(repr(val))
                    self.hci_socket.sendall(val)
                elif s is self.hci_socket:
                    log.debug('SOCKET')
                    val = self.hci_socket.recv(4096)
                    log.debug(repr(val))
                    os.write(self.pty_master, val)


def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument('--hci', type=int, default=0, help='The number of HCI device to connect to')
    args = parser.parse_args()
    hci_proxy = HciProxy(args.hci)
    try:
        hci_proxy.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
