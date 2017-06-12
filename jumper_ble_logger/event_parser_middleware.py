from __future__ import absolute_import, division, print_function, unicode_literals

import struct
import logging
from datetime import timedelta


class EventParserException(Exception):
    pass


class EventParser(object):
    LOGGER_EVENT_HEADER = "<BBIB"
    LOGGER_EVENT_HEADER_LENGTH = struct.calcsize(LOGGER_EVENT_HEADER)

    def __init__(self, config, logger=None):
        self.check_config(config)
        self._events_dict = config
        self._logger = logger or logging.getLogger(__name__)

    @staticmethod
    def check_config(config):
        for k, v in config.items():
            if v.get('data') and v.get('strings'):
                raise ValueError("""
                Error parsing event {} from events_config.json . An event can have either strings or data, not both.
                """.format(k))

    def parse(self, mac_address, data, boot_time):
        if len(data) < self.LOGGER_EVENT_HEADER_LENGTH:
            raise EventParserException('Data header too short: {}'.format(repr(data)))

        header = data[:self.LOGGER_EVENT_HEADER_LENGTH]
        body = data[self.LOGGER_EVENT_HEADER_LENGTH:]
        version, event_type_id, time_from_boot, data_length = struct.unpack(self.LOGGER_EVENT_HEADER, header)

        event_config = self._events_dict.get(event_type_id, None)

        if event_config is None:
            self._logger.warning('Event type missing in config for event id: %d', event_type_id)
            type = event_type_id

        else:
            type = event_config['type']

        timestamp = boot_time + timedelta(seconds=time_from_boot)
        event_dict = dict(
            type=type,
            timestamp=timestamp.isoformat() + 'Z',
            device_id=mac_address
        )

        self._logger.debug('timestamp: {}'.format(boot_time + timedelta(seconds=time_from_boot)))

        if event_config:
            if event_config.get('data'):
                event_dict.update(self.parse_body_struct(body, event_config['data']))
            elif event_config.get('strings'):
                event_dict.update(self.parse_body_strings(body, event_config['strings']))

        return event_dict

    @staticmethod
    def parse_body_struct(body, event_config):
        struct_format = ''.join(event_config.values())

        if len(body) < struct.calcsize(struct_format):
            raise EventParserException('Data body is too short')

        values = struct.unpack(struct_format, body)

        return {value_key: value for value_key, value in zip(event_config.keys(), values)}

    @staticmethod
    def parse_body_strings(body, event_config):
        d = dict()
        strings = [x for x in body.split('\x00') if x != '']
        if len(strings) != len(event_config):
            raise EventParserException(
                'Not enough strings in packet body.\nBody: {}\nStrings: {}'.format(repr(body), strings)
            )

        for i in range(len(strings)):
            string_name = event_config[i]
            d[string_name] = strings[i]

        return d
