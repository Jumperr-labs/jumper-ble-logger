import struct


class EventParserException(Exception):
    pass


class EventParser(object):
    LOGGER_EVENT_HEADER = "<LLLL"
    LOGGER_EVENT_HEADER_LENGTH = struct.calcsize(LOGGER_EVENT_HEADER)

    def __init__(self, config, logger):
        self._events_dict = config
        self._logger = logger

    def parse(self, mac_address, data, time_offset):
        if len(data) < self.LOGGER_EVENT_HEADER_LENGTH:
            raise EventParserException('Data header too short: {}'.format(repr(data)))

        header = data[:self.LOGGER_EVENT_HEADER_LENGTH]
        body = data[self.LOGGER_EVENT_HEADER_LENGTH:]
        version, event_type_id, timestamp, data_length = struct.unpack(self.LOGGER_EVENT_HEADER, header)

        event_config = self._events_dict.get(event_type_id, None)

        if event_config is None:
            self._logger.warninig('Event type missing in config for event id: %d', event_type_id)
            type = event_type_id

        else:
            type = event_config['type']

        event_dict = dict(
            type=type,
            timestamp=time_offset + timestamp,
            device_id=mac_address
        )

        if event_config and event_config['data']:
            event_dict.update(self.parse_body(body, event_config['data']))

        return event_dict

    @staticmethod
    def parse_body(body, event_config):
        struct_format = ''.join(event_config.values())

        if len(body) < struct.calcsize(struct_format):
            raise EventParserException('Data body is too short')

        values = struct.unpack(struct_format, body)

        return {value_key: value for value_key, value in zip(event_config.keys(), values)}

