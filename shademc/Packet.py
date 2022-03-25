from enum import Enum
from io import BytesIO
import sched
from sys import byteorder
from typing import Dict
from shademc.utility import byte, encode_bytes, encode_string, encode_varint, decode_varint_stream, decode_bytes_stream, decode_string_stream

class DataType(Enum):
    BYTE = 0
    VARINT = 1
    STRING = 2
    BYTES = 3
    USHORT = 4

class Packet:
    next_state = None

    schema = []

    def __init__(self, contents):
        self.contents = contents

    def serialize(self) -> bytes:
        self.data = bytes()

        for (name, type_, default) in self.schema:
            if name not in self.contents:
                if default != None:
                    value = default
                else:
                    raise LookupError(f'No data provided for field \'{name}\' of type \'{type_}\'.')
            else:
                value = self.contents[name]

            if type_ == DataType.BYTE:
                self.data += byte(value)
            elif type_ == DataType.BYTES:
                self.data += encode_bytes(value)
            elif type_ == DataType.STRING:
                self.data += encode_string(value)
            elif type_ == DataType.VARINT:
                self.data += encode_varint(value)
            elif type_ == DataType.USHORT:
                self.data += value.to_bytes(2, byteorder='big')

            return self.data
    
    @classmethod
    def deserialize(cls, data):
        stream = BytesIO(data)
        contents = {}

        for (name, type_, _) in self.schema:
            if type_ == DataType.VARINT:
                value = decode_varint_stream(stream)
            elif type_ == DataType.BYTES:
                value = decode_bytes_stream(stream)
            elif type_ == DataType.STRING:
                value = decode_string_stream(stream)

            contents |= {name: value}

        return cls(contents)


class CPacketHandshake(Packet):
    schema = [
        ('packet_id', DataType.VARINT, 0x00),
        ('version', DataType.VARINT, 758),
        ('address', DataType.STRING, None),
        ('port', DataType.USHORT, 25565),
        ('next_state', DataType.VARINT, None)
    ]

class CPacketStatus(Packet):
    schema = [
        ('packet_id', DataType.VARINT, 0x00)
    ]

class CPacketLogin(Packet):
    schema = [
        ('packet_id', DataType.VARINT, 0x00),
        ('username', DataType.STRING, None)
    ]

class CPacketKeepalive(Packet):
    schema = [
        ('packet_id', DataType.VARINT, 0x0f),
        ('id', DataType.BYTES, None)
    ]

packet = CPacketHandshake({
    'address': 'localhost',
    'next_state': 1
});

packet.serialize()

print(packet.data)