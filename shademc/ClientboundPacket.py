# Utility
from shademc.utility import decode_varint_stream, decode_bytes_stream, decode_string_stream, State, read_all

# Miscellaneous
import json

class ClientboundPacket:
    pass

class StatusClientboundPacket(ClientboundPacket):
    def __init__(self, info):
        self.packet_id = 0x00
        self.info
        self.next_state = State.STATUS

    @classmethod 
    def from_payload_stream(cls, payload_stream):
        info = json.loads(decode_string_stream(payload_stream))

        return cls(info)

class SetCompressionClientboundPacket(ClientboundPacket):
    def __init__(self, threshold):
        self.threshold = threshold
        self.packet_id = 0x03
        self.next_state = State.LOGIN

    @classmethod
    def from_payload_stream(cls, payload_stream):
        threshold = decode_varint_stream(payload_stream)

        return cls(threshold)

class EncryptionClientboundPacket(ClientboundPacket):
    def __init__(self, server_id, public_key, verify_token):
        self.packet_id = 0x01
        self.next_state = State.LOGIN

        self.server_id = server_id
        self.public_key = public_key
        self.verify_token = verify_token

    @classmethod
    def from_payload_stream(cls, payload_stream):
        server_id = decode_string_stream(payload_stream)
        public_key = decode_bytes_stream(payload_stream)
        verify_token = decode_bytes_stream(payload_stream)

        return cls(server_id, public_key, verify_token)

class LoginSuccessClientboundPacket(ClientboundPacket):
    def __init__(self, uuid, username):
        self.packet_id = 0x02
        self.next_state = State.PLAY

        self.username = username
        self.uuid = uuid

    @classmethod
    def from_payload_stream(cls, payload_stream):
        uuid = payload_stream.read(16)
        username = decode_string_stream(payload_stream)

        return cls(uuid, username)

class ChatClientboundPacket(ClientboundPacket):
    def __init__(self, contents, type_, sender):
        self.packet_id = 0x0f
        self.next_state = State.PLAY

        self.contents = contents
        self.type = type_
        self.sender = sender

    @classmethod
    def from_payload_stream(cls, payload_stream):
        contents = json.loads(decode_string_stream(payload_stream))
        type_ = int.from_bytes(payload_stream.read(1), byteorder='big')
        sender = payload_stream.read(16)

        return cls(contents, type_, sender)

class KeepAliveClientBoundPacket(ClientboundPacket):
    def __init__(self, keep_alive_id: bytes):
        self.packet_id = 0x21
        self.next_state = State.PLAY

        self.keep_alive_id = keep_alive_id

    @classmethod
    def from_payload_stream(cls, payload_stream):
        keep_alive_id = read_all(payload_stream)

        return cls(keep_alive_id)