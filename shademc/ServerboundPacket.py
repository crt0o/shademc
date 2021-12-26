# Utility
from shademc.utility import encode_varint, encode_string, encode_bytes, byte, State

class ServerboundPacket:
    pass

class HandshakeServerboundPacket(ServerboundPacket):
    def __init__(self, next_state, host, version=757, port=25565):
        self.packet_id = 0x00
        self.version = version
        self.host = host
        self.port = port
        self.next_state = State(next_state)

    def generate_message(self):
        version_bytes = encode_varint(self.version)
        host_bytes = encode_string(self.host)
        port_bytes = self.port.to_bytes(2, byteorder='big')
        next_state_byte = byte(self.next_state.value)

        self.payload = version_bytes + host_bytes + port_bytes + next_state_byte

class StatusServerboundPacket(ServerboundPacket):
    def __init__(self, next):
        self.packet_id = 0x00
        self.next_state = State.STATUS

    def generate_message(self):
        self.payload = bytes()

class LoginServerboundPacket(ServerboundPacket):
    def __init__(self, username):
        self.packet_id = 0x00
        self.username = username
        self.next_state = State.LOGIN

    def generate_message(self):
        self.payload = encode_string(self.username)

class KeepAliveServerboundPacket(ServerboundPacket):
    def __init__(self, keep_alive_id):
        self.packet_id = 0x0f
        self.next_state = State.PLAY
        self.keep_alive_id = keep_alive_id
    
    def generate_message(self):
        self.payload = self.keep_alive_id

class ChatServerboundPacket(ServerboundPacket):
    def __init__(self, text):
        self.packet_id = 0x03
        self.next_state = State.PLAY
        self.text = text

    def generate_message(self):
        self.payload = encode_string(self.text)

class ClientStatusServerboundPacket(ServerboundPacket):
    def __init__(self, action_id):
        self.packet_id = 0x04
        self.next_state = State.PLAY
        self.action_id = action_id

    def generate_message(self):
        self.payload = encode_varint(self.action_id)

class EncryptionServerboundPacket(ServerboundPacket):
    def __init__(self, shared_secret, verify_token):
        self.packet_id = 0x01
        self.next_state = State.LOGIN
        self.shared_secret = shared_secret
        self.verify_token = verify_token
    
    def generate_message(self):
        shared_secret_bytes = encode_bytes(self.shared_secret)
        verify_token_bytes = encode_bytes(self.verify_token)

        self.payload = shared_secret_bytes + verify_token_bytes