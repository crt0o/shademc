# Networking
import socket

# Parsing
from io import BytesIO

# Cryptography stuff
import zlib
import hashlib
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import secrets

# Miscellaneous
from enum import Enum
import time
import json
from threading import Thread

# --- Error classes ---

class InvalidPacketIdError(Exception):
        pass

# --- Enums ---

class State(Enum):
    HANDSHAKING = 0
    STATUS = 1
    LOGIN = 2
    PLAY = 3

class StreamType(Enum):
    SOCKET = 0
    BYTESIO = 1

# --- Packet classes ---

# --- ServerboundPacket classes ---

class ServerboundPacket:
    @staticmethod
    def _generate_message_metadata(packet_id, payload):
        packet_id_bytes = encode_varint(packet_id)
        message = packet_id_bytes + payload

        return message

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

        payload = version_bytes + host_bytes + port_bytes + next_state_byte

        self.message = self._generate_message_metadata(self.packet_id, payload)

class StatusServerboundPacket(ServerboundPacket):
    def __init__(self):
        self.packet_id = 0x00
        self.next_state = State.STATUS

    def generate_message(self):
        self.message = self._generate_message_metadata(self.packet_id, bytes())

class LoginServerboundPacket(ServerboundPacket):
    def __init__(self, username):
        self.packet_id = 0x00
        self.username = username
        self.next_state = State.LOGIN

    def generate_message(self):
        username_bytes = encode_string(self.username)

        self.message = self._generate_message_metadata(self.packet_id, username_bytes)

class KeepAliveServerboundPacket(ServerboundPacket):
    def __init__(self, id_bytes):
        self.packet_id = 0x0f
        self.next_state = State.PLAY
        self.id_bytes = id_bytes
    
    def generate_message(self):
        self.message = self._generate_message_metadata(self.packet_id, self.id_bytes)

class ChatServerboundPacket(ServerboundPacket):
    def __init__(self, text):
        self.packet_id = 0x03
        self.next_state = State.PLAY
        self.text = text

    def generate_message(self):
        text_bytes = encode_string(self.text)
        self.message = self._generate_message_metadata(self.packet_id, text_bytes)

class ClientStatusServerboundPacket(ServerboundPacket):
    def __init__(self, action_id):
        self.packet_id = 0x04
        self.next_state = State.PLAY
        self.action_id = action_id

    def generate_message(self):
        action_id_bytes = encode_varint(self.action_id)

        self.message = self._generate_message_metadata(self.packet_id, action_id_bytes)

class EncryptionServerboundPacket(ServerboundPacket):
    def __init__(self, shared_secret, verify_token):
        self.packet_id = 0x01
        self.next_state = State.LOGIN
        self.shared_secret = shared_secret
        self.verify_token = verify_token
    
    def generate_message(self):
        shared_secret_bytes = encode_bytes(self.shared_secret)
        verify_token_bytes = encode_bytes(self.verify_token)

        payload = shared_secret_bytes + verify_token_bytes

        self.message = self._generate_message_metadata(self.packet_id, payload)

# --- ClientboundPacket classes ---

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

# --- Utility functions ---

def byte(n):
    return bytes((n, ))

def encode_varint(n):
    b = bytes()
    while True:
        if (n & 0xffffff80) == 0:
            b += byte(n)
            return b
        b += byte(n & 0x7f | 0x80)
        n >>= 7

def decode_varint_stream(stream, cipher=None):
    shift = 0
    result = 0
    while True:
        if cipher:
            i = cipher.decrypt(read(stream, 1))
        else:
            i = read(stream, 1)
        if not i: return
        result |= (i[0] & 0x7f) << shift
        shift += 7
        if not (i[0] & 0x80):
            break

    return result

def encode_string(s):
    return encode_varint(len(s)) + bytes(s, encoding='utf-8')

def decode_string_stream(stream):
    return str(decode_bytes_stream(stream), encoding='utf-8')

def encode_bytes(bytes_):
    return encode_varint(len(bytes_)) + bytes_

def decode_bytes_stream(stream):
    length = decode_varint_stream(stream)
    return read(stream, length)

def read(stream, n):
    if isinstance(stream, socket.socket):
        return stream.recv(n)
    elif isinstance(stream, BytesIO):
        return stream.read(n)
    else:
        raise TypeError('Invalid stream type')

def read_all(stream):
    data = bytes()

    while True: 
        buf = stream.read(1024)
        if not buf: return data
        data += buf

def minecraft_sha1(server_id, shared_secret, public_key):
    sha1 = hashlib.sha1()

    sha1.update(server_id)
    sha1.update(shared_secret)
    sha1.update(public_key)

    return format(int.from_bytes(sha1.digest(), byteorder='big'), 'x')

class Shade:
    
    # --- Class variables --- 

    PACKET_TYPES = {
        State.STATUS: {
            0x00: StatusClientboundPacket
        },
        State.LOGIN: {
            0x02: LoginSuccessClientboundPacket
        },
        State.PLAY: {
            0x0f: ChatClientboundPacket
        }
    }

    # --- Constructor ---

    def __init__(self, host, port=25565, buffer_size=1024):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        
    # --- Private methods ---

    def _generate_packet_header(self, message):
        message_length_bytes = encode_varint(message_length := len(message))

        if self.compression_on:
                if message_length > self.compression_threshold:
                    data = message_length_bytes + zlib.compress(message)
                else:
                    data = b'\x00' + message
                    
                full_length_bytes = encode_varint(len(data))
                return full_length_bytes + data

        else:
            return message_length_bytes + message

    def _recieve(self):
        while True:
            # Exit if the recieve_thread_exit flag is set to True
            if self.recieve_thread_exit: exit()

            # Try to recieve the length of the packet
            if self.encryption_on:
                cipher = AES.new(self.shared_secret, AES.MODE_CFB, iv=self.shared_secret)
                payload_length = decode_varint_stream(self.s, cipher=cipher)
            else:
                payload_length = decode_varint_stream(self.s)

            # If reading fails, continue
            if not payload_length: continue

            # Recieve the entire packet
            data = bytes()

            while True:
                if last_buffer := (payload_length - len(data)) < self.buffer_size:
                    buf = self.s.recv(last_buffer)
                else:
                    buf = self.s.recv(self.buffer_size)

                data += buf
                if len(data) == payload_length:
                    break

            # Decrypt packet body if it is encrypted
            if self.encryption_on:
                data = cipher.decrypt(data)

            # Decompress the packet if it is compressed
            if self.compression_on:
                stream = BytesIO(data)
                uncompressed_length = decode_varint_stream(stream)

                if uncompressed_length > self.compression_threshold:
                    data_compressed = read_all(stream)
                    data = zlib.decompress(data_compressed)
                else:
                    data = read_all(stream)

            # Instantiate a BytesIO object with the packet data and parse out the packet id
            stream = BytesIO(data)
            packet_id = decode_varint_stream(stream)

            # Handle encryption request packets
            if packet_id == 0x01 and self.state == State.LOGIN:
                packet = EncryptionClientboundPacket.from_payload_stream(stream)

                cipher = PKCS1_v1_5.new(RSA.importKey(packet.public_key))

                self.shared_secret = secrets.token_bytes(16)

                encrypted_shared_secret = cipher.encrypt(self.shared_secret)
                encrypted_verify_token = cipher.encrypt(packet.verify_token)
                
                self.send(EncryptionServerboundPacket(encrypted_shared_secret, encrypted_verify_token))

                self.encryption_on = True
                continue

            # Handle set compression packets
            if packet_id == 0x03 and self.state == State.LOGIN:
                self.compression_on = True
                self.compression_threshold = SetCompressionClientboundPacket.from_payload_stream(stream).threshold
                continue

            # Handle keep-alive packets
            elif packet_id == 0x21:
                id_bytes = read_all(stream)
                self.send(KeepAliveServerboundPacket(id_bytes))
                continue   

            # Instantiate a ClientboundPacket and pass it to the handle_packet function
            try:
                packet = self.PACKET_TYPES[self.state][packet_id].from_payload_stream(stream)
            except KeyError:
                # raise InvalidPacketIdError(packet_id)
                continue

            self.state = packet.next_state

            if not hasattr(self, 'handle_packet'): continue
            self.handle_packet(packet)

    # --- Public methods ---

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port))

        self.compression_on = False
        self.encryption_on = False

        self.recieve_thread_exit = False
        self.recieve_thread = Thread(target=self._recieve)
        self.recieve_thread.start()

    def login(self, username, password=''):
        self.send(HandshakeServerboundPacket(host=self.host, next_state=0x02))
        self.send(LoginServerboundPacket(username))
        time.sleep(0.2)
        # self.send(ClientStatusServerboundPacket(0))

    def on_packet(self, fun):
        self.handle_packet = fun

    def close(self):
        self.recieve_thread_exit = True
        self.s.close()

    def send(self, packet):
        packet.generate_message()
        packet_bytes = self._generate_packet_header(packet.message)
        
        if self.encryption_on:
            cipher = AES.new(self.shared_secret, AES.MODE_CFB, iv=self.shared_secret)
            packet_bytes = cipher.encrypt(packet_bytes)

        self.s.sendall(packet_bytes)
        self.state = packet.next_state