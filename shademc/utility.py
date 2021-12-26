# Networking
import socket

# Cryptography
import hashlib

# Miscellaneous
from io import BytesIO
from enum import Enum

# --- Functions ---

def byte(n: int) -> bytes:
    return bytes((n, ))

def encode_varint(n: int) -> bytes:
    b = bytes()
    while True:
        if (n & 0xffffff80) == 0:
            b += byte(n)
            return b
        b += byte(n & 0x7f | 0x80)
        n >>= 7

def decode_varint_stream(stream, cipher=None) -> int:
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

def encode_string(s: str) -> bytes:
    return encode_varint(len(s)) + bytes(s, encoding='utf-8')

def decode_string_stream(stream) -> str:
    return str(decode_bytes_stream(stream), encoding='utf-8')

def encode_bytes(bytes_: bytes) -> bytes:
    return encode_varint(len(bytes_)) + bytes_

def decode_bytes_stream(stream) -> bytes:
    length = decode_varint_stream(stream)
    return read(stream, length)

def read(stream, n: int) -> bytes:
    if isinstance(stream, socket.socket):
        return stream.recv(n)
    elif isinstance(stream, BytesIO):
        return stream.read(n)
    else:
        raise TypeError('Invalid stream type')

def read_all(stream) -> bytes:
    data = bytes()

    while True: 
        buf = stream.read(1024)
        if not buf: return data
        data += buf

def twos_complement(n: int, bits: int) -> int:
    if (n & (1 << (bits - 1))) != 0:
        n = n - (1 << bits)
    return n

def minecraft_sha1(server_id: bytes, shared_secret: bytes, public_key: bytes) -> str:
    sha1 = hashlib.sha1()

    sha1.update(server_id)
    sha1.update(shared_secret)
    sha1.update(public_key)

    return format(twos_complement(int.from_bytes(sha1.digest(), byteorder='big'), 160), 'x')

# --- Enums ---

class State(Enum):
    HANDSHAKING = 0
    STATUS = 1
    LOGIN = 2
    PLAY = 3
