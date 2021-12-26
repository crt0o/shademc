# Networking
import socket

# Utility
from shademc.utility import decode_varint_stream, encode_varint, read_all

# Cryptography
from Crypto.Cipher import AES
import zlib

# Miscellaneous
from io import BytesIO
from threading import Thread
from typing import Callable

class Relayer:
    def __init__(self, host, port, buffer_size=1024):
        self._encryption_on = False
        self._compression_on = False
        self.exit_flag = False

        self._buffer_size = buffer_size
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        self._recieve_thread = Thread(target=self._recieve)
        self._recieve_thread.start()

        self.active = True

    # --- Private methods ---

    def _recieve(self) -> None:
        while True:
            # Exit if the exit flag is set to True
            if self.exit_flag:
                self.s.close()
                exit()

            # Try to recieve the length of the packet
            if self._encryption_on:
                cipher = AES.new(self._key, AES.MODE_CFB, iv=self._key)
                payload_length = decode_varint_stream(self.s, cipher=cipher)
            else:
                payload_length = decode_varint_stream(self.s)

            # If reading fails, continue
            if not payload_length: continue

            # Recieve the entire packet
            data = bytes()

            while True:
                if last_buffer := (payload_length - len(data)) < self._buffer_size:
                    buf = self.s.recv(last_buffer)
                else:
                    buf = self.s.recv(self._buffer_size)

                data += buf
                if len(data) == payload_length:
                    break

            # Decrypt packet if it is encrypted
            if self._encryption_on:
                data = cipher.decrypt(data)

            # Decompress the packet if it is compressed
            if self._compression_on:
                stream = BytesIO(data)
                uncompressed_length = decode_varint_stream(stream)

                if uncompressed_length > self._compression_threshold:
                    data_compressed = read_all(stream)
                    data = zlib.decompress(data_compressed)
                else:
                    data = read_all(stream)

            if not hasattr(self, '_packet_handler'): continue
            self._packet_handler(data)

    # --- Public methods ---

    def exit(self) -> None:
        self.exit_flag = True
        self.active = False

    def enable_compression(self, compression_threshold: int) -> None:
        self._compression_threshold = compression_threshold
        self._compression_on = True
    
    def disable_compression(self) -> None:
        self._compression_on = False

    def enable_encryption(self, key: bytes) -> None:
        self._encryption_on = True
        self._key = key

    def disable_encryption(self) -> None:
        self._encryption_on = False

    def on_packet(self, func: Callable) -> None:
        self._packet_handler = func

    def send(self, data: bytes) -> bytes:
        if not self.active: return

        data_length_bytes = encode_varint(data_length := len(data))

        # Compress the data if compression is on
        if self._compression_on:
            if data_length > self._compression_threshold:
                full = data_length_bytes + zlib.compress(data)
            else:
                full = b'\x00' + data
                
            full_length_bytes = encode_varint(len(full))
            full = full_length_bytes + full
        else:
            full = data_length_bytes + data

        # Encrypt data if encryption is on
        if self._encryption_on:
            cipher = AES.new(self._key, AES.MODE_CFB, iv=self._key)
            full = cipher.encrypt(full)

        # Send the data and return it
        self.s.sendall(full)
        
        return full
    
    def send_raw(self, data: bytes) -> bytes:
        self.s.sendall(data)
        
        return data