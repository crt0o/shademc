# Networking
import secrets
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from shademc.Relayer import Relayer

# Utility
from shademc.utility import decode_varint_stream, State, encode_varint

# Packets
from shademc.ClientboundPacket import EncryptionClientboundPacket, KeepAliveClientBoundPacket, SetCompressionClientboundPacket
from shademc.ServerboundPacket import EncryptionServerboundPacket, KeepAliveServerboundPacket, HandshakeServerboundPacket, ServerboundPacket, StatusServerboundPacket, LoginServerboundPacket
from shademc.PACKET_TYPES import PACKET_TYPES

# Miscellaneous
from io import BytesIO
from typing import Callable

class Shade:
    def __init__(self, host: str, port=25565, buffer_size=1024, keep_alive=True):
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.keep_alive = keep_alive

        self.state = State.HANDSHAKING

    # --- Private methods ---

    def _handle_packet(self, data: bytes) -> None:
        stream = BytesIO(data)

        packet_id = decode_varint_stream(stream)

        try:
            packet = PACKET_TYPES[self.state][packet_id].from_payload_stream(stream)
        except KeyError:
            return

        if isinstance(packet, KeepAliveClientBoundPacket) and self.keep_alive:
            self.send(KeepAliveServerboundPacket(packet.keep_alive_id))
            return

        if isinstance(packet, SetCompressionClientboundPacket):
            self.relayer.enable_compression(packet.threshold)
            return

        if isinstance(packet, EncryptionClientboundPacket):
            shared_secret = secrets.token_bytes(16)
            
            cipher = PKCS1_v1_5.new(RSA.importKey(packet.public_key))

            encrypted_shared_secret = cipher.encrypt(shared_secret)
            encrypted_verify_token = cipher.encrypt(packet.verify_token)

            self.send(EncryptionServerboundPacket(encrypted_shared_secret, encrypted_verify_token))
            self.relayer.enable_encryption(shared_secret)

            return

        if hasattr(self, '_packet_handler'):
            self._packet_handler(packet)

        self.state = packet.next_state

    # --- Public methods ---

    def connect(self) -> None:
        self.relayer = Relayer(self.host, self.port)
        self.relayer.on_packet(self._handle_packet)

    def login(self, username, password=None) -> None:
        self.send(HandshakeServerboundPacket(host=self.host, next_state=0x02))
        self.send(LoginServerboundPacket(username))

    def get_relayer(self) -> Relayer:
        if hasattr(self, 'relayer'):
            return self.relayer
        else: return None

    def send(self, packet) -> bytes:
        packet.generate_message()
        data = self.generate_data(packet)
        
        self.relayer.send(data)

        self.state = packet.next_state

    def on_packet(self, func: Callable) -> None:
        self._packet_handler = func

    def exit(self) -> None:
        self.relayer.exit()

    # --- Static methods ---

    @staticmethod
    def generate_data(packet) -> bytes:
        return encode_varint(packet.packet_id) + packet.payload

