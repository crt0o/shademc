# Packets
from shademc.ClientboundPacket import *
from shademc.utility import State

PACKET_TYPES = {
    State.STATUS: {
        0x00: StatusClientboundPacket,
    },
    State.LOGIN: {
        0x01: EncryptionClientboundPacket,
        0x02: LoginSuccessClientboundPacket,
        0x03: SetCompressionClientboundPacket

    },
    State.PLAY: {
        0x0f: ChatClientboundPacket,
        0x21: KeepAliveClientBoundPacket
    }
}