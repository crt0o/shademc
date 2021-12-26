from threading import Thread
from shademc import Shade
from shademc.ClientboundPacket import ChatClientboundPacket
from shademc.ServerboundPacket import ChatServerboundPacket

def tty():
    while True:
        client.send(ChatServerboundPacket(input()))

server = input('Connect to: ')
username = input('Use username: ')

client = Shade.Shade(server)
client.connect()
client.login(username)

Thread(target=tty).start()

def handle_packet(packet):
    if isinstance(packet, ChatClientboundPacket):
        if packet.type == 0:
            print(packet.contents)

        if packet.type == 1:
            try:
                print(packet.contents)
            except:
                pass


client.on_packet(handle_packet)