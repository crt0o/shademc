import Shade
from threading import Thread

def tty():
    while True:
        client.send(Shade.Shade.ChatServerboundPacket(input()))

server = input('Connect to: ')
username = input('Use username: ')

client = Shade.Shade(server)
client.connect()
client.login(username)

Thread(target=tty).start()

def handle_packet(packet):
    if isinstance(packet, Shade.Shade.ChatClientboundPacket):
        if packet.type == 0:
            print(packet.contents)
            # print('<' + packet.contents['with'][0]['text'] + '> ' + packet.contents['with'][1])

        if packet.type == 1:
            try:
                print('<Server>', packet.contents)
            except:
                pass


client.on_packet(handle_packet)