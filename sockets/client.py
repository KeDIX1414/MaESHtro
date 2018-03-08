from maestrosocket import MaestroSocket
import sys

sock = MaestroSocket('10.0.0.105', 10000)
sock.maestro_connect('10.0.0.105', 10003)
while 1:
    msg = sys.stdin.readline()
    if msg == 'Disconnect\n':
        break
    sock.maestro_send(msg.encode(), len(msg.encode()))