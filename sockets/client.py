from maestrosocket import MaestroSocket

sock = MaestroSocket('10.0.0.105', 10000)
sock.maestro_connect('10.0.0.105', 10003)
sock.maestro_send('hello'.encode(), len('hello'.encode()))