from maestrosocket import MaestroSocket

sock = MaestroSocket('10.0.0.105', 10004, server=True)
sock.server_loop()