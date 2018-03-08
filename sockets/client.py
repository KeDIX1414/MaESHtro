from maestrosocket import MaestroSocket


sock = MaestroSocket('10.0.0.105', 10000)
sock.client_loop()