from maestrosocket import MaestroSocket

sock = MaestroSocket('10.0.0.105', 10003, server=True)
while True:
	print("waiting...")
	sock.maestro_accept()
	sock.maestro_server_receive()
	sock.maestro_close()
