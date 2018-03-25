from maestrosocket import MaestroSocket
import socket
import sys

if __name__ == "__main__":
	port_num = int(sys.argv[1])
    # IP HERE REMAINS EMPTY
	#sock = MaestroSocket('', 20001, server=True)
	sock = MaestroSocket('', port_num, server=True)
	sock.server_loop()
# 	socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#	socket.bind(("127.0.0.1", 20001))
#	while True:
#		data, addr = socket.accept()
#		print("here")