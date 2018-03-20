from maestrosocket import MaestroSocket
import socket
import sys

if __name__ == "__main__":
    sock = MaestroSocket('127.0.0.4', 20001, server=True)
    sock.server_loop()
# 	socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#	socket.bind(("127.0.0.1", 20001))
#	while True:
#		data, addr = socket.accept()
#		print("here")