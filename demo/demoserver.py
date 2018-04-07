from maestrosocket import MaestroSocket
import socket
import sys

if __name__ == "__main__":
    sock = MaestroSocket(sys.argv[1], sys.argv[2], server=True)
    sock.server_loop()
