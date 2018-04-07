from maestrosocket import MaestroSocket
import socket
import sys

if __name__ == "__main__":
    sock = MaestroSocket('172.20.10.7', 20001, server=True)
    sock.server_loop()
