from maestrosocket import MaestroSocket
import sys

if __name__ == "__main__":
	ip_addr = sys.argv[1]
	#print("ip addr is ")
	#print(ip_addr)
	sock = MaestroSocket(ip_addr, 20000)
	sock.client_loop()