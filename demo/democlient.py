import socket
import time
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('172.20.10.7', 20008))
sock.connect(('172.20.10.7', 20001))
while True:
	try:
		time.sleep(3)
		num = random.randint(0,100)
		sock.send(str(num).encode())
	except KeyboardInterrupt:
		sock.close()
		sys.exit()
sock.close()