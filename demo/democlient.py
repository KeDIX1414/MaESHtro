import socket
import time
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((sys.argv[1], sys.argv[2]))
sock.connect((sys.argv[3], sys.argv[4]))
while True:
	try:
		time.sleep(3)
		num = random.randint(0,100)
		msg = 'rand:' + str(num)
		sock.send(msg.encode())
	except KeyboardInterrupt:
		sock.close()
		sys.exit()
sock.close()