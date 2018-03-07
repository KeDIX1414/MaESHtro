import socket
class MaestroSocket:
	def __init__(self, ip, port, server=False):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)

	def maestro_connect(self, host, port):
		self.sock.connect((host, port))

	def maestro_accept(self):
		self.connection, self.client_address = self.sock.accept()

	def maestro_close(self):
		self.connection.close()

	def maestro_send(self, msg, msglen):
		self.sock.send(msg)
		data = self.sock.recv(1024)
		print(data)

	def maestro_server_receive(self):
		data = self.connection.recv(1024)
		print('received data' + str(data))
		self.connection.send('received'.encode())


