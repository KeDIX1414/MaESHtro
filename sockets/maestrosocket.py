import socket
import select

class MaestroSocket:
	def __init__(self, ip, port, server=False):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# self.sock.setblocking(0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			self.client_list = []
			self.client_list.append(self.sock)

	def maestro_connect(self, host, port):
		self.sock.connect((host, port))

	def maestro_accept(self):
		self.connection, self.client_address = self.sock.accept()

	def maestro_close(self):
		self.connection.close()

	def new_close(self):
		self.sock.close()

	def maestro_send(self, msg, msglen):
		self.sock.send(msg)
		data = self.sock.recv(1024)
		print(data)

	def server_loop(self):
		while 1:
			ready_to_read,ready_to_write,in_error = select.select(self.client_list,[],[],0)
			for sock in ready_to_read:
				if sock is self.sock:
					print("here")
					connection, addr = self.sock.accept()
					self.client_list.append(connection)
					print("I have received a new connection")
				else:
					try:
						data = sock.recv(1024)
						if data:
							print(data)
						else:
							sock.close()
							self.client_list.remove(sock)
							print("A client has left.")
					except:
						print("Client offline...")

	def maestro_server_receive(self):
		while True:
			data = self.connection.recv(1024)
			if not data: break
			print('received data' + str(data))
			self.connection.send('received'.encode())
		self.connection.close()


