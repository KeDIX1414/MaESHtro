import socket
import select
import sys

class MaestroSocket:
	def __init__(self, ip, port, server=False):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# self.sock.setblocking(0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			self.client_list = [self.sock]
		else:
			try:
				self.sock.connect(('10.0.0.105', 10004))
				print('You have been connected to the remote host.')
				self.socket_list = [self.sock, sys.stdin]
			except Exception as e:
				print(str(e))
				print('You could not connect to the server.')
				sys.exit()

	def client_loop(self):
		while 1:
			ready_to_read,ready_to_write,in_error = select.select(self.socket_list , [], [])
			for sock in ready_to_read:
				if sock == self.sock:
					data = sock.recv(1024)
					if not data:
						print('You have been disconnected from the server')
						sys.exit()
					else:
						print(data)
				else:
					msg = sys.stdin.readline()
					self.sock.send(msg.encode())
					
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
							print("here")
							self.broadcast(sock, data)
						else:
							sock.close()
							self.client_list.remove(sock)
							print("A client has left.")
					except Exception as e:
						print(str(e))
						print("Client offline...")

	def broadcast(self, sock, data):
		for socket in self.client_list:
			if socket != sock and socket != self.sock:
				try:
					socket.send(data)
				except:
					if socket in self.client_list:
						self.client_list.remove(socket)




