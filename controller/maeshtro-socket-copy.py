import socket
import select
import sys
from user import User
import json
import ast
import commands
import subprocess

class MaestroSocket:
	def __init__(self, ip, port, server=False, username="KeDIX1414"):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# self.sock.setblocking(0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			print(self.sock.getsockname())
			self.client_list = [self.sock]
		else:
			try:
				self.sock.connect(('0.0.0.0', 20001))
				print('You have been connected to the remote host.')
				msg = "Username:" + username
				self.sock.send(msg.encode())
				self.socket_list = [self.sock, sys.stdin]
			except Exception as e:
				print(str(e))
				print('You could not connect to the server.')
				sys.exit()

	def client_loop(self):
		my_ip_address = subprocess.check_output(["hostname", "-f"])
		gateway_node_ip = ""
		while 1:
			ready_to_read,ready_to_write,in_error = select.select(self.socket_list , [], [])
			for sock in ready_to_read:
				if sock == self.sock:
					data = sock.recv(1024)
					if not data:
						print('You have been disconnected from the server')
						sys.exit()
					else:
						#TODO: I assume gateway_node_ip is now a string, but I haven't verified this yet!
						#print(data.decode())
						gateway_node_ip = data.decode()
						print(gateway_node_ip)
						
						#If current client is the gate, delete the route
						#if my_ip_address == gateway_node_ip: 
						#	subprocess.check_output(["ip route del", "0/0"])

						#Add route to gateway node
						#output = subprocess.check_output(["sudo ip route add default via", gateway_node_ip])
						#print(output)
				else:
					# msg = sys.stdin.readline()
					my_file = open('client-neighbors.json', 'r')
					msg = my_file.read()
					self.sock.send(msg.encode())
					
	def server_loop(self):
		gateway_node_ip = ""
		while 1:
			ready_to_read,ready_to_write,in_error = select.select(self.client_list,[],[],0)
			for sock in ready_to_read:
				if sock is self.sock:
					connection, addr = self.sock.accept()
					self.client_list.append(connection)
					print("I have received a new connection")
				else:
					try:
						data = sock.recv(1024)
						if data:
							message = data.decode()
							#parse json (THIS ASSUMES MESSAGE IS A DOUBLE QUOTED STRING VALUE!!!)
							parsed_client_json = ast.literal_eval(message)
							if parsed_client_json["is_gateway"] == True: 
								gateway_node_ip = parsed_client_json["my_ip"]

							#self.broadcast(sock, data)
							self.broadcast(sock, gateway_node_ip.encode())
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




