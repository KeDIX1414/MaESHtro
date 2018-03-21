import socket
import select
import sys
import json
import ast
import commands
import subprocess
import time
import os 
from graph import Graph

class MaestroSocket:
	def __init__(self, ip, port, server=False, username="KeDIX1414"):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.controller_graph = Graph(directed=True)
		# self.sock.setblocking(0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			print(self.sock.getsockname())
			self.client_list = [self.sock]
		else:
			try:
				self.sock.connect(('127.0.0.4', 20001))
				print('You have been connected to the remote host.')
				#msg = "Username:" + username
				#self.sock.send(msg.encode())
				self.socket_list = [self.sock, sys.stdin]
			except Exception as e:
				print(str(e))
				print('You could not connect to the server.')
				sys.exit()

	def client_loop(self):
		my_ip_address = ""
		gateway_node_ip = ""

		try: 
			my_ip_address = subprocess.check_output(["sed -n -e 's/^.*address //p' /etc/network/interfaces"], shell=True)
			print("my ip address is ")
			print(my_ip_address)
		except Exception as e: 
			print(str(e))
			print("Could not run 'sed' command to find client IP address")
		

		while 1:
                    
			my_file = open('client-neighbors.json', 'r')
			msg = my_file.read()
			
			# Sleep for 5 seconds so as not to overload server
			time.sleep(5)

			try: 
				self.sock.send(msg.encode())
			except Exception as e: 
				print(str(e))
				print("Could not send client-neighbors.json to server")

			try: 
				data = self.sock.recv(1024)
				gateway_node_ip = data.decode()
				print("gateway_node_ip in client is: ")
				print(gateway_node_ip)
			except Exception as e: 
				print(str(e))
				print("Could not receive gateway IP address from server")

			# Compare new gateway node to old gateway node. If different, delete default route
			# Do not change gateway if node already has functioning gateway
			# NOTE: this will not work if gateway_node_ip is not string type
			# TODO: test value of old_gateway

			old_gateway = os.environ["GATEWAY_NODE_IP"]
			print("Client old gateway IP is: ")
			print(old_gateway)

			if old_gateway != gateway_node_ip and old_gateway == "": 
				os.environ["GATEWAY_NODE_IP"] = gateway_node_ip
				print("I have a new gateway node now!")
				subprocess.call(["sudo ip route del ", "0/0"], shell=True)

			print("and my ip address is: ")
			print (my_ip_address)

			#If current client is the gate, delete the route
			if my_ip_address == gateway_node_ip: 
				subprocess.call(["sudo ip route del ", "0/0"], shell=True)
			
			#Else add route to non-gateway node
			else:
				cmd_string = "sudo ip route add default via " + gateway_node_ip
				subprocess.call([cmd_string], shell=True)
                            
##			ready_to_read,ready_to_write,in_error = select.select(self.socket_list , [], [])
##			for sock in ready_to_read:
##				if sock == self.sock:
##                                        #data = sock.recv(1024)
##					if not data:
##						print('You have been disconnected from the server')
##						sys.exit()
##					else:
##						#TODO: I assume gateway_node_ip is now a string, but I haven't verified this yet!
##                                                my_file = open('client-neighbors.json', 'r')
##                                                msg = my_file.read()
##                                                print('1')
##                                                self.sock.send(msg.encode())
##                                                print('2')
##                                                data = sock.recv(1024)
##                                                print('3')
##						gateway_node_ip = data.decode()
##						print("gateway_node_ip in client is: ")
##						print(gateway_node_ip)
##						
##						#If current client is the gate, delete the route
##						if my_ip_address == gateway_node_ip: 
##							subprocess.check_output(["ip route del ", "0/0"])
##
##						#Add route to gateway node
##						output = subprocess.check_output(["sudo ip route add default via ", gateway_node_ip])
##						print(output)
##				else:
##					# msg = sys.stdin.readline()
##					#my_file = open('client-neighbors.json', 'r')
##					#msg = my_file.read()
##					#self.sock.send(msg.encode())
##					print("not goosd")
					
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
							parsed_client_json = ast.literal_eval(message)
							print("Received client JSON received: ")
							print(parsed_client_json)
							
							# Add/delete nodes in network to graph, if any
							client_ip = parsed_client_json["my_ip"]
							client_neighbors = parsed_client_json["neighbors"]
							self.controller_graph.update_neighbors(client_ip, client_neighbors)

							# If client is a gateway, update controller graph accordingly
							if parsed_client_json["is_gateway"] == True: 
								gateway_node_ip = parsed_client_json["my_ip"]
								self.controller_graph.add_gateway(gateway_node_ip)
								print("added gateway node ip to graph: ")
								print(gateway_node_ip)
								# gateway_node_ip= "192.168.1.1"
							sock.send(gateway_node_ip.encode())
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




