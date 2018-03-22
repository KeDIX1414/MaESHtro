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
		self.controller_graph = Graph()
		# self.sock.setblocking(0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			print(self.sock.getsockname())
			self.client_list = [self.sock]
		else:
			try:
				self.sock.connect(('192.168.1.2', 20001))
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
                os.environ["GATEWAY_NODE_IP"] = ""
                should_add_gateway = False
                
		try: 
			my_ip_address = subprocess.check_output(["sed -n -e 's/^.*address //p' /etc/network/interfaces"], shell=True)
			my_ip_address = my_ip_address.strip('\n')
			print("My ip address is ")
			print(my_ip_address)
		except Exception as e: 
			print(str(e))
			print("Could not run 'sed' command to find client IP address")
		

		while 1:
            
            # Generate client-neighbors.json file
                        try: 
				run = subprocess.check_output(["sh create-client-json.sh"], shell=True)
                        except Exception as e: 
				print(str(e))
				print("Could not run 'create-client-json' script")
            
            # Sleep for 5 seconds so as not to overload server
			time.sleep(5)

			# Read client json 
			my_file = open('client-neighbors.json', 'r')
			msg = my_file.read()
			print("Generated JSON is: ")
			print(msg)

			print("Now sending JSON to server")
			try: 
				self.sock.send(msg.encode())
			except Exception as e: 
				print(str(e))
				print("Could not send client-neighbors.json to server")

			print("Now receiving data from server")
			try: 
				data = self.sock.recv(1024)
				gateway_node_ip = data.decode()
				print("Gateway_node_ip received from server is: ")
				print(gateway_node_ip)
			except Exception as e: 
				print(str(e))
				print("Could not receive gateway IP address from server")

			# Compare new gateway node to old gateway node. If different, delete default route
			# Do not change gateway if node already has functioning gateway
			old_gateway = os.environ["GATEWAY_NODE_IP"]
			print("Client old gateway IP was: ")
			print(old_gateway)

			# If I got a new gateway IP, delete defulta routes
			if old_gateway != gateway_node_ip or old_gateway == "": 
				os.environ["GATEWAY_NODE_IP"] = gateway_node_ip
				print("I have a new gateway node now!")
				should_add_gateway = True
				subprocess.call(["sudo ip route del ", "0/0"], shell=True)
			
			#If current client is the gateway, delete the route
                        if my_ip_address == gateway_node_ip: 
				print("I am the gateway")
				should_add_gateway = False
				subprocess.call(["sudo ip route del ", "0/0"], shell=True)
			
			#Else add route to non-gateway node
			if should_add_gateway and my_ip_address != gateway_node_ip:
				print("Adding route to gateway!")
				cmd_string = "sudo ip route add default via " + gateway_node_ip
				should_add_gateway = False
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
		counter = 0

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
							
							# Update this client's neighbors in graph. If client is new, add to graph
							client_ip = parsed_client_json["my_ip"]
							client_neighbors = parsed_client_json["neighbors"]
							print("Now updating neighbors")
							self.controller_graph.update_neighbors(client_ip, client_neighbors)

							# If client is a gateway, update controller graph accordingly
							# Otherwise, make sure IP is not in gateway list
							is_gateway = parsed_client_json["is_gateway"]
							print("Now updating gateways")
							self.controller_graph.update_gateways(client_ip, is_gateway)

							# Mark that you've seen this node recently
							# If 1000 iterations have passed, remove all inactive nodes (those node yet seen) and reset
							counter = counter + 1
							print("Now updating seen nodes")
							self.controller_graph.update_seen(client_ip)
							if counter == 1000: 
								print("Now resetting seen")
								self.controller_graph.reset_seen()
								counter = 0

							# Find this node's closest gateway and send it to them
							if is_gateway == True: 
								gateway_node_ip = client_ip
							else: 
								print("Now finding best gateway with shitty algorithm")
								# TODO: Test better algorithm too
								gateway_node_ip = self.controller_graph.find_best_gateway(client_ip)

							# Debugging print statements
							print("This client's ip is: ")
							print(client_ip)
							print("The best gateway node for this client is: ")
							print(gateway_node_ip)
							print("Now printing controller graph: ")
							print(self.controller_graph._graph)
							#gateway_node_ip= "192.168.1.1"
							
							print("Now sending gateway IP to client")
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




