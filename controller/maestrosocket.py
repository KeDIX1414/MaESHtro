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
	def __init__(self, ip, port, server=False):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.controller_graph = Graph()
		# self.sock.setblocking(0)

		# Set timeout here if necessary
		#self.sock.settimeout(5.0)
		if server:
			self.sock.bind((ip, port))
			self.sock.listen(1)
			print(self.sock.getsockname())
			self.client_list = [self.sock]
		else:
			try:
                # THIS IS THE IP AND PORT OF THE SERVER. TO CHANGE PORT, CHANGE HERE AND SERVER.PY
				self.sock.bind((ip, 10000))

                # 6.6.1.3 is the static IP address of the server
				self.sock.connect(('6.6.1.3', port))
				#self.sock.connect(('127.0.0.4', 20001))				
				print('You have been connected to the remote host.')
				self.socket_list = [self.sock, sys.stdin]
			except Exception as e:
				print(str(e))
				print('You could not connect to the server.')
				sys.exit()

	def client_loop(self):
		my_ip_address = ""
		gateway_node_ip = ""
		os.environ["GATEWAY_NODE_IP"] = ""
		#should_add_gateway = False
		devnull = open(os.devnull, 'w')
                
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
				message = data.decode()

				parsed_server_json = ast.literal_eval(message)
				print("Server JSON received is: ")
				print(parsed_server_json)
			except Exception as e: 
				print(str(e))
				print("Could not receive gateway IP address from server")

			# Compare new gateway node to old gateway node. If different, delete default route
			# Do not change gateway if node already has functioning gateway
			old_gateway = os.environ["GATEWAY_NODE_IP"]
			print("Client old gateway IP was: ")
			print(old_gateway)
			gateway_node_ip = parsed_server_json["default"]


			# If I got a new gateway IP, or I am the gateway, delete default routes
			if old_gateway != gateway_node_ip or old_gateway == "" or gateway_node_ip == "": 
				os.environ["GATEWAY_NODE_IP"] = gateway_node_ip
				print("I have a new gateway/next hop IP now!")
				subprocess.call(["sudo ip route del ", "0/0"], shell=True, stdout=devnull, stderr=devnull)
			
			#Add default route and routes to next hops to every other node in network
			if gateway_node_ip != "":
				print("Adding default route to gateway!")
				cmd_string = "sudo ip route add default via " + gateway_node_ip
				print(cmd_string)
				subprocess.call([cmd_string], shell=True, stdout=devnull, stderr=devnull)

			# Now add routes to all other nodes with next hops info
			print("Adding routes to next hop for all other nodes!")
			next_hops = parsed_server_json["next_hops"]
			for n in next_hops: 
				dest = n[0]
				hop = n[1]
				cmd_string = "sudo ip route add " + dest + " via " + hop
				print(cmd_string)
				subprocess.call([cmd_string], shell=True, stdout=devnull, stderr=devnull)

					

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

							# BUG: Something happens here where 'remove' is an invalid function
							# BUG: Basically, if node goes offline, graph won't reflect that change
							# Mark that you've seen this node recently
							# If 100 iterations have passed, remove all inactive nodes (those node yet seen) and reset
							#counter = counter + 1
							#print("Now updating seen nodes")
							#self.controller_graph.update_seen(client_ip)
							#if counter == 100: 
							#	print("Now resetting seen")
							#	self.controller_graph.reset_seen()
							#	counter = 0

							# Find next hop to closest gateway (this may be the gateway)
							# Also find next hops to all nodes in network
							next_hops_json = self.controller_graph.find_next_hop_for_all_nodes(client_ip)
							#print("Best gateway is: ")
							#print(gateway_node_ip)
                                                                

							# Debugging print statements
							print("********************")
							print("This client's ip is: ")
							print(client_ip)
							#print("The best gateway node for this client is: ")
							print("Next hop/gateway JSON is: ")
							print(next_hops_json)
							print("Now printing controller graph: ")
							print(self.controller_graph._graph)
							print("********************")
							
							# Send gateway IP to client
							sock.send(next_hops_json.encode())
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




