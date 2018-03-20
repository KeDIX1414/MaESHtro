import socket
import select
import sys
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
		# my_ip_address = subprocess.check_output(["hostname", "-f"])
		#test = subprocess.check_output(["cat /etc/network/interfaces"], shell=True)
		#print(test)
		my_ip_address = subprocess.check_output(["sed -n -e 's/^.*address //p' /etc/network/interfaces"], shell=True)
		print("my ip address is ")
		print(my_ip_address)
		gateway_node_ip = ""
		while 1:
                        my_file = open('client-neighbors.json', 'r')
                        msg = my_file.read()
                        print('1')
                        self.sock.send(msg.encode())
                        print('2')
                        data = self.sock.recv(1024)
                        print('3')
                        gateway_node_ip = data.decode()
                        print("gateway_node_ip in client is: ")
                        print(gateway_node_ip)
			print("and my ip address is: ")
			print (my_ip_address)
			#If current client is the gate, delete the route
                        if my_ip_address == gateway_node_ip: 
                            subprocess.call(["sudo ip route del ", "0/0"], shell=True)
			#Add route to non-gateway node
                        else:
                            cmd_string = "sudo ip route add default via " + gateway_node_ip
                            subprocess.call([cmd_string], shell=True)
                            #output = subprocess.call(["sudo ip route add default via ", gateway_node_ip], shell=True)
                            #print(output)
                            
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
							#parse json (THIS ASSUMES MESSAGE IS A DOUBLE QUOTED STRING VALUE!!!)
							parsed_client_json = ast.literal_eval(message)
							if parsed_client_json["is_gateway"] == True: 
								gateway_node_ip = parsed_client_json["my_ip"]
								print("gateway node ip in server loop is now: ")
								print(gateway_node_ip)
                                                        gateway_node_ip= "192.168.1.1"
                                                    							#self.broadcast(sock, data)
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




