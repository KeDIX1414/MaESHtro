import json
import commands
import subprocess

f = open('route-table', 'r')

json_string = f.readline()
#print(json_string)
parsed_json = json.loads(json_string)

ip_address = parsed_json['ip_address']
#print(ip_address)
port = parsed_json['port']
#print(port)

code_output1 = subprocess.check_output(["echo", "Hello World!"])
print(code_output1)


#TODO: ADD SUDO HERE
#sudo route add default gw 8.8.8.8 wlan0
code_output2 = subprocess.check_output("route add default gw " + ip_address + " wlan0", shell=True)
print(code_output2)
