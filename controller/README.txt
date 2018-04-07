How to set up controller/client stuff: 

NOTE: I use 'controller' and 'server' interchangeably. 



1.) Pi #3 is the controller. This is hardcoded in. 

2.) First, go on Pi #3 and within the controller directory, run 'python server.py 20000'. (20000 is the port it'll run on)

3.) Pick a Pi that will act as a client (either gateway or non-gateway). Based on your setup, you'll need to modify/look over the create-client-json.sh script in the controller directory. Whoever you want to be your neighbor, modify lines 24 and 27 to reflect that. For example, say I am Pi 6.6.1.1, and I want to setup the network such that I am only neighbors with 6.6.1.2. Then, the bottom part of the script will look like this: 


#Manually ping each possible neighbor IP and add if reachable 
#TODO: Add your range of IPs you'd like to ping here
echo "'neighbors': [" >> client-neighbors.json

PING_OUTPUT="$(ping -c 1 6.6.1.2 | grep "1 received")"	# THIS LINE IS CHANGED

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'6.6.1.2'" >> client-neighbors.json 		#THIS LINE IS CHANGED
fi 

echo "]" >> client-neighbors.json

#End JSON file with curly bracket
echo "}" >> client-neighbors.json



Say I am Pi 6.6.1.1, and I want to setup the network so I am neighbors with 6.6.1.2 AND 6.6.1.3. Then, the bottom of my script would look like this: 


#Manually ping each possible neighbor IP and add if reachable 
#TODO: Add your range of IPs you'd like to ping here
echo "'neighbors': [" >> client-neighbors.json

PING_OUTPUT="$(ping -c 1 6.6.1.2 | grep "1 received")" # THIS LINE WAS CHANGED

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'6.6.1.2'" >> client-neighbors.json # THIS LINE WAS CHANGED
fi 

PING_OUTPUT="$(ping -c 1 6.6.1.3 | grep "1 received")" THIS LINE WAS CHANGED

if ! [ -z "$PING_OUTPUT" ]; then 
	echo ", '6.6.1.3'" >> client-neighbors.json # THIS LINE WAS CHANGED. NOTE THE COMMA AND SPACE BEFORE THE STRING. THIS IS IMPORTANT FOR JSON PARSING
fi 

echo "]" >> client-neighbors.json

#End JSON file with curly bracket
echo "}" >> client-neighbors.json 



4.) Within controller directory, run 'python client.py [your_mesh_ip_here]' This script takes the mesh IP, just the normal 6.6.1.x. 

5.) Repeat Steps 3 and 4 for all your clients.