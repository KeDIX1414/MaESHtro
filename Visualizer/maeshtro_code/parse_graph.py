import time

def parse_graph():	
	connections = set()
	pis = set()
	gateways = set()

	with open('a.txt') as f:
		firstline = f.readline()
		unparsed_connections = firstline[27:].split(']),')
		for node in unparsed_connections:
			parsed = node.split('\'')[1::2]
			node_id = parsed.pop(0)
			pis.add(node_id)
			parsed_connections = set((node_id, x) for x in parsed)
			connections |= parsed_connections
		nextline = f.readline()
		while nextline:
			gateways |= {nextline.strip()}
			nextline = f.readline()
	# print connections
	# print gateways

	link_counter = 0
	node_counter = 0

	link_list = []
	for link in connections:
		link_list.append({"source" : link[0], "target": link[1], "id": link_counter})
		link_counter += 1

	node_list = []
	for pi in pis:
		pi_util = 100 if pi in gateways else 0
		node_list.append({"id" : str(pi), "label": "pi" + str(node_counter), "level": int(pi)/2, "util": pi_util})
		node_counter += 1

	data ='{"edges":' + str(link_list).replace('\'', '"') + ', "nodes":' + str(node_list).replace('\'', '"') + '}'
	datafile = open('maeshtro.json', 'w')
	datafile.write(data)
	time.sleep(1)

while True:
	parse_graph()