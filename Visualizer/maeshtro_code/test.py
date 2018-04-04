from graph import Graph

#Construct a graph and add all the connections you want (in directed graph)
graph = Graph()
connections = [("0", "1"), ("0", "2"), ("2", "3"), ("3", "0"), ("1", "4"), ("4", "1")]
graph.add_connections_list(connections)

# Print graph -- THIS IS WHAT YOU'RE WORKING WITH HERE
print(graph._graph)

# Add all nodes currently in network to all_nodes set
graph.all_nodes.add("0")
graph.all_nodes.add("1")
graph.all_nodes.add("2")
graph.all_nodes.add("3")
graph.all_nodes.add("4")

# Add gateway to network
graph.all_gateways.add("0")
graph.all_gateways.add("4")

# Find best gateway for given node using Dijkstra's
# g = graph.find_best_gateway("0")
# print("Best gateway is: ")
# print(g)

# Print all current gateways
# print("Printing all gateways now: ")
for s in graph.all_gateways: 
	print(s)


