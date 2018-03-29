### CODE FROM USER mVChr on StackOverflow

from collections import defaultdict
import math

class Graph(object):
    """ Graph data structure. Set to directed graph as default"""

    def __init__(self, directed=True):
        # Represent graph as dictionary of sets. Node is key, neighbors are enumerated in set
        self._graph = defaultdict(set)
        self._directed = directed 
        self.all_nodes = set() # Set of all nodes (vertices set)
        self.all_gateways = set() # Set of all gateways
        self.has_seen = set() # Set of all nodes communicated with in past x iterations of server code

    def update_seen(self, client_ip): 
        self.has_seen.add(client_ip)

    def reset_seen(self): 
        set_difference = self.all_nodes.difference(self.has_seen)
        for s in set_difference: 
            self._graph.remove(s)    # MIGHT CAUSE ERRORS?
            self.all_nodes.remove(s)
            if s in self.all_gateways: 
                self.all_gateways.remove(s)
        self.has_seen = set()

    '''
    @param: client_ip address and a list of its neighbors
    @return: nothing
    Update the neighbors of a client to be its list of neighbors. 
    '''
    def update_neighbors(self, client_ip, client_neighbors): 
        # If client hasn't been seen yet, add to graph
        if client_ip not in self.all_nodes: 
            self.all_nodes.add(client_ip)

        # Update client's neighbors in graph. If neighbor not in graph, add to it
        new_neighbors = set()
        for n in client_neighbors: 
            new_neighbors.add(n)
            if n not in self.all_nodes: 
                self.all_nodes.add(n)
        self._graph[client_ip] = new_neighbors

    '''
    @param: client ip address and boolean whether or not it is a gateway
    @return: nothing
    Update node as gateway if it is a gateway
    '''
    def update_gateways(self, client_ip, is_gateway): 
        if is_gateway == True: 
            self.all_gateways.add(client_ip)
        else: 
            if client_ip in self.all_gateways: 
                self.all_gateways.remove(client_ip)

    def add_connections_list(self, connections):
        """ Add connections (list of tuple pairs) to graph """

        for node1, node2 in connections:
            self.add_connection(node1, node2)

    def add_connection(self, node1, node2):
        """ Add connection between node1 and node2 """

        self._graph[node1].add(node2)
        if not self._directed:
            self._graph[node2].add(node1)

    def remove(self, node):
        """ Remove all references to node """

        for n, cxns in self._graph.iteritems():
            try:
                cxns.remove(node)
            except KeyError:
                pass
        try:
            del self._graph[node]
        except KeyError:
            pass

    def is_connected(self, node1, node2):
        """ Is node1 directly connected to node2 """

        return node1 in self._graph and node2 in self._graph[node1]

    def find_best_gateway(self, client_ip): 
        q = []
        dist = {}
        prev = {}
        for v in self.all_nodes: 
            dist[v] = 100000
            prev[v] = None
            q.append(v)

        dist[client_ip] = 0

        while len(q) > 0: 
            #print("dictionary keys are: ")
            set_of_keys = set(dist.keys())
            #print(set_of_keys)
            set_of_queue = set(q)
            intersection = set_of_queue.intersection(set_of_keys)
            #print("intersection set is: ")
            #print(intersection)

            #u = min(dist, key=dist.get)
            min_dist = 100000
            for i in intersection: 
                if dist[i] < min_dist: 
                    min_dist = dist[i]
                    u = i

            #print("u is: ")
            #print(u)
            q.remove(u)
            neighbors = self._graph[u]
            #print("neighbors are: ")
            #print(neighbors)

            for v in neighbors: 
                alt = dist[u] + 1
                if alt < dist[v]: 
                    dist[v] = alt
                    prev[v] = u

        min_dist_gateway = 100000
        return_gateway = ""
        for g in self.all_gateways: 
            if dist[g] < min_dist_gateway: 
                return_gateway = g
        return return_gateway

    def find_path(self, node1, node2, path=[]):
        """ Find any path between node1 and node2 (may not be shortest) """
        print("in find_path function in graph.py")
        path = path + [node1]
        if node1 == node2:
            print("returning path in find_path function")
            return path
        if node1 not in self._graph:
            print("node1 not in self._graph")
            return None
        for node in self._graph[node1]:
            if node not in path:
                new_path = self.find_path(node, node2, path)
                if new_path:
                    print("returning new_path")
                    return new_path
        return None

    def __str__(self):
        return '{}({})'.format(self.__class__.__name__, dict(self._graph))
