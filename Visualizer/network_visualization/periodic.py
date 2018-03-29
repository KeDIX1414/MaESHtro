import time, threading
def foo(bool):
	file = open('data/changenet.json', 'w')
	if bool:
	    file.write('{"edges": [{"source" : "0","target" : "2","id" : "0"}, {"source" : "0","target" : "1","id" : "1"}, {"source" : "1","target" : "3","id" : "2"}, {"source" : "1","target" : "4","id" : "3"}, {"source" : "4","target" : "5","id" : "4"}],"nodes" : [{"id" : "0","label": "switch-1","level": 0,"util" : 50}, {"id" : "1","label": "switch-2","level": 0,"util" : 100}, {"id" : "2","label": "switch-3","level": 1,"util" : 30}, {"id" : "3","label": "switch-4","level": 1,"util" : 20}, {"id" : "4","label": "switch-5","level": 1,"util" : 0}, {"id" : "5","label": "switch-6","level": 2,"util" : 50}]}')
	    file.close()
	    threading.Timer(1, foo, [False]).start()
	else:
	    file.write('{"edges": [{"source" : "0","target" : "2","id" : "0"}, {"source" : "0","target" : "1","id" : "1"}, {"source" : "1","target" : "3","id" : "2"}, {"source" : "1","target" : "4","id" : "3"}],"nodes" : [{"id" : "0","label": "switch-1","level": 0,"util" : 50}, {"id" : "1","label": "switch-2","level": 0,"util" : 0}, {"id" : "2","label": "switch-3","level": 1,"util" : 100}, {"id" : "3","label": "switch-4","level": 1,"util" : 60}, {"id" : "4","label": "switch-5","level": 1,"util" : 0}]}')
	    file.close()
	    threading.Timer(1, foo, [True]).start()

foo(True)