priv_ports = list(range(1,1025))
priv_port_list = []

non_priv_ports = list(range(1025,65535))
non_priv_port_list = []


for i in non_priv_ports:
	y = str(i)
	non_priv_port_list.append(y)

for i in priv_ports:
	x = str(i)
	priv_port_list.append(x)

graph = {
	'A':['B','C'],
	'B':['C','D'],
	'C':['D'],
	'D':['C'],
	'E':['F'],
	'F':['C']}

hierarchy_ports = {
	'ANY_PORT':['PRIV','NON-PRIV'],
	'PRIV':priv_port_list,
	'NON_PRIV':non_priv_port_list
}

print(hierarchy_ports.get("NON_PRIV"))

def find_path(graph, start, end, path=[]):
	path = path + [start]
	if start == end:
		return path
	if not graph.has_key(start):
		return None
	for node in graph[start]:
		if node not in path:
			newpath = find_path(graph, node, end, path)
			if newpath: return newpath
	return None

def find_shortest_path(graph, start, end, path=[]):
	path = path + [start]
	if start == end:
		return path
	if not graph.has_key(start):
		return None
	shortest = None
	for node in graph[start]:
		if node not in path:
			newpath = find_shortest_path(graph, node, end, path)
			if newpath:
				if not shortest or len(newpath) < len(shortest):
					shortest = newpath
	return shortest

#print(find_shortest_path(graph, 'A', 'D'))
#print(find_path(graph, 'A', 'D'))