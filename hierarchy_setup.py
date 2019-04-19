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
	'B':['D','E'],
	'C':['F','G'],
	'D':['H','I'],
	'E':['J','K'],
	'F':['L','M'],
	'G':['N','O']
	}

hierarchy_ports = {
	'ANY_PORT':['PRIV','NON_PRIV'],
	'PRIV':priv_port_list,
	'NON_PRIV':non_priv_port_list	
	}

"""
BY FINDING MATCHING NODES IN THE PATHS TAKEN WITHIN THE FIND_SHORT_PATH FUNC YOU CAN THEN ELIMINATE THE MATCHES FROM THE COUNT OF THE DISTANCE BETWEEN THE TWO NODES, THEREFORE GIVING YOU THE TOTAL DISTANCE BETWEEN THE TWO NODES, FIXING THE ISSUE OF NOT BEING ABLE TO BACK TRACK IN THE DICTIONARY DAGS
"""

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

#print(find_shortest_path(graph, 'A', 'H'))
#print(find_shortest_path(graph, 'A', 'A'))

def find_total_dist(graph, start, end_1, end_2):
	distance_1 = find_shortest_path(graph, start, end_1) #['ANY_PORT', 'PRIV', '1024']
	distance_2 = find_shortest_path(graph, start, end_2) #['ANY_PORT', 'PRIV', '80']	
	non_matches = 0

	length_1 = len(distance_1)
	length_2 = len(distance_2)

	if length_1 > length_2:
		length = length_1 - length_2
		for i in distance_1:
			if i not in distance_2:
				non_matches = non_matches + 1
		total_distance = (non_matches * 2) - length
	elif length_1 < length_2:
		length = length_2 - length_1
		for i in distance_1:
			if i not in distance_2:
				non_matches = non_matches + 1
		total_distance = (non_matches * 2) - length
	else:
		for i in distance_1:
			if i not in distance_2:
				non_matches = non_matches + 1
		total_distance = non_matches * 2

	return total_distance

#print(find_total_dist(hierarchy_ports, 'ANY_PORT', '1024', '80'))
print(find_total_dist(graph, 'A', 'H', 'F'))