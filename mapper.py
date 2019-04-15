#!/usr/bin/env python

"""mapper.py"""

"""
Author: Joe Yelland // B525320 // COC251 
#----------------------------------------#
STAGE 1 - Mapper 
Input: Raw Snort IDS Alert log file
Output: Tuples of the form (Alarm Type, Source-port, Source-IP, Dest-port, Dest-IP, Time) contained within a list
#----------------------------------------#
START SOURCES
[1] - https://stackoverflow.com/questions/1883980/find-the-nth-occurrence-of-substring-in-a-string
END SOURCES
#----------------------------------------#
"""

import sys
import re

with open("test_dataset_full.pcap") as test_dataset: #Inputting and parsing alert logs line by line 
	content = test_dataset.readlines()

#----------------------------------------# Start source [1]
def find_nth(string, substring, n):
	parts = string.split(substring, n + 1)
	if len(parts) <= n + 1:
		return -1
	return len(string) - len(parts[-1]) - len(substring)
#----------------------------------------# End source [1]

def alert_type(list):
	a2 = find_nth(list[0], "]", 1) # Finding the alert Snort signature

	a4 = find_nth(list[0], "[", 2) # Finding alert type
	a5 = list[0][a2 + 2 : a4 - 1] #""

	return a5

def alert_classification(list):
	b1 = list[1].index(":") # Finding the alert classification
	b2 = list[1].index("]") # ""
	b3 = list[1][b1 + 2:b2] # ""

	b4 = find_nth(list[1], ":", 1) # Finding the priority of alert
	b5 = len(list[1]) - 3 # ""
	b6 = list[1][b4 + 2 : b5] # ""
	
	return b3, b6

def alert_date_time(list):
	c1 = list[2].index("-") # Finding alert date
	c2 = list[2][: c1] # ""

	c3 = list[2].index(" ")# Finding alert time
	c4 = list[2][c1 + 1 : c3]
	return c2, c4

def exception_source_ip_port(list): # EXCEPTION CASE
	z2 = list[6].index(":") # Finding source IP
	z3 = list[6][: z2] # ""

	z4 = list[6].index(" ") # Finding source port
	z5 = list[6][z2 + 1 : z4] # ""
	return z3, z5

def exception_dest_ip_port(list): # EXCEPTION CASE
	y1 = find_nth(list[6], " ", 1) # Finding dest IP
	y2 = find_nth(list[6], ":", 1)
	y3 = list[6][y1 + 1 : y2] # ""

	y4 = list[6].index(" ") # Finding dests port
	y5 = list[6].index("\n") # ""
	y6 = list[6][y2 + 1 : y5] # ""
	return y3, y6

def alert_exception(exception):
	if((exception.index("** ORIGINAL DATAGRAM DUMP:\n")) < 10):
		return "True", exception_source_ip_port(content), exception_dest_ip_port(content)
	else:
		return "False"
"""
[**] [1:402:7] ICMP Destination Unreachable Port Unreachable [**]
[Classification: Misc activity] [Priority: 3] 
03/16-07:30:00.060000 192.168.27.25 -> 192.168.202.100
ICMP TTL:127 TOS:0x0 ID:25932 IpLen:20 DgmLen:56
Type:3  Code:3  DESTINATION UNREACHABLE: PORT UNREACHABLE
** ORIGINAL DATAGRAM DUMP:
192.168.202.100:45660 -> 192.168.27.25:19322
UDP TTL:37 TOS:0x0 ID:59923 IpLen:20 DgmLen:28
Len: 0  Csum: 39736
** END OF DUMP

[**] [1:2049:4] MS-SQL ping attempt [**]
[Classification: Misc activity] [Priority: 3] 
03/16-07:42:07.620000 192.168.202.79:57173 -> 255.255.255.255:1434
UDP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:29 DF
Len: 1
[Xref => http://cgi.nessus.org/plugins/dump.php3?id=10674]
"""

def alert_source_ip_port(list):
	d1 = list[2].index(" ") # Finding source IP
	d2 = find_nth(list[2], ":", 2) # ""
	d3 = list[2][d1 + 1: d2] # ""

	d4 = find_nth(list[2], " ", 1) # Finding source port
	d5 = list[2][d2 + 1 : d4] # ""
	return d3, d5

def alert_dest_ip_port(list):
	e1 = find_nth(list[2], " ", 2) # Finding dest IP
	e2 = find_nth(list[2], ":", 3)# ""
	e3 = list[2][e1 + 1 : e2] # ""

	e4 = find_nth(list[2], ":", 3) # Finding dest port
	e5 = list[2].index("\n")
	e6 = list[2][e4 + 1 : e5] # ""
	return e3, e6

def alert_data(list): 
	alert_data_array = []
	colon_finder = 0
	i = 0

	while colon_finder != -1 or i == (range(len(list[1]) - 1)):
		colon_finder = find_nth(list[3], ":", i) 
		try:	
			space_finder = list[3][colon_finder:].index(" ")
		except:
			pass
		if(colon_finder != -1):
			alert_data_array.append(list[3][colon_finder + 1: space_finder + colon_finder])	
		i = i + 1	
	return alert_data_array

def alert_removal(alert_log):
	i = 0 
	next_alert = alert_log.index("\n")
	while i < (next_alert + 1):
		x = alert_log[0]
		alert_log.remove(x)
		i = i + 1
	return alert_log


def alert_appending(alert_log):
	alert_types = []
	
	next_alert = alert_log.index("\n")
	exception_case = alert_exception(content)

	if(exception_case[0] == "True"):
		#alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content)[0])
		alert_types.append(alert_classification(content)[1])
		alert_types.append(alert_date_time(content)[0])
		alert_types.append(alert_date_time(content)[1])
		alert_types.append(exception_case[1][0])
		alert_types.append(exception_case[1][1])
		alert_types.append(exception_case[2][0])
		alert_types.append(exception_case[2][1])
	else:
		#alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content)[0])
		alert_types.append(alert_classification(content)[1])
		alert_types.append(alert_date_time(content)[0])
		alert_types.append(alert_date_time(content)[1])
		alert_types.append(alert_source_ip_port(content)[0])
		alert_types.append(alert_source_ip_port(content)[1])
		alert_types.append(alert_dest_ip_port(content)[0])
		alert_types.append(alert_dest_ip_port(content)[1])
		
	return alert_types

def alert_number(alert_log):
	z = 0
	for i in alert_log:
		if i == "\n":
			z = z + 1
	return z

def alert_grouping(alert_log):
	alert_full = []
	i = 0
	x = 0
	alert_num = alert_number(content)

	while i < alert_num:
		alert_full.append(alert_appending(alert_log))
		alert_removal(alert_log)
		print(alert_full[i])
		i = i + 1
	return alert_full


alert_grouping(content)
for i in alert_grouping(content):
	print i
"""

#Checking all alert types
all_types = []
for i in content:
	if i.startswith("[Classification:"):
		b1 = i.index(":") # Finding the alert classification
		b2 = i.index("]") # ""
		b3 = i[b1 + 2 : b2] # ""
		if(b3 not in all_types):
			all_types.append(b3)


#Checking all alert reasons
alert_classes = []
for x in content:
	if x.startswith("[**]"):
		a2 = find_nth(x, "]", 1) 
		a4 = find_nth(x, "[", 2)
		a5 = x[a2 + 2 : a4 - 1]
		alert_classes.append(a5)


166491




"""
