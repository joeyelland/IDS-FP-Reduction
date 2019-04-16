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

def big_daddy(list):
	a2 = find_nth(list[0], "]", 1) # Finding the alert Snort signature

	a4 = find_nth(list[0], "[", 2) # Finding alert type
	a5 = list[0][a2 + 2 : a4 - 1] #

	b1 = list[1].index(":") # Finding the alert classification
	b2 = list[1].index("]") # ""
	b3 = list[1][b1 + 2:b2] # ""

	c1 = list[2].index("-") # Finding alert date
	c2 = list[2][: c1] # ""

	c3 = list[2].index(" ")# Finding alert time
	c4 = list[2][c1 + 1 : c3]

	d1 = list[2].index(" ") # Finding source IP
	d2 = find_nth(list[2], ":", 2) # ""
	d3 = list[2][d1 + 1: d2] # ""

	d4 = find_nth(list[2], " ", 1) # Finding source port
	d5 = list[2][d2 + 1 : d4] # ""

	e1 = find_nth(list[2], " ", 2) # Finding dest IP
	e2 = find_nth(list[2], ":", 3)# ""
	e3 = list[2][e1 + 1 : e2] # ""

	e4 = find_nth(list[2], ":", 3) # Finding dest port
	e5 = list[2].index("\n")
	e6 = list[2][e4 + 1 : e5] # ""

	return b3, c2, c4, d3, d5, e3, e6

def big_daddy_exception(list):
	a2 = find_nth(list[0], "]", 1) # Finding the alert Snort signature

	a4 = find_nth(list[0], "[", 2) # Finding alert type
	a5 = list[0][a2 + 2 : a4 - 1] #

	b1 = list[1].index(":") # Finding the alert classification
	b2 = list[1].index("]") # ""
	b3 = list[1][b1 + 2:b2] # ""

	c1 = list[2].index("-") # Finding alert date
	c2 = list[2][: c1] # ""

	c3 = list[2].index(" ")# Finding alert time
	c4 = list[2][c1 + 1 : c3]

	z2 = list[6].index(":") # Finding source IP
	z3 = list[6][: z2] # ""

	z4 = list[6].index(" ") # Finding source port
	z5 = list[6][z2 + 1 : z4] # ""
	
	y1 = find_nth(list[6], " ", 1) # Finding dest IP
	y2 = find_nth(list[6], ":", 1)
	y3 = list[6][y1 + 1 : y2] # ""

	y4 = list[6].index(" ") # Finding dests port
	y5 = list[6].index("\n") # ""
	y6 = list[6][y2 + 1 : y5] # ""

	return b3, c2, c4, z3, z5, y3, y6

def alert_removal(alert_log):
	i = 0 
	next_alert = alert_log.index("\n")
	while i < (next_alert + 1):
		x = alert_log[0]
		alert_log.remove(x)
		i = i + 1
	return alert_log

def alert_number(alert_log):
	z = 0
	for i in alert_log:
		if i == "\n":
			z = z + 1
	return z

def alert_exception(exception):
	next_alert = exception.index("\n")
	next_group = exception[2].index(" ")

	if("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert] and (":" in exception[6])):
		return "Case_1"
	elif(("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert]) and (":" not in exception[6])):
		return "Case_2"
	elif(":" not in exception[2][next_group:]):
		return "Case_3"
	else:
		return "Case_4"

def alert_appending(alert_log):
	alert_types = []
	
	next_alert = alert_log.index("\n")
	exception_case = alert_exception(content)

	if(exception_case == "Case_1"):
		alert_types.append(big_daddy_exception(content))
	elif(exception_case == "Case_2"):
		pass
	elif(exception_case == "Case_3"):
		pass
	else:
		alert_types.append(big_daddy(content))

	return alert_types


def alert_grouping(alert_log):

	alert_full = []
	i = 0
	x = 0
	alert_num = alert_number(content)
	while i < alert_num:
		q1 = alert_appending(alert_log)
		if(len(q1) == 0):
			alert_removal(alert_log)
		else:
			alert_full.append(q1)
			alert_removal(alert_log)	
			print(i, q1)

		i = i + 1
	return alert_full

alert_grouping(content)

"""
for i in alert_grouping(content):
	print i

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


166,491
"""
