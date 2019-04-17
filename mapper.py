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
	
	return b3

def alert_date_time(list):
	c1 = list[2].index("-") # Finding alert date
	c2 = list[2][: c1] # ""

	c3 = list[2].index(" ")# Finding alert time
	c4 = list[2][c1 + 1 : c3]
	return c2, c4

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

def string_inversion(input): # Inverts a string that is given as input
	output = input[::-1] # Inversion using slicing
	return output

def exception_case_4(exception):
	t1 = string_inversion(exception)
	t2 = t1.index(":")
	t3 = string_inversion(t1[: t2])
	
	t5 = find_nth(t1, " " , 1)
	t6 = t1[t5:].index(":")
	t7 = string_inversion(t1[t5 + 1 : t6 + t5])
	
	return t3, t7

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

def alert_exception(exception): #Finds what alert is currently being read and finds what to append
	next_alert = exception.index("\n")
	next_group = exception[2].index(" ")

	if("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert] and (":" in exception[6])):
		return "Case_1", exception_source_ip_port(content), exception_dest_ip_port(content)
	elif(("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert]) and (":" not in exception[6])):
		return "Case_2"
	elif(":" not in exception[2][next_group:]):
		return "Case_3"
	elif(WHAT?):
		return "Case_4"
	else:
		return "Case_5"

def alert_appending(alert_log):
	alert_types = []
	
	next_alert = alert_log.index("\n")
	exception_case = alert_exception(content)

	if(exception_case[0] == "Case_1"):
		#alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content))
		alert_types.append(alert_date_time(content)[0])
		alert_types.append(alert_date_time(content)[1])
		alert_types.append(exception_case[1][0])
 		alert_types.append(exception_case[1][1])
		alert_types.append(exception_case[2][0])
		alert_types.append(exception_case[2][1])
	elif(exception_case == "Case_2"):
		pass
	elif(exception_case == "Case_3"):
		pass
	elif(exception_case == "Case_4"):
		#alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content))
		alert_types.append(alert_date_time(content)[0])
		alert_types.append(alert_date_time(content)[1])
		alert_types.append("Undefined") # IP Not defined
		alert_types.append(exception_case_4(content)[1])
		alert_types.append("Undefined") # IP Not defined
		alert_types.append(exception_case_4(content)[0])
	else:
		#alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content))
		alert_types.append(alert_date_time(content)[0])
		alert_types.append(alert_date_time(content)[1])
		alert_types.append(alert_source_ip_port(content)[0])
		alert_types.append(alert_source_ip_port(content)[1])
		alert_types.append(alert_dest_ip_port(content)[0])
		alert_types.append(alert_dest_ip_port(content)[1])

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


#print(alert_exception(content))
#alert_grouping(content)

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
