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
[1] - https://stackoverflow.com/questions/1883980/find-the-nth-occurrence-of-substring-in-a-string/
[2] - https://www.python.org/doc/essays/graphs/
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

def string_inversion(input): # INPUTS A STRING AND OUTPUTS ITS REVERSE
	output = input[::-1] # Inversion using slicing
	return output

def alert_type(list):# FINDS ALERT TYPE
	a2 = find_nth(list[0], "]", 1) # Finding the alert Snort signature

	a4 = find_nth(list[0], "[", 2) # Finding alert type
	a5 = list[0][a2 + 2 : a4 - 1] #""

	return a5

def alert_classification(list): # FINDS ALERT CLASSIFICATION
	b1 = list[1].index(":") # Finding the alert classification
	b2 = list[1].index("]") # ""
	b3 = list[1][b1 + 2:b2] # ""

	b4 = find_nth(list[1], ":", 1) # Finding the priority of alert
	b5 = len(list[1]) - 3 # ""
	b6 = list[1][b4 + 2 : b5] # ""
	
	return b3

def alert_source_ip_port(list): # FINDS SOURCE PORT AND IP
	d1 = list[2].index(" ") # Finding source IP
	d2 = find_nth(list[2], ":", 2) # ""
	d3 = list[2][d1 + 1: d2] # ""

	d4 = find_nth(list[2], " ", 1) # Finding source port
	d5 = list[2][d2 + 1 : d4] # ""
	return d3, d5

def alert_dest_ip_port(list): # FINDS DESTINATION PORT AND IP
	e1 = find_nth(list[2], " ", 2) # Finding dest IP
	e2 = find_nth(list[2], ":", 3)# ""
	e3 = list[2][e1 + 1 : e2] # ""

	e4 = find_nth(list[2], ":", 3) # Finding dest port
	e5 = list[2].index("\n")
	e6 = list[2][e4 + 1 : e5] # ""
	return e3, e6

def exception_case_1(list): # EXCEPTION CASE
	z2 = list[6].index(":") # Finding source IP
	z3 = list[6][: z2] # ""

	z4 = list[6].index(" ") # Finding source port
	z5 = list[6][z2 + 1 : z4] # ""
	return z3, z5

def exception_case_1_1(list): # EXCEPTION CASE
	y1 = find_nth(list[6], " ", 1) # Finding dest IP
	y2 = find_nth(list[6], ":", 1)
	y3 = list[6][y1 + 1 : y2] # ""

	y4 = list[6].index(" ") # Finding dests port
	y5 = list[6].index("\n") # ""
	y6 = list[6][y2 + 1 : y5] # ""
	return y3, y6

def exception_case_5(exception): # EXCEPTION CASE
	t1 = string_inversion(exception[2])
	t2 = t1.index(":")
	t3 = string_inversion(t1[: t2]).rstrip()

	t5 = find_nth(t1, " " , 1)
	t6 = t1[t5:].index(":")
	t7 = string_inversion(t1[t5 + 1 : t6 + t5]).rstrip()
	
	return t7,t3

def alert_removal(alert_log): # REMOVES THE NEXT ALERT IN THE LIST
	i = 0 
	next_alert = alert_log.index("\n")
	while i < (next_alert + 1):
		x = alert_log[0]
		alert_log.remove(x)
		i = i + 1
	return alert_log

def alert_number(alert_log): # FINDS THE NUMBER OF ALERTS IN THE LIST
	z = 0
	for i in alert_log:
		if i == "\n":
			z = z + 1
	return z

def alert_exception(exception): # FINDS ALERT DATA AND DECIDES ON EXCEPTION CASE
	next_alert = exception.index("\n")
	next_group = exception[2].index(" ")

	if("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert] and (":" in exception[6])):
		return "Case_1"
	elif(("** ORIGINAL DATAGRAM DUMP:\n" in exception[ : next_alert]) and (":" not in exception[6])):
		return "Case_2"
	elif(":" not in exception[2][next_group:]):
		return "Case_3"
	elif(" :: " in exception[2]):
		return "Case_4"
	elif(exception[2].count(":") > 4):
		return "Case_5"
	else:
		return "Case_6"

def alert_appending(alert_log): # APPENDS THE CORRECT DATA DEPENDING IN ALERT_EXCEPTION OUTPUT
	alert_types = []
	
	next_alert = alert_log.index("\n")
	exception_case = alert_exception(content)

	if(exception_case == "Case_1"):
		alert_types.append(alert_type(content)) #0
		alert_types.append(alert_classification(content)) #1
 		alert_types.append(exception_case_1(content)[1]) #2
		alert_types.append(exception_case_1(content)[0]) #3
		alert_types.append(exception_case_1_1(content)[1]) #4
		alert_types.append(exception_case_1_1(content)[0]) #5
	elif(exception_case == "Case_2"):
		pass
	elif(exception_case == "Case_3"):
		pass
	elif(exception_case == "Case_4"):
		alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content))
		alert_types.append("Undefined") # Source Port Not defined
		alert_types.append("Undefined") # Source IP Not defined
		alert_types.append("Undefined") # Dest Port Not defined
		alert_types.append("Undefined") # Dest IP Not defined
	elif(exception_case == "Case_5"):
		alert_types.append(alert_type(content))
		alert_types.append(alert_classification(content))
		alert_types.append(exception_case_5(content)[0])
		alert_types.append("Undefined") # IP Not defined
		alert_types.append(exception_case_5(content)[1])
		alert_types.append("Undefined") # IP Not defined
	else:
		alert_types.append(alert_type(content)) #0
		alert_types.append(alert_classification(content)) #1
		alert_types.append(alert_source_ip_port(content)[1]) #2
		alert_types.append(alert_source_ip_port(content)[0]) #3
		alert_types.append(alert_dest_ip_port(content)[1]) #4
		alert_types.append(alert_dest_ip_port(content)[0]) #5
	return alert_types

def alert_grouping(alert_log): # RUNS THROUGH ALERT LOG DATA 
	alert_full = []
	i = 0
	x = 0
	alert_num = alert_number(content)
	mapper_output = open("mapper_output.txt","w+")

	while i < alert_num:
		print(i)
		q1 = alert_appending(alert_log)
		if(len(q1) == 0):
			alert_removal(alert_log)
		else:
			alert_full.append([q1])
			alert_removal(alert_log)
			mapper_output.write("%s\n" % q1)
		i = i + 1
	return alert_full

alert_grouping(content) # CALLING FUNCTION