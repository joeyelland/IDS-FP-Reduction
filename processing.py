"""
Author: Joe Yelland B525320
#----------------------------------------#
STAGE 1 - PREPROCESSING 
pre-processing the data found in the IDS Log files, in order to attain all the 
relevant data from each alert log as well as putting it into an easier format for the mapper
to deal with
#----------------------------------------#
START SOURCES
[1] - https://stackoverflow.com/questions/1883980/find-the-nth-occurrence-of-substring-in-a-string
END SOURCES
#----------------------------------------#
"""

alert_types = []

with open("test_dataset.pcap") as test_dataset: #Inputting and parsing alert logs line by line 
	content = test_dataset.readlines()

#----------------------------------------# Start source [1]
def find_nth(string, substring, n):
	parts = string.split(substring, n + 1)
	if len(parts) <= n + 1:
		return -1
	return len(string) - len(parts[-1]) - len(substring)
#----------------------------------------# End source [1]

def alert_type(list):
	a1 = find_nth(list[0], "[", 1) # Finding the alert Snort signature
	a2 = find_nth(list[0], "]", 1) # ""
	a3 = list[0][a1 + 1:a2] # ""

	a4 = find_nth(list[0], "[", 2) # Finding alert type
	a5 = list[0][a2 + 2 : a4] #""

	return a3, a5

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

def alert_source_ip_port(list):
	d1 = list[2].index(" ") # Finding source IP
	d2 = find_nth(list[2], ":", 2) # ""
	d3 = list[2][d1 + 1: d2] # ""

	d4 = find_nth(list[2], " ", 1) # Finding source port
	d5 = list[2][d2 + 1 : d4] # ""
	return d3, d5

def alert_dest_ip_port(list):
	e1 = find_nth(list[2], " ", 2) # Finding dest IP
	e2 =  find_nth(list[2], ":", 3)# ""
	e3 = list[2][e1 + 1 : e2] # ""

	e4 = find_nth(list[2], ":", 3) # Finding dest port
	e5 = list[2].index("\n")
	e6 = list[2][e4 + 1 : e5] # ""
	return e3, e6

#print(alert_classification(content))
#print(alert_type(content))
#print alert_date_time(content)
print alert_dest_ip_port(content)




"""
[**] [1:2009358:5] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [**]
[Classification: Web Application Attack] [Priority: 1] 
03/16-07:30:00.000000 192.168.202.79:50465 -> 192.168.229.251:80
TCP TTL:127 TOS:0x0 ID:1573 IpLen:20 DgmLen:218 DF
***AP**F Seq: 0x9EB207E5  Ack: 0xB58E1793  Win: 0xFA4A  TcpLen: 32
[Xref => http://doc.emergingthreats.net/2009358]
"""