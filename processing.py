"""
Stage 1 - pre-processing the data found in the IDS Log files, in order to attain all the 
relevant data from each alert log before passing it into the mapper and the reducer
"""

with open("test_dataset.pcap") as test_dataset: #Inputting and parsing alert logs line by line 
    content = test_dataset.readlines()
    
content = [x.strip("\n ") for x in content] #Removing \n and spaces from the logs 



"""
[**] [1:2009358:5] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [**]
[Classification: Web Application Attack] [Priority: 1] 
03/16-07:30:00.000000 192.168.202.79:50465 -> 192.168.229.251:80
TCP TTL:127 TOS:0x0 ID:1573 IpLen:20 DgmLen:218 DF
***AP**F Seq: 0x9EB207E5  Ack: 0xB58E1793  Win: 0xFA4A  TcpLen: 32
[Xref => http://doc.emergingthreats.net/2009358]
"""