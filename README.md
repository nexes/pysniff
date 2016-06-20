#PySniff
##What is it
Capture ethernet packets passing through your computer. The captured packets and be printed to the console or saved to a file.

##Usage
pysniff.py [options]

|Option|Description|
|------|-----------|
|-l, --length|Assign the number of packets to be captured. If blank, will continue to run|
|-p, --promiscuous|will place the NIC in monitoring/promiscuous mode to capture all network traffic|
|-o, --output|The name of the output file to be saved. This will save in the users home directory by default|
|-h, --help|This help message|

##Example output
*You will probably need to run this with elevated privileges, e.g sudo or run as administrator*

pysniff.py --length 1 -p
```
Source IP: 192.168.0.1 Destination IP: 239.255.255.250 Source MAC: - Destination MAC: -
                 	Version: 4 Size: 430 	ID: 0 	TTL: 4   Type: UDP
                 	Source port: 46216 Destination port: 1900
		Header size: 410 Checksum: 39672

		b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1800\r\nCACHE-CONTROL: max-
		age=100\r\nLOCATION: http://192.168.0.1:49179/description.xml\r\nNT:
		urn:schemas-wifialliance-org:service:WFAWLANConfig:1\r\nNTS:
		ssdp:alive\r\nSERVER: Linux/2.6.20.19, UPnP/1.0, Portable SDK for UPnP
		devices/1.3.1\r\nX-User-Agent: redsonic\r\nUSN:
		uuid:bc426e00-1dd8-11f2-8a01-2a235d92dde8::urn:schemas-wifialliance-
		org:service:WFAWLANConfig:1\r\n\r\n'
--------------------------------------------------------------------------------
Source IP: 192.168.0.149 Destination IP: 172.217.3.174 Source MAC: - Destination MAC: -
                 	Version: 4 Size: 41 	ID: 26486 	TTL: 128   Type: TCP
                 	Source port: 58773 Destination port: 443  
 	ECE : 0	URG : 0	RST : 0	NS  : 0
	FIN : 0	PSH : 1	SYN : 1	ACK : 0	CWR : 0
	Seq number: 270676286 ACK number: 350090098 Checksum: 29152

		b'\x00'
------------------------------------------------------------------------------------------
Source IP: 172.217.3.174 Destination IP: 192.168.0.149 Source MAC: - Destination MAC: -
                 	Version: 4 Size: 52 	ID: 51769 	TTL: 56   Type: TCP
                 	Source port: 443   Destination port: 58773
 	ECE : 0	URG : 0	RST : 0	NS  : 0
	FIN : 1	PSH : 0	SYN : 0	ACK : 0	CWR : 0
	Seq number: 350090098 ACK number: 270676287 Checksum: 21213

		b'\x01\x01\x05\n\x10"1>\x10"1?'
```

##TODO:
* parse more packet types
* sniff out other networked computers and open ports
* GUI

#LICENSE (MIT)
Copyright (c) 2016 Joe Berria