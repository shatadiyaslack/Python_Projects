import socket
import urllib
from binascii import*
from bs4 import BeautifulSoup
from struct import*


#Parsing XML file to get Protocol Names
thisurl="http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml"
handle=urllib.urlopen(thisurl)
xml_file=handle.read()
file1= open("protocol.xml","wb")
file1.write(xml_file)
file1.close()

#Using BeautifulSoup for XML Parsing

soup = BeautifulSoup(open("protocol.xml"),"xml")

protocol_name={}
for rec in soup.registry.registry.findAll("record"):
	rec_p=rec.get_text().split("\n")
	protocol_num=rec_p[1].encode('ascii')
	protocol_name[protocol_num]=rec_p[2].encode('ascii')

#Convert a string of 6 characters of ethernet address to a colon separated format of hex string
	
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b 

#create a AF_PACKET (packet level) type raw socket
#0x0003 = ETH_P_ALL (All Packets)
try:
	s= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error , msg:
	print "Socket cannot be created" + str(msg[0])
	sys.exit()
count=0

#Receive a packet


while True:
	count=count+1
	packet= s.recvfrom(8080)

#packet dtring from tuple
	packet=packet[0]

#parse ethernet packet
	eth_length=14

	eth_header=packet[0:eth_length]
	eth_packet=unpack("!6s6sH",eth_header)
	dest_mac=eth_addr(packet[0:6])
	source_mac=eth_addr(packet[6:12])
	eth_protocol=socket.ntohs(eth_packet[2])
	p_name=protocol_name[str(eth_protocol)]
	print  ' Destination MAC : ' + str(dest_mac) + ' Source MAC : ' + str(source_mac) + 'Protocol : ' + str(p_name)


#IP HEADER
#Parse IP Packets

#IP Header=first 20 bytes

	ip_header=packet[eth_length:20+eth_length]

#unpack the packets
	iph=unpack('!BBHHHBBH4s4s',ip_header)
	#version_iph=iph[0]
	#version = version_iph >> 4
	
	ttl=iph[5]

	protocol=iph[6]
	p_name=protocol_name[str(protocol)]
	source_ip=socket.inet_ntoa(iph[8])
	destination_ip=socket.inet_ntoa(iph[9])
	ip_length=20
	print  'SL_No :'+ str(count) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(p_name) + ' Source Address : ' + str(source_ip) + ' Destination Address : ' + str(destination_ip)


#TCP HEADER
#Parse TCP Packets

#TCP Header=first 20 bytes

	tcp_header=packet[ip_length:ip_length+20]
	tcph=unpack('!HHLLBBHHH',tcp_header)
	source_port=tcph[0]
	dest_port=tcph[1]
	sequence=tcph[2]
	acknowledgement=tcph[3]
	offset=tcph[4]
	tcp_length=offset>>4
	print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcp_length)
     	h_size = eth_length+ip_length + tcp_length * 4
	data_size = len(packet) - h_size
     
#Get data from the packet
	data = packet[h_size:]
     	print 'Data : ' + data
	print
	


#ICMP Packets
 	icmp_length=ip_length+eth_length
	icmp_header=packet[icmp_length:icmp_length+4]
	icmph=unpack("!BBH",icmp_header)
	
	icmp_type=icmph[0]
	code=icmp[1]
	checksum=icmp[2]
	print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
	
	h_size=eth+length+ip_length+icmp_length
	data_size-len(packet)-h_size
	
	data=packet[h_size:]
	
	print 'Data : '+ data

#UDP Packets
	udph_length=iph_length+eth_length
	udp_header=packet[udph_length:udph_length+8]
	udph=unpack("!HHH",udp_header)

	source_port=udph[0]
	dest_port=udph[1]
	length=udph[2]
	checksum=udph[3]
	
	print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            print 'Data : ' + data
