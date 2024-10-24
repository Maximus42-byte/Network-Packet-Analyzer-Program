# # #Packet sniffer in python
# # #For Linux
# #
# # import socket
# #
# # #create an INET, raw socket
# # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# #
# # # receive a packet
# # while True:
# #   print s.recvfrom(65565)
#
# #Packet sniffer in python for Linux
# #Sniffs only incoming TCP packet
#
# import socket, sys
# from struct import *
#
# #create an INET, STREAMing socket
# try:
#     s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# except socket.error , msg:
#     print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
#     sys.exit()
#
# # receive a packet
# while True:
#     packet = s.recvfrom(65565)
#
#     #packet string from tuple
#     packet = packet[0]
#
#     #take first 20 characters for the ip header
#     ip_header = packet[0:20]
#
#     #now unpack them :)
#     iph = unpack('!BBHHHBBH4s4s' , ip_header)
#
#     #version_ihl = iph[0]
#     #version = version_ihl >> 4
#     #ihl = version_ihl & 0xF
#
#     #iph_length = ihl * 4
#
#     ttl = iph[5]
#     protocol = iph[6]
#     s_addr = socket.inet_ntoa(iph[8]);
#     d_addr = socket.inet_ntoa(iph[9]);
#
#     print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
#
#
#
#
#
#
#
#
#     tcp_header = packet[iph_length:iph_length+20]
#
#     #now unpack them :)
#     tcph = unpack('!HHLLBBHHH' , tcp_header)
#
#     source_port = tcph[0]
#     dest_port = tcph[1]
#     sequence = tcph[2]
#     acknowledgement = tcph[3]
#     doff_reserved = tcph[4]
#     tcph_length = doff_reserved >> 4
#
#     print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
#
#     h_size = iph_length + tcph_length * 4
#     data_size = len(packet) - h_size
#
#     #get data from the packet
#     data = packet[h_size:]
#
#     print 'Data : ' + data
#
# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)
# Silver Moon (m00n.silv3r@gmail.com)







import socket, sys
from struct import *

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print 'Ethernet: Src MAC : ' + eth_addr(packet[6:12]) + 'Dst MAC : ' + eth_addr(packet[0:6])  #+ ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    #checksum  va fragmentsegment nistand
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
        fragmentsegment = iph[4]
        ttl = iph[5]
        protocol = iph[6]
        checksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'Ip:  Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)+'Header checksum :'+str(checksum)+ ' Protocol : ' + str(protocol) +' TTL : ' + str(ttl) + '  fragmentsegment: ' + str(fragmentsegment)

        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            data_offset = doff_reserved << 6
            bitwiseand = int('0000111111',2)
            data_offset = data_offset & bitwiseand
            flagss = tcph[5]
            inp_A = int('000001',2)
            inp_B = int('000011',2)
            inp_C = int('000111',2)
            inp_D = int('001111',2)
            inp_E = int('011111',2)

            syn_flag = ((flagss <<4)&inp_B) >>1
            fin_flag = (flagss <<5) & inp_A
            ack_flag = ((flagss <<1) & inp_D )>>4
            urg_flag =flags >>5
            rst_flag =((flagss <<3) & inp_C )>>2
            checksum1 = tcph[7]
            windowsize = tcph[6]

            print 'Src Port : ' + str(source_port) + ' Dst Port : ' + str(dest_port) + ' Seq Number : ' + str(sequence) + ' Ack Number : ' + str(acknowledgement)+ ' window size: '+str(windowsize) +' checksum : '+str(checksum1)
            #print #flags
            print  ' syn_flag : ' + str(syn_flag) + ' fin_flag ' + str(fin_flag) + ' urg_flag: ' + str(urg_flag) + ' ack_flag : '+ ack_flag + ' rst_flag : ' + str(rst_flag)
            print ' data offset : '+ str(data_offset)
            #h_size = eth_length + iph_length + tcph_length * 4
            #data_size = len(packet) - h_size

            #get data from the packet
            #data = packet[h_size:]

            #print 'Data : ' + data

        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

            #h_size = eth_length + iph_length + icmph_length
            #data_size = len(packet) - h_size

            #get data from the packet

            #data = packet[h_size:]

            #print 'Data : ' + data

        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Src Port : ' + str(source_port) + ' Dst Port : ' + str(dest_port)  + ' Checksum : ' + str(checksum) + ' Length : ' + str(length)

            #h_size = eth_length + iph_length + udph_length
            #data_size = len(packet) - h_size

            #get data from the packet
            #data = packet[h_size:]

            #print 'Data : ' + data
