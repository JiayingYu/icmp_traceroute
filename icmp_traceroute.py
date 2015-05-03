__author__ = 'Jiaying Yu'


from socket import *
import os
import sys
import struct
import time
import select
import binascii
ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

"""refer to ICMP pinger lab skeleton code"""
def checksum(str):
    csum = 0
    countTo = (len(str) / 2) * 2
    count = 0
    while count < countTo:

        thisVal = ord(str[count+1]) * 256 + ord(str[count])
        csum = csum + thisVal
        csum = csum & 0xffffffffL
        count = count + 2
    if countTo < len(str):
        csum = csum + ord(str[len(str) - 1])
        csum = csum & 0xffffffffL
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

""" modify the send_one_ping() methond in ICMP pinger lab"""
def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.
# Make the header in a similar way to the ping exercise.
# Append checksum to the header.
# So the function ending should look like this
#create header and append check sum, Header is type (8), code (8), checksum (16), id (16), seq (16)
#create header and append check sum, Header is type (8), code (8), checksum (16), id (16), seq (16)
    myChecksum = 0
    #create the identifier through pid
    myID = os.getpid() & 0xFFFF
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data

    return packet

def get_route(hostname):
    print "*********traceroute " + hostname + "***********"
    timeLeft = TIMEOUT
    for ttl in xrange(1,MAX_HOPS):
        for tries in xrange(TRIES):
            destAddr = gethostbyname(hostname)

            #Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    print " * * * Request timed out."
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print " * * * Request timed out."
            except timeout:
                continue
            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                icmp_header = recvPacket[20:28]
                type, code, checksum, ID, sequenceN = struct.unpack("bbHHh", icmp_header)
                #determine the host name
                host_ip = addr[0]
                try:
                    host = gethostbyaddr(host_ip)
                    printname = str(host_ip) + " (" + str(host[0]) + ")"
                except Exception:
                    printname = str(host_ip) + " (host name not resolved)"
                #Fill in end

                if type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" %(ttl, (timeReceived -t)*1000, printname)
                elif type == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" %(ttl, (timeReceived-t)*1000, printname)
                elif type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print " %d rtt=%.0f ms %s" %(ttl, (timeReceived - timeSent)*1000, printname)
                    return
                else:
                    print "error"
                break
            finally:
                mySocket.close()

get_route("google.com")
get_route("yahoo.com")
get_route("facebook.com")
get_route("github.com")
