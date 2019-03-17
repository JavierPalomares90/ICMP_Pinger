from socket import *
import os
import sys
import struct
import time
import select
import binascii
import argparse

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
# Header size is 192 bits
HEADER_SIZE_BITS = 192
# Header format for signed char, signed char, unsigned short, unsigned short, short
HEADER_FORMAT = "bbHHh"
# The ICMP header starts after bit 160
HEADER_START_BIT = 160
# Header ends at bit 192
HEADER_SIZE_BITS = 64

BITS_IN_BYTE = 8
BUF_SIZE = 1024

MILLIS_IN_SEC = 1000

# define the timer to use as used in the timeit module
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


def checksum(string): 
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout

    while 1:
        startedSelect = default_timer()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (default_timer() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = default_timer()
        recPacket, addr = mySocket.recvfrom(BUF_SIZE)

        #Fetch the ICMP header from the IP packet
        headerStart = HEADER_START_BIT / BITS_IN_BYTE
        headerEnd = (HEADER_START_BIT + HEADER_SIZE_BITS)/ BITS_IN_BYTE

        icmpHeader = recPacket[headerStart:headerEnd]
        type, code, checksum, packetId, sequence = struct.unpack(HEADER_FORMAT, icmpHeader)
        if type == ICMP_ECHO_REPLY and packetId == ID:
            packet_size = len(recPacket)
            
            # get the time when the ping was sent
            double_format = "d"
            double_byte_size = struct.calcsize(double_format)
            start = headerEnd
            end = start + double_byte_size

            timer_data = recPacket[start:end]
            timeSent = struct.unpack(double_format,timer_data)[0]
            # round trip time
            rtt = timeReceived - timeSent
            return rtt
        timeLeft -= howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):

    # initialize a dummy checksum with 0
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # struct -- Interpret strings as packed binary data
    type = ICMP_ECHO_REQUEST
    code = 0
    packedId = ID
    sequence = 1

    # format for signed char, signed char, unsigned short, unsigned short, short
    header = struct.pack(HEADER_FORMAT, type, code, myChecksum, packedId, sequence)

    # In the packet, we're going to send the timer as a double
    double_format = "d"
    # get the packet to send
    packet = struct.pack(double_format, default_timer())

    # Calculate the checksum on the header and packet
    myChecksum = checksum(str(header + packet))

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:

        myChecksum = htons(myChecksum)

    type = ICMP_ECHO_REQUEST
    code = 0
    packedId = ID
    sequence = 1

    # now we can form the packet with the real checksum
    header = struct.pack(HEADER_FORMAT, type, code, myChecksum, packedId, sequence)
    packet = header + packet
    # AF_INET address must be tuple, not str
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
#    http://sock-raw.org/papers/sock_raw

    try:
        my_socket = socket(AF_INET,SOCK_RAW,icmp)
    except error, (errno,msg):
        if (errno == 1):
            print(msg)
            raise Exception("Socket error. Please execute as administrator/root.")

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(my_socket,destAddr, myID)
    delay = receiveOnePing(my_socket, myID, timeout, destAddr)

    my_socket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    #TODO: Where does 56(84) come from?
    print("PING {}({}) 56(84) bytes of data.".format(host,dest))
    # Send ping requests to a server separated by approximately one second
    while 1 :
        delay = doOnePing(dest, timeout)
        print("ping delay: {} millisecs".format(delay * MILLIS_IN_SEC))
        time.sleep(1)# one second
    return delay


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host_name", help="The server's hostname")
    parser.parse_args()
    args = parser.parse_args()
    hostName = args.host_name

    ping(hostName)


if __name__ =="__main__":
    main()
