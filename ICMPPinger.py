from socket import *
import os
import sys
import struct
import time
import select
import binascii
import argparse

ICMP_ECHO_REQUEST = 8
PACKET_SIZE = 192
# format for signed char, signed char, unsigned short, unsigned short, short
HEADER_FORMAT = "bbHHh"


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
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(HEADER_FORMAT, icmpHeader)

           #Fill in start
        
            #Fetch the ICMP header from the IP packet
        
        #Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


# I found that my requests were timing out on Windows
def get_system_timer():
    if sys.platform == "win32":
        # On Windows, the best timer is time.clock()
        return time.clock
    else:
        # On most other platforms the best timer is time.time()
        return time.time

def sendOnePing(mySocket, destAddr, ID):

    # initialize a dummy checksum with 0
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # struct -- Interpret strings as packed binary data

    # format for signed char, signed char, unsigned short, unsigned short, short
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

    # In the packet, we're going to send the timer as a double, the remaining bytes
    # can be anything

    # return the bytesize of double
    double_byteSize = struct.calcsize("d")
    data_size = PACKET_SIZE - double_byteSize
    # get the data to pack in the remainder of the packet
    dummy_data = data_size * 'a'
    dummy_data = dummy_data.encode()

    timer = get_system_timer()
    # get the packe to send
    packet = struct.pack("d", timer()) + dummy_data

    # Calculate the checksum on the header and packet
    myChecksum = checksum(str(header + packet))

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:

        myChecksum = htons(myChecksum)

    # now we can form the packet with the real checksum
    header = struct.pack(HEADER_FORMAT, ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + packet
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
#    http://sock-raw.org/papers/sock_raw

    my_socket = socket(AF_INET,SOCK_RAW,icmp)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(my_socket,destAddr, myID)
    delay = receiveOnePing(my_socket, myID, timeout, destAddr)

    my_socket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    # Send ping requests to a server separated by approximately one second
    while 1 :
        delay = doOnePing(dest, timeout)
        print(delay)
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
