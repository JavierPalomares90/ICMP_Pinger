from socket import *
import os
import sys
import struct
import time
import select
import binascii
import argparse
import numpy as np

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

# TTL is found in the IP header starting at bit 64
TTL_START_BIT = 64

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
            return None

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

            # get the ttl
            ttlStart = TTL_START_BIT / BITS_IN_BYTE
            # ttl is 1 byte long
            ttlEnd = ttlStart + 1
            ttlPacket = recPacket[ttlStart:ttlEnd]

            signed_char_format = 'b'
            ttl = struct.unpack(signed_char_format,ttlPacket)[0]

            return packet_size,addr,sequence,ttl,rtt
        timeLeft -= howLongInSelect
        if timeLeft <= 0:
            # the request timed out
            return None


def sendOnePing(mySocket, destAddr, ID,sequence):

    # initialize a dummy checksum with 0
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # struct -- Interpret strings as packed binary data
    type = ICMP_ECHO_REQUEST
    code = 0
    packedId = ID

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

    # now we can form the packet with the real checksum
    header = struct.pack(HEADER_FORMAT, type, code, myChecksum, packedId, sequence)
    packet = header + packet
    # AF_INET address must be tuple, not str
    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout,sequence):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:
#    http://sock-raw.org/papers/sock_raw

    try:
        my_socket = socket(AF_INET,SOCK_RAW,icmp)
    except error, (errno,msg):
        if (errno == 1):
            print(msg)
            raise Exception("Socket error. Please execute as administrator/root.")
        else:
            raise error

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(my_socket,destAddr, myID,sequence)
    data = receiveOnePing(my_socket, myID, timeout, destAddr)

    my_socket.close()
    return data


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    try:
        dest = gethostbyname(host)
    except error,(errno,msg):
        raise error("Hostname {} unreachable.\n Error code {} with msg: {}".format(host,errno,msg))

    print("PING {}({}).".format(host,dest))
    # Send ping requests to a server separated by approximately one second
    txPackets = 0
    rxPackets = 0
    delays = []
    sequence = 1
    while 1 :
        try:
            txPackets += 1
            try:
                data = doOnePing(dest, timeout,sequence)
            except error, (errno, msg):
                print("Ping to {} failed.\n Error code {} with msg: {}".format(host,errno,msg))
            if not data:
                # returned None. Assume the ping timed out
                print("Request timeout for icmp_seq {}".format(sequence))
            else:
                rxPackets += 1
                num_bytes = data[0]
                addr = data[1]
                seq = data[2]
                ttl = data[3]
                rtt = data[4]
                delay = rtt * MILLIS_IN_SEC
                delays.append(delay)
                print("{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms".format(num_bytes,addr[0],seq,ttl,delay))
            sequence += 1
            time.sleep(1)# one second
        except (KeyboardInterrupt,EOFError):
            # User hit ctrl-c
            return txPackets,rxPackets,delays


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host_name", help="The server's hostname")
    parser.parse_args()
    args = parser.parse_args()
    hostName = args.host_name

    txPackets,rxPackets,delays = ping(hostName)
    packet_loss = 100.0 - (rxPackets / txPackets * 100.0)
    print('--- {} ping statistics ---'.format(hostName))
    print("{} packets transmitted, {} packets received, {}% packet loss".format(txPackets,rxPackets,packet_loss))
    if delays:
        max_delay = max(delays)
        min_delay = min(delays)
        avg_delay = sum(delays) / len(delays)
        std_dev_delay = np.std(delays)
        print("round-trip min/avg/max/stddev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms".format(min_delay,avg_delay,max_delay,std_dev_delay))


if __name__ =="__main__":
    main()
