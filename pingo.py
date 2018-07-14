#!/usr/bin/env python
 
"""
    pingo.py - a pingtime measure tool for high frequency pinging

    pingo.py [src-addr] [dest-addr] [timeout-msec] [threshhold-msec] [pause-msec]

INTRODUCTION
    Pingo is a rewrite of a simple python based ping-tool.
    Pingos purpose is to record network health between two peers by
    by measuring ping-times in a continious stream of high frequency pings.
    Results are printed to console / STDOUT.

ARGUMENTS

    src-addr 
        Local host/ip-address to send the ping from

    dest-addr
        Destination host/ip-address to send the ping to

    timeout-msec (default: 2000)
        Timeout in milliseconds for waiting for ping-answer. 
        Timed out ping-requests are accounted with this time in the output

    threshhold-msec (default: 200)
        Pings using more than this threshhold (in milliseconds) of time are registered / printed
        Use lower value if the network being tested is more local i.e. "20" for LAN

    pause-msec (default: 100)
        Pause (in milliseconds) between separate ping attempts.


LICENSE
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.


ORIGINAL CREDITS

    A pure python ping implementation using raw socket.
  
    Note that ICMP messages can only be sent from processes running as root.
 
    Derived from ping.c distributed in Linux's netkit. That code is
    copyright (c) 1989 by The Regents of the University of California.
    That code is in turn derived from code written by Mike Muuss of the
    US Army Ballistic Research Laboratory in December, 1983 and
    placed in the public domain. They have my thanks.
 
    Bugs are naturally mine. I'd be glad to hear about them. There are
    certainly word - size dependenceies here.
 
    Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
    Distributable under the terms of the GNU General Public License
    version 2. Provided with no warranties of any sort.
 
    Original Version from Matthew Dixon Cowles:
      -> ftp://ftp.visi.com/users/mdc/ping.py
 
    Rewrite by Jens Diemer:
      -> http://www.python-forum.de/post-69122.html#69122
 
    Rewrite by George Notaras:
      -> http://www.g-loaded.eu/2009/10/30/python-ping/
 
    Revision history
    ~~~~~~~~~~~~~~~~
 
    November 8, 2009
    ----------------
    Improved compatibility with GNU/Linux systems.
 
    Fixes by:
     * George Notaras -- http://www.g-loaded.eu
    Reported by:
     * Chris Hallman -- http://cdhallman.blogspot.com
 
    Changes in this release:
     - Re-use time.time() instead of time.clock(). The 2007 implementation
       worked only under Microsoft Windows. Failed on GNU/Linux.
       time.clock() behaves differently under the two OSes[1].
 
    [1] http://docs.python.org/library/time.html#time.clock
 
    May 30, 2007
    ------------
    little rewrite by Jens Diemer:
     -  change socket asterisk import to a normal import
     -  replace time.time() with time.clock()
     -  delete "return None" (or change to "return" only)
     -  in checksum() rename "str" to "source_string"
 
    November 22, 1997
    -----------------
    Initial hack. Doesn't do much, but rather than try to guess
    what features I (or others) will want in the future, I've only
    put in what I need now.
 
    December 16, 1997
    -----------------
    For some reason, the checksum bytes are in the wrong order when
    this is run under Solaris 2.X for SPARC but it works right under
    Linux x86. Since I don't know just what's wrong, I'll swap the
    bytes always and then do an htons().
 
    December 4, 2000
    ----------------
    Changed the struct.pack() calls to pack the checksum and ID as
    unsigned. My thanks to Jerome Poincheval for the fix.
 
 
    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: $
    $Rev: $
    $Author: $
"""
 
 
import os, sys, socket, struct, select, time, locale

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.
 
 
def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        #val1=ord(source_string[count + 1])
        #val2=ord(source_string[count])
        #thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        thisVal = source_string[count + 1]*256+source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
 
    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
 
    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
 
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
 
    return answer
 
 
def receive_one_ping(my_socket, ID, timeout):
    """
    receive the ping from the socket.
    """
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return
 
        timeReceived = time.time()
        recPacket, addr = my_socket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        if packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent
 
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return
 
 
def send_one_ping(my_socket, dest_addr, ID):
    """
    Send one ping to the given >dest_addr<.
    """
    dest_addr  =  socket.gethostbyname(dest_addr)
 
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0
 
    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", time.time()) + data.encode('ascii')
 
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)
 
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1
 
 
def do_one(src_addr, dest_addr, timeout):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

        # bind socket to source address
        if src_addr != "-" :
            src_addr = socket.gethostbyname(src_addr)
            my_socket.bind((src_addr,1))
            
    except socket.error (errno, msg):
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error
 
    my_ID = os.getpid() & 0xFFFF
 
    send_one_ping(my_socket, dest_addr, my_ID)
    delay = receive_one_ping(my_socket, my_ID, timeout)
 
    my_socket.close()
    return delay
 
 
def verbose_ping(dest_addr, timeout = 2, count = 4):
    """
    Send >count< ping to >dest_addr< with the given >timeout< and display
    the result.
    """
    for i in range(count):
        print("ping %s..." % (dest_addr))
        try:
            delay  =  do_one(dest_addr, timeout)
        except socket.gaierror as e:
            print("failed. (socket error: '%s')" % (e[1]))
            break
 
        if delay  ==  None:
            print("failed. (timeout within %ssec.)" % (timeout))
        else:
            delay  =  delay * 1000
            print("get ping in %0.4fms" % (delay))
    print

def print_pingmeasure_result(timestr,timestamp,src_addr,dest_addr,timeout_msec,count,threshhold_msec,delay):
    local_timestamp = locale.format("%0.4f", timestamp)
    if delay  ==  None:
        print("%s;%s;%s;%s;%s;lost;%s" % (timestr,local_timestamp,src_addr,dest_addr,count,timeout_msec))
    else:
        delay  =  delay * 1000
        if delay >= threshhold_msec :
            local_delay = locale.format("%0.4f", delay)
            local_threshhold_msec = locale.format("%0.4f", threshhold_msec)
            print("%s;%s;%s;%s;%s;%s;%s" % (timestr,local_timestamp,src_addr,dest_addr,count,local_threshhold_msec,local_delay))
            

def ping_stream(src_addr, dest_addr, timeout_msec = 2000, threshhold_msec = 200, pause_msec = 100):
    """
    Send continous ping to >dest_addr< with the given p>pause< between pings and display
    the result if delay surpasses threshhold.
    """
    count = 0
    while True:
        count=count+1
        now=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())
        ts = time.time()
        
        try:
            delay  =  do_one(src_addr, dest_addr, timeout_msec/1000)
        except socket.gaierror as e:
            print("failed. (socket error: '%s')" % (e[1]))
            break
 
        print_pingmeasure_result(now,ts,src_addr, dest_addr,timeout_msec,count,threshhold_msec,delay)
        time.sleep(pause_msec/1000)
 
if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, '')  
    src_addr        = sys.argv[1]
    dest_addr       = sys.argv[2]
    timeout         = int(sys.argv[3])
    threshhold_msec = locale.atof(sys.argv[4])
    pause_msec      = int(sys.argv[5])
      
    ping_stream(src_addr,dest_addr,timeout,threshhold_msec,pause_msec)
    
