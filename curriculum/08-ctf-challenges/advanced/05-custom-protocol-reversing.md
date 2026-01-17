# Challenge 05 - Custom Protocol Reversing

**Category:** Reverse Engineering / Forensics
**Difficulty:** Advanced
**Points:** 450
**Target:** Custom Network Protocol

## Challenge Description

You've intercepted network traffic from a proprietary industrial control system. The protocol is custom and undocumented, but you know it's being used to transmit sensitive commands and data.

Your mission is to reverse engineer the custom protocol, understand its structure, and extract the flag that was transmitted in an encrypted/encoded message.

## Objectives

- Analyze unknown binary network protocols
- Identify protocol structure (headers, fields, checksums)
- Reverse engineer encoding/encryption schemes
- Write a protocol decoder
- Extract hidden data from protocol messages

## Target Information

- **Capture File:** custom_protocol.pcap
- **Port:** TCP/5555
- **Protocol:** Custom binary protocol (undocumented)
- **Encryption:** XOR-based with session key negotiation

## Getting Started

1. Create the custom protocol server and capture:

```python
#!/usr/bin/env python3
"""Custom Protocol Server - For CTF Challenge"""

import socket
import struct
import random
import threading

# Protocol Structure:
# [MAGIC:4][VERSION:1][TYPE:1][LENGTH:2][SESSION:4][PAYLOAD:N][CHECKSUM:2]
#
# MAGIC: 0xDEADBEEF (4 bytes)
# VERSION: Protocol version (1 byte)
# TYPE: Message type (1 byte)
#   0x01 = HELLO (client init)
#   0x02 = HELLO_ACK (server response with session key)
#   0x03 = DATA (encrypted data)
#   0x04 = DATA_ACK
#   0x05 = FLAG_REQUEST
#   0x06 = FLAG_RESPONSE
# LENGTH: Payload length (2 bytes, big-endian)
# SESSION: Session ID (4 bytes)
# PAYLOAD: Variable length data (XOR encrypted after handshake)
# CHECKSUM: CRC16 of header + payload

MAGIC = 0xDEADBEEF
VERSION = 0x01
FLAG = b"FLAG{pr0t0c0l_r3v3rs1ng_m4st3r}"

def crc16(data):
    """Calculate CRC16-CCITT"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def xor_encrypt(data, key):
    """XOR encrypt/decrypt with 4-byte key"""
    key_bytes = struct.pack('>I', key)
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % 4])
    return bytes(result)

def build_packet(msg_type, session_id, payload):
    """Build protocol packet"""
    header = struct.pack('>IBBHI',
        MAGIC,
        VERSION,
        msg_type,
        len(payload),
        session_id
    )
    checksum = crc16(header + payload)
    return header + payload + struct.pack('>H', checksum)

def parse_packet(data):
    """Parse protocol packet"""
    if len(data) < 14:  # Minimum packet size
        return None

    magic, version, msg_type, length, session_id = struct.unpack('>IBBHI', data[:12])

    if magic != MAGIC:
        return None
    if version != VERSION:
        return None

    payload = data[12:12+length]
    checksum = struct.unpack('>H', data[12+length:14+length])[0]

    # Verify checksum
    expected_checksum = crc16(data[:12] + payload)
    if checksum != expected_checksum:
        print(f"Checksum mismatch: {checksum:04x} != {expected_checksum:04x}")
        return None

    return {
        'type': msg_type,
        'session': session_id,
        'payload': payload
    }

def handle_client(conn, addr):
    """Handle client connection"""
    print(f"[*] Connection from {addr}")
    session_key = random.randint(0x10000000, 0xFFFFFFFF)
    session_id = random.randint(0x10000000, 0xFFFFFFFF)
    authenticated = False

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            packet = parse_packet(data)
            if not packet:
                print("[!] Invalid packet")
                continue

            msg_type = packet['type']
            payload = packet['payload']

            if msg_type == 0x01:  # HELLO
                print(f"[*] Received HELLO from {addr}")
                # Send HELLO_ACK with session key (XOR'd with magic constant)
                key_payload = struct.pack('>I', session_key ^ 0xCAFEBABE)
                response = build_packet(0x02, session_id, key_payload)
                conn.send(response)
                authenticated = True
                print(f"[*] Sent session key: {session_key:08x}")

            elif msg_type == 0x03:  # DATA
                if not authenticated:
                    continue
                # Decrypt payload
                decrypted = xor_encrypt(payload, session_key)
                print(f"[*] Received DATA: {decrypted}")
                # Send ACK
                response = build_packet(0x04, session_id, b"OK")
                conn.send(response)

            elif msg_type == 0x05:  # FLAG_REQUEST
                if not authenticated:
                    continue
                # Send encrypted flag
                encrypted_flag = xor_encrypt(FLAG, session_key)
                response = build_packet(0x06, session_id, encrypted_flag)
                conn.send(response)
                print(f"[*] Sent encrypted flag")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        print(f"[*] Connection closed from {addr}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("[*] Custom Protocol Server listening on port 5555")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == '__main__':
    main()
```

2. Generate sample capture with client:

```python
#!/usr/bin/env python3
"""Custom Protocol Client - Generate Traffic"""

import socket
import struct

MAGIC = 0xDEADBEEF
VERSION = 0x01

def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def xor_encrypt(data, key):
    key_bytes = struct.pack('>I', key)
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % 4])
    return bytes(result)

def build_packet(msg_type, session_id, payload):
    header = struct.pack('>IBBHI', MAGIC, VERSION, msg_type, len(payload), session_id)
    checksum = crc16(header + payload)
    return header + payload + struct.pack('>H', checksum)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5555))

    # Send HELLO
    hello = build_packet(0x01, 0, b"INIT")
    sock.send(hello)

    # Receive HELLO_ACK
    response = sock.recv(1024)
    session_id = struct.unpack('>I', response[8:12])[0]
    key_payload = response[12:16]
    session_key = struct.unpack('>I', key_payload)[0] ^ 0xCAFEBABE
    print(f"Session: {session_id:08x}, Key: {session_key:08x}")

    # Send DATA
    data = xor_encrypt(b"Hello Server!", session_key)
    data_pkt = build_packet(0x03, session_id, data)
    sock.send(data_pkt)
    sock.recv(1024)

    # Request FLAG
    flag_req = build_packet(0x05, session_id, b"")
    sock.send(flag_req)

    flag_resp = sock.recv(1024)
    encrypted_flag = flag_resp[12:-2]
    flag = xor_encrypt(encrypted_flag, session_key)
    print(f"Flag: {flag.decode()}")

    sock.close()

if __name__ == '__main__':
    main()
```

3. Capture traffic with tcpdump/Wireshark while running client

---

## Hints

<details>
<summary>Hint 1 (Cost: -45 points)</summary>

Start by examining the packet structure in Wireshark:
- Look for repeating patterns at packet starts (magic bytes)
- Identify fixed-length headers vs variable-length payloads
- Note the port numbers and packet sizes

The protocol likely has:
- Magic bytes for identification
- Type field for different message types
- Length field for payload size
- Some form of checksum for integrity

</details>

<details>
<summary>Hint 2 (Cost: -60 points)</summary>

The protocol structure is:
```
[4 bytes: Magic 0xDEADBEEF]
[1 byte:  Version]
[1 byte:  Message Type]
[2 bytes: Payload Length (big-endian)]
[4 bytes: Session ID]
[N bytes: Payload]
[2 bytes: CRC16 Checksum]
```

Message types:
- 0x01: Client Hello
- 0x02: Server Hello ACK (contains XOR'd session key)
- 0x05: Flag Request
- 0x06: Flag Response (encrypted flag)

The session key is XOR'd with 0xCAFEBABE in the HELLO_ACK.

</details>

<details>
<summary>Hint 3 (Cost: -90 points)</summary>

To decode the flag:

1. Find the HELLO_ACK packet (type 0x02)
2. Extract the 4-byte payload: `encrypted_key`
3. Recover session key: `session_key = encrypted_key XOR 0xCAFEBABE`
4. Find the FLAG_RESPONSE packet (type 0x06)
5. Extract the encrypted flag payload
6. Decrypt: `flag = XOR(encrypted_flag, session_key)` (4-byte rolling key)

Python decoder:
```python
import struct
session_key = encrypted_key ^ 0xCAFEBABE
key_bytes = struct.pack('>I', session_key)
flag = bytes(b ^ key_bytes[i % 4] for i, b in enumerate(encrypted_flag))
```

</details>

---

## Solution Walkthrough

<details>
<summary>Click to reveal full solution</summary>

### Step 1: Initial PCAP Analysis

```bash
# Basic stats
tshark -r custom_protocol.pcap -q -z io,stat,0

# View raw packets
tshark -r custom_protocol.pcap -x
```

In Wireshark, observe:
- TCP port 5555
- Binary data with repeating header pattern
- First 4 bytes often: `de ad be ef` (magic)

### Step 2: Identify Protocol Structure

Export TCP stream and analyze bytes:

```python
#!/usr/bin/env python3
"""Analyze PCAP to identify protocol structure"""

from scapy.all import *
import struct

packets = rdpcap('custom_protocol.pcap')

for pkt in packets:
    if TCP in pkt and pkt[TCP].payload:
        data = bytes(pkt[TCP].payload)
        if len(data) < 12:
            continue

        # Check for magic bytes
        if data[:4] == b'\xde\xad\xbe\xef':
            print(f"Found magic! Packet size: {len(data)}")
            print(f"  Raw: {data.hex()}")

            # Parse header
            magic, version, msg_type, length, session = struct.unpack('>IBBHI', data[:12])
            print(f"  Magic: {magic:08x}")
            print(f"  Version: {version}")
            print(f"  Type: {msg_type:02x}")
            print(f"  Length: {length}")
            print(f"  Session: {session:08x}")

            if length > 0:
                payload = data[12:12+length]
                print(f"  Payload: {payload.hex()}")

            checksum = struct.unpack('>H', data[12+length:14+length])[0]
            print(f"  Checksum: {checksum:04x}")
            print()
```

### Step 3: Understand Handshake

From packet analysis:
1. Client sends HELLO (type 0x01)
2. Server responds with HELLO_ACK (type 0x02) containing session key
3. Subsequent messages are encrypted with session key

### Step 4: Extract Session Key

```python
#!/usr/bin/env python3
"""Extract session key from HELLO_ACK"""

from scapy.all import *
import struct

def find_session_key(pcap_file):
    packets = rdpcap(pcap_file)

    for pkt in packets:
        if TCP in pkt and pkt[TCP].payload:
            data = bytes(pkt[TCP].payload)
            if len(data) < 16:
                continue

            if data[:4] != b'\xde\xad\xbe\xef':
                continue

            magic, version, msg_type, length, session = struct.unpack('>IBBHI', data[:12])

            # Look for HELLO_ACK (type 0x02)
            if msg_type == 0x02:
                payload = data[12:12+length]
                if len(payload) >= 4:
                    encrypted_key = struct.unpack('>I', payload[:4])[0]
                    session_key = encrypted_key ^ 0xCAFEBABE
                    print(f"[+] Found HELLO_ACK")
                    print(f"    Session ID: {session:08x}")
                    print(f"    Encrypted Key: {encrypted_key:08x}")
                    print(f"    Session Key: {session_key:08x}")
                    return session_key, session

    return None, None

session_key, session_id = find_session_key('custom_protocol.pcap')
```

### Step 5: Decrypt Flag Response

```python
#!/usr/bin/env python3
"""Full Protocol Decoder - Extract Flag"""

from scapy.all import *
import struct

MAGIC = 0xDEADBEEF

def xor_decrypt(data, key):
    """XOR decrypt with 4-byte key"""
    key_bytes = struct.pack('>I', key)
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % 4])
    return bytes(result)

def decode_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    session_key = None
    decrypted_messages = []

    for pkt in packets:
        if TCP in pkt and pkt[TCP].payload:
            data = bytes(pkt[TCP].payload)
            if len(data) < 14:
                continue

            # Check magic
            if struct.unpack('>I', data[:4])[0] != MAGIC:
                continue

            # Parse header
            _, version, msg_type, length, session_id = struct.unpack('>IBBHI', data[:12])
            payload = data[12:12+length]

            msg_type_names = {
                0x01: 'HELLO',
                0x02: 'HELLO_ACK',
                0x03: 'DATA',
                0x04: 'DATA_ACK',
                0x05: 'FLAG_REQUEST',
                0x06: 'FLAG_RESPONSE'
            }

            print(f"\n[Packet] Type: {msg_type_names.get(msg_type, f'UNKNOWN({msg_type:02x})')}")
            print(f"  Session: {session_id:08x}")
            print(f"  Payload ({length} bytes): {payload.hex()}")

            if msg_type == 0x02:  # HELLO_ACK
                encrypted_key = struct.unpack('>I', payload[:4])[0]
                session_key = encrypted_key ^ 0xCAFEBABE
                print(f"  [*] Session Key Extracted: {session_key:08x}")

            elif msg_type == 0x03:  # DATA
                if session_key:
                    decrypted = xor_decrypt(payload, session_key)
                    print(f"  [*] Decrypted Data: {decrypted}")

            elif msg_type == 0x06:  # FLAG_RESPONSE
                if session_key:
                    decrypted = xor_decrypt(payload, session_key)
                    print(f"  [*] Decrypted Flag: {decrypted.decode()}")
                    return decrypted.decode()

    return None

flag = decode_pcap('custom_protocol.pcap')
if flag:
    print(f"\n[+] FLAG: {flag}")
```

### Step 6: Build Protocol Client (for verification)

```python
#!/usr/bin/env python3
"""Custom Protocol Client - Retrieve Flag"""

import socket
import struct

MAGIC = 0xDEADBEEF
VERSION = 0x01

def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def xor_crypt(data, key):
    key_bytes = struct.pack('>I', key)
    return bytes(b ^ key_bytes[i % 4] for i, b in enumerate(data))

def build_packet(msg_type, session_id, payload):
    header = struct.pack('>IBBHI', MAGIC, VERSION, msg_type, len(payload), session_id)
    checksum = crc16(header + payload)
    return header + payload + struct.pack('>H', checksum)

def parse_packet(data):
    if len(data) < 14:
        return None
    magic, version, msg_type, length, session_id = struct.unpack('>IBBHI', data[:12])
    payload = data[12:12+length]
    return {'type': msg_type, 'session': session_id, 'payload': payload}

def get_flag(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Step 1: Send HELLO
    print("[*] Sending HELLO...")
    hello = build_packet(0x01, 0, b"INIT")
    sock.send(hello)

    # Step 2: Receive HELLO_ACK
    response = sock.recv(1024)
    pkt = parse_packet(response)
    session_id = pkt['session']
    encrypted_key = struct.unpack('>I', pkt['payload'][:4])[0]
    session_key = encrypted_key ^ 0xCAFEBABE
    print(f"[*] Session Key: {session_key:08x}")

    # Step 3: Request Flag
    print("[*] Requesting flag...")
    flag_req = build_packet(0x05, session_id, b"")
    sock.send(flag_req)

    # Step 4: Receive and decrypt flag
    response = sock.recv(1024)
    pkt = parse_packet(response)
    encrypted_flag = pkt['payload']
    flag = xor_crypt(encrypted_flag, session_key)
    print(f"[+] FLAG: {flag.decode()}")

    sock.close()
    return flag.decode()

if __name__ == '__main__':
    get_flag('localhost', 5555)
```

### Protocol Summary

```
+-------------+--------+---------+--------+-----------+---------+----------+
| Magic (4B)  |Version | Type    | Length | Session   | Payload | Checksum |
| 0xDEADBEEF  | (1B)   | (1B)    | (2B)   | (4B)      | (var)   | (2B)     |
+-------------+--------+---------+--------+-----------+---------+----------+

Types:
  0x01 = HELLO         (client -> server)
  0x02 = HELLO_ACK     (server -> client, payload = XOR'd key)
  0x03 = DATA          (encrypted with session key)
  0x04 = DATA_ACK
  0x05 = FLAG_REQUEST
  0x06 = FLAG_RESPONSE (encrypted flag)

Key Exchange:
  session_key = payload_from_HELLO_ACK XOR 0xCAFEBABE

Encryption:
  Rolling XOR with 4-byte session key
```

### Reverse Engineering Tips

1. **Look for magic bytes**: Consistent patterns at packet start
2. **Identify length fields**: Usually follow type/command fields
3. **Find checksums**: Often at packet end, CRC16/32 common
4. **Analyze handshake**: Key exchange usually early in session
5. **XOR patterns**: Check for repeating 4/8 byte patterns in "encrypted" data

</details>

---

## Flag

```
FLAG{pr0t0c0l_r3v3rs1ng_m4st3r}
```

**Flag Format:** `FLAG{...}`

## Skills Practiced

- Binary protocol analysis
- Network packet forensics
- Reverse engineering unknown formats
- Cryptographic primitive identification
- Protocol implementation

## Tools Used

- Wireshark/tshark
- Python (scapy, struct)
- Hex editors
- Protocol dissector development

## Related Challenges

- [05 - PCAP Analysis (Intermediate)](../intermediate/05-pcap-analysis.md) - Network forensics
- [06 - Binary Analysis (Intermediate)](../intermediate/06-binary-analysis.md) - Reverse engineering

## References

- [Wireshark Protocol Dissector Development](https://wiki.wireshark.org/Lua/Dissectors)
- [Binary Protocol Reverse Engineering](https://resources.infosecinstitute.com/topic/reverse-engineering-networking-protocols/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Protocol Reverse Engineering Guide](https://sockpuppet.org/blog/2014/08/04/protocol-reversing/)
