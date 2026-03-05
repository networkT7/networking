```markdown
# Network Security Emulator

A software emulation of a simplified IP-over-Ethernet network with security
attacks and defenses, built in Python using raw sockets.

---

## Network Topology

<img width="401" height="160" alt="Screenshot 2026-03-05 at 18 34 41" src="https://github.com/user-attachments/assets/2c9c2295-6435-4feb-812d-84d8ef0aad12" />


| Node | IP   | MAC | Wire |
|------|------|-----|------|
| N1   | 0x12 | N1  | W1   |
| N2   | 0x13 | N2  | W1   |
| N3   | 0x22 | N3  | W2   |
| N4   | 0x32 | N4  | W3   |
| R1   | 0x11 | R1  | W1   |
| R2   | 0x21 | R2  | W2   |
| R3   | 0x31 | R3  | W3   |

---

## Frame Formats

**Ethernet frame:**
| Src MAC (2B) | Dst MAC (2B) | DataLen (1B) | Data (≤256B) |

**IP packet (inside Ethernet data):**
| Src IP (1B) | Dst IP (1B) | Protocol (1B) | DataLen (1B) | Data (≤252B) |

**IP Protocols:**
| Value | Name |
|-------|------|
| 0     | DATA |
| 1     | PING |
| 2     | ARP  |

---

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Network

Open a terminal per component. Start wires first, then router, then nodes.

```bash
# Wires
./run_wire.sh W1
./run_wire.sh W2
./run_wire.sh W3

# Router
./run_router.sh

# Nodes
./run_node.sh N1
./run_node.sh N2
./run_node.sh N3
./run_node.sh N4
```

---

## Node CLI Commands

```
MAC {dst} {msg}                    Send raw Ethernet frame
IP {dst_hex} PING                  Send ICMP-like ping
SPOOF {src_hex} {dst_hex} {msg}    IP Spoofing attack
SNIFF on|off                       Toggle sniffing mode
FIREWALL ADD BLOCK {src_hex}       Add block rule (N3 only)
FIREWALL ADD ACCEPT {src_hex}      Add accept rule (N3 only)
FIREWALL REMOVE {src_hex}          Remove rule (N3 only)
FIREWALL LIST                      Show active rules (N3 only)
```

---

## Implemented Features

### Core Network (7%) 
- **Ethernet emulation (2%)** — Wire broadcasts all frames to all nodes on the
  same LAN; nodes drop frames not addressed to them
- **IP emulation (3%)** — IP packets encapsulated in Ethernet frames with
  src/dst IP, protocol, and data fields
- **Packet forwarding (2%)** — Router maintains a fixed routing table and
  forwards packets across LANs via the correct interface
- **Ping protocol (1%)** — ARP resolution + PING req/res round trip across LANs

### IP Spoofing (2%) 
N1 accepts user input to forge the source IP of any outgoing packet,
impersonating another node. The receiving node has no way to distinguish
a spoofed packet from a legitimate one at the IP layer.

```
SPOOF 0x13 0x22 hello from node2
# N3 receives this believing it came from N2 (0x13)
```

### Sniffing Attack (1%) 
N1 enters promiscuous mode and captures all frames on LAN1, including those
addressed to N2 or the router. Logs the full IP header and payload of
intercepted frames.

```
SNIFF on    # N1 now logs all of N2's traffic
SNIFF off   # disable sniffing
```

### Firewall (2%) 
N3 has a configurable packet filter. Users can add/remove rules at runtime
to block or accept packets based on source IP. Default policy is ACCEPT.

```
FIREWALL ADD BLOCK 0x13    # block all packets from N2
FIREWALL REMOVE 0x13       # remove the rule
FIREWALL LIST              # show current ruleset
```

---

## Open Category Features (8%) 

### MITM Attack 
N1 intercepts packets between N2 and N3, modifies the payload in-flight,
and re-forwards the tampered frame. Demonstrates active packet tampering
on a shared broadcast LAN.
- N1 uses sniffing to capture N2→N3 traffic
- Modifies the payload before re-injecting onto the wire

### DDoS Attack 
N1 floods the router or a target node with a high volume of packets to
simulate a denial-of-service scenario, causing legitimate traffic to be
dropped or delayed.
- Rapid packet generation loop from N1
- Optional: spawn additional attacker nodes on a new LAN

### Intrusion Detection System
Passive monitor that watches traffic across the network and flags anomalies
in real time.
- Detects abnormal packet rates from a single source (DDoS indicator)
- Detects packets with inconsistent MAC/IP source pairs (spoofing/MITM indicator)
- Logs timestamped alerts with offending node info

### Dynamic Firewall / Rate Limiting 
Router-level defense that reacts to IDS alerts automatically.
- Blocks or throttles flagged source IPs at the router
- Rate limiting: drops packets exceeding N packets/second from a source
- Integrates with IDS output to trigger rules dynamically

### Encryption & Authentication
Adds a cryptographic layer to the IP packet structure.
- Symmetric encryption of packet payload
- Message authentication code (MAC tag) to detect in-flight tampering
- Nodes share keys at startup; router can optionally verify tags
- Demonstrates that encrypted traffic resists MITM modification

---

## File Structure

```
src/
├── main.py                    # Entry point — wire / node / router modes
└── networking/
    ├── frames.py              # MACFrame and IPFrame serde
    ├── types.py               # IPProtocol, NodeConfig, address types
    ├── constants.py           # BROADCAST_MAC, encoding
    ├── config.py              # Loads config.yaml
    ├── log_format.py          # Logger setup
    ├── components/
    │   ├── node.py            # Node logic, CLI, attacks
    │   ├── router.py          # Packet forwarding, ARP
    │   └── wire.py            # Broadcast Ethernet emulation
    └── collections/
        └── ts_dict.py         # Thread-safe dictionary
```
```
