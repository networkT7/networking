# 🛡️ Network Security Emulator

**A Python-based software emulation of a simplified IP-over-Ethernet network.**

This project implements a custom networking stack using **raw sockets** to demonstrate security vulnerabilities and defensive mechanisms at the Link and Network layers.

-----

## 🌐 Network Topology

The network is partitioned into distinct wires (segments) connected via routers. The following table maps the logical addressing for all active nodes.
To view the network structure, including wire segments and node connections, please refer to the diagram below:


[Network Topology Diagram](https://github.com/user-attachments/assets/2c9c2295-6435-4feb-812d-84d8ef0aad12)

| Node | IP Address | MAC Address | Wire Segment |
| :--- | :--- | :--- | :--- |
| **N1** | `0x12` | `N1` | W1 |
| **N2** | `0x13` | `N2` | W1 |
| **N3** | `0x22` | `N3` | W2 |
| **N4** | `0x32` | `N4` | W3 |
| **R1** | `0x11` | `R1` | W1 |
| **R2** | `0x21` | `R2` | W2 |
| **R3** | `0x31` | `R3` | W3 |

-----

## 🛠️ Technical Specifications

### Frame Formats

The emulation uses a custom-tailored encapsulation model.

#### 1\. Ethernet Frame (Layer 2)

| Field | Size | Description |
| :--- | :--- | :--- |
| **Src MAC** | 2B | Source Hardware Address |
| **Dst MAC** | 2B | Destination Hardware Address |
| **DataLen** | 1B | Length of the payload |
| **Data** | ≤256B | Encapsulated IP Packet |

#### 2\. IP Packet (Layer 3)

*Encapsulated within the Ethernet Data field.*

| Field | Size | Description |
| :--- | :--- | :--- |
| **Src IP** | 1B | Source Logical Address |
| **Dst IP** | 1B | Destination Logical Address |
| **Protocol** | 1B | See Protocol Table below |
| **DataLen** | 1B | Length of the payload |
| **Data** | ≤252B | Application Data |

#### 3\. TCP Implementation (Layer 4)
This emulator utilises a **Simplified State-Machine TCP**. Rather than complex headers, the IP payload carries a single-byte state to manage the connection lifecycle.

| State | Description |
| :--- | :--- |
| **SYN** | Connection request |
| **SYNACK** | Connection accepted |
| **KEEPALIVE** | Heartbeat used to maintain an active connection |
| **FIN** | Graceful connection termination |
| **RST** | Connection refused (e.g., connection table is full) |



---

### 📋 Supported Protocols
The `Protocol` field in the IP header determines how the payload is handled by the receiving node.

| Value | Identifier | Description |
| :---: | :--- | :--- |
| `0` | **DATA** | Standard data transmission |
| `1` | **PING** | ICMP-like connectivity check |
| `2` | **ARP** | Address Resolution Protocol |
| `3` | **TCP** | State-based transport protocol |


## 🚀 Getting Started

### Prerequisites

  * Python 3.x
  * Virtual Environment (`venv`)

### Installation

Clone the repository and set up your environment using the following commands:

```bash
# Create a virtual environment
python -m venv venv

# Activate the environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> [\!NOTE]
> Because this emulator uses raw sockets, you may need to run certain scripts with administrative/root privileges depending on your OS security settings.
