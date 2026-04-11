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
| **Data** | ≤256B | Application Data |

#### 3\. TCP Implementation (Layer 4)
This emulator utilises a **Simplified State-Machine TCP**. Instead of using TCP connection state headers, the IP payload carries the state in bytes to manage the connection lifecycle.

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

  * Python 3.14 or later
  * Virtual Environment (`venv`)

### Modern Setup (Recommended)

Install [uv](https://github.com/astral-sh/uv) for fast Python package management:

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv venv
uv sync
```

### Alternative Setup

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

---

## Configuration

The network topology and behavior are configured through `config.yaml`. The configuration is validated against `config-schema.yaml`.

### Global Settings
```yaml
config:
  HOSTNAME: 127.0.0.1          # Host for socket connections
  LOGGING_LEVEL: INFO          # DEBUG, INFO, WARNING, ERROR, CRITICAL
  RECEIVE_SIZE: 261            # Socket receive buffer size
  SOCKET_TIMEOUT: 1            # Socket timeout in seconds
```

### Network Topology
```yaml
nodes:
  N1:
    MAC: N1                    # MAC address identifier
    IP: 0x12                   # IP address in hex
    wire: W1                   # Connected wire
    firewall: true             # Optional: enable firewall (default: false)

wires:
  W1:
    port: 8000                 # UDP port for wire communication
    subnet: 0x10               # Subnet address
    subnetMask: 0xF0           # Subnet mask

routers:
  interfaces:
    R1:
      MAC: R1                  # Router interface MAC
      IP: 0x11                 # Router interface IP
      wire: W1                 # Connected wire
  routing_table:
    0x12: R1                   # IP -> Router interface mapping
    0x13: R1
    0x22: R2
    0x32: R3
```

### Modifying Configuration
- Edit `config.yaml` to change network topology, add/remove nodes, or modify router settings
- The configuration is validated against the JSON schema in `config-schema.yaml`
- Restart all components after configuration changes

---

## Quick Start with start.bat

For an automated setup that runs the entire network in a single tmux session:

### Prerequisites

- [uv](https://github.com/astral-sh/uv) (Python package manager)
- [Task](https://taskfile.dev) (task runner)
- [tmux](https://github.com/tmux/tmux/wiki) (terminal multiplexer)
  - On Windows, use [psmux](https://github.com/lukesampson/psmux) or WSL2 with tmux

### Run the Network

```bash
# Install dependencies and run all components
./start.bat
```

This will:
- Create a tmux session with multiple panes
- Start 3 wires (W1, W2, W3), 1 router, and 4 nodes (N1-N4)
- Attach to the tmux session for interaction

Use `Ctrl-b d` to detach from tmux, and `tmux attach -t networking` to reattach.

---

## Task Automation

The project uses [Taskfile](https://taskfile.dev) for automation. After setup:

```bash
# Run individual components
task -- wire W1    # Start wire W1
task -- node N1    # Start node N1
task -- router     # Start router

# Or run the default task (same as above with arguments)
task wire W1
task node N1
task router
```

Task automatically handles virtual environment activation and dependency installation.

> [\!NOTE]
> Because this emulator uses raw sockets, you may need to run certain scripts with administrative/root privileges depending on your OS security settings.
---

## Running the Network

For manual setup (alternative to automated methods above), open a terminal per component. Start wires first, then router, then nodes.

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

On Windows, use the `.bat` versions of the scripts.

---

## Node CLI Commands

### Core Commands
```
SEND <IP> <message>               Send message to IP address
PING <IP>                         Send ping request to IP
SPOOF <spoofed_IP> <IP> <message> IP spoofing attack
SNIFF on|off                      Toggle packet sniffing mode
ARP                               Display ARP table
HELP or ?                         Show available commands
```

### Firewall Commands (when firewall enabled)
```
FW ADD ACCEPT|DROP <IP>           Add firewall rule
FW REMOVE <rule_id>               Remove rule by index
FW LIST                           List all firewall rules
FW DEFAULT ACCEPT|DROP            Set default firewall policy
```

### TCP Commands
```
CONNECT <IP>                      Attempt TCP connection
STATS                             Show connection table and active attacks
SLOWLORIS <IP>                    Start Slowloris attack on IP
SLOWLORIS STOP                    Stop Slowloris attack
```

---

## Tools and Dependencies

### Core Dependencies
- **Python 3.14+** - Required runtime
- **PyYAML** - Configuration parsing

### Development Tools
- **[uv](https://github.com/astral-sh/uv)** - Fast Python package installer and virtual environment manager
- **[Task](https://taskfile.dev)** - Task runner for automation
- **[tmux](https://github.com/tmux/tmux/wiki)** - Terminal multiplexer for running multiple components
  - Windows alternative: [psmux](https://github.com/lukesampson/psmux) or WSL2

### Installation Commands

**uv:**
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
winget install astral-sh.uv
```

**Task:**
```bash
# macOS
brew install go-task/tap/go-task

# Linux
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d

# Windows
winget install Task.Task
```

**tmux:**
```bash
# macOS
brew install tmux

# Linux (Ubuntu/Debian)
sudo apt install tmux

# Windows
winget install marlocarlo.psmux
```

---

## File Structure

```
src/
├── main.py                    # Entry point — wire / node / router modes
└── networking/
    ├── frames.py              # MACFrame and IPFrame serialization/deserialization
    ├── types.py               # IPProtocol enum, NodeConfig, address types
    ├── constants.py           # BROADCAST_MAC, encoding constants
    ├── config.py              # Loads and validates config.yaml
    ├── log_format.py          # Logger setup and formatting
    ├── firewall.py            # Firewall rule engine and packet filtering
    ├── ids.py                 # IDS configuration and threshold constants
    ├── components/
    │   ├── node.py            # Node logic, CLI interface, application loading
    │   ├── router.py          # Packet forwarding, ARP table, IDS monitoring
    │   └── wire.py            # Broadcast Ethernet emulation
    ├── applications/
    │   ├── tcp.py             # TCP protocol stack and connection handling
    │   ├── ddos.py            # Slowloris attack implementations
    │   └── mitm.py            # MITM attack via ARP poisoning
    └── collections/
        └── ts_dict.py         # Thread-safe dictionary
```
