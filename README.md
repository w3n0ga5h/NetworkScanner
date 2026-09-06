# NetworkScanner

A small network reconnaissance tool written in Python with [Scapy](https://scapy.net/).
You give it an IP address or a CIDR range, and it maps what is alive on that network:
ARP discovery, ICMP ping sweep, and TCP SYN port scanning — built from raw packets,
not by wrapping `nmap`.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Scapy](https://img.shields.io/badge/built%20with-scapy-green)

---

## Why this project exists

I am a security engineer, and I decided to relearn Python from zero.

Rather than grinding through generic tutorial exercises, I preferred to rebuild something
from my own field and understand it at the packet level: how an ARP request is actually
framed, why a half-open SYN scan is "stealthy", what a subnet mask really gives you.
Writing the tool teaches far more than reading about it.

[!NOTE]
**Every line of Python in this repository was written by hand, without any AI assistance.**
That is the whole point of the exercise. The only exception is this README, which was
written with the help of an AI — the code is mine, the documentation is not.

---

## What it does

Given one target, the tool runs the following steps in order:

| Step | Method | What it does |
|---|---|---|
| 1 | `ipinformation()` | Prints the network details of the target (network address, mask, usable range) |
| 2 | `ip_range()` | Expands a CIDR range into the list of usable host addresses |
| 3 | `scanarp()` | Sends a broadcast ARP request to each host and reports the IP / MAC pairs that answer |
| 4 | `stealth_port_scan()` | Half-open TCP SYN scan of every host in the target range; on a SYN-ACK it replies with **RST** so the connection is never completed |
| 5 | `port_scan()` | Same SYN scan over the same hosts, but on a SYN-ACK it replies with **ACK**, completing the handshake |
| 6 | `ping_sweep()` | Sends an ICMP echo request to each host and reports who replies |

The port scans check a fixed list of 12 common TCP ports:

```
20  21  22  23  25  53  80  88  115  389  443  445
```

---

## Requirements

* **Python 3.11+**
* **Root / Administrator privileges** — the tool crafts and sends raw packets, which is a
  privileged operation on every OS.
* A packet capture driver:
  * **Linux / macOS** — nothing to install, just run with `sudo`.
  * **Windows** — install [Npcap](https://npcap.com/) and tick *"Install Npcap in WinPcap
    API-compatible Mode"* during setup, then run your terminal **as Administrator**.
* Python packages: `ipaddress`, `scapy`, `subnetcalc`

---

## Installation

### Option A — with `uv` (recommended)

The script carries a [PEP 723](https://peps.python.org/pep-0723/) inline dependency header,
so `uv` resolves and installs everything on its own. No virtual environment to manage.

```bash
git clone https://github.com/w3n0ga5h/NetworkScanner.git
```

Then, from inside the cloned folder:

```bash
sudo $(which uv) run networkscanner.py
```

On Windows, open an **Administrator** terminal and run:

```bash
uv run networkscanner.py
```

### Option B — with `pip` and a virtual environment

```bash
git clone https://github.com/w3n0ga5h/NetworkScanner.git
```

Create the environment and install the dependencies:

```bash
python -m venv .venv
```

Activate it — on Linux / macOS:

```bash
source .venv/bin/activate
```

On Windows (PowerShell):

```bash
.venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
pip install ipaddress scapy subnetcalc
```

Then run it — on Linux / macOS:

```bash
sudo .venv/bin/python networkscanner.py
```

On Windows, from an **Administrator** terminal:

```bash
python networkscanner.py
```

---

## Usage

The tool is interactive: it asks for a single target, then runs all the scans in sequence.

```
Please enter the ip address of the server you wish to connect with:
```

Accepted input formats:

| Input | Interpreted as |
|---|---|
| `192.168.1.10` | A single host (`/32`) |
| `192.168.1.10/32` | A single host |
| `192.168.1.0/24` | The whole subnet, host by host |
| `10.0.0.0/29` | A small range of 6 usable hosts |

Anything that is not a valid IPv4 address or network is rejected and the prompt is
repeated, so you cannot crash it with a typo.

### Example session

```
Please enter the ip address of the server you wish to connect with:192.168.1.10
... network details of the target ...
Starting ARP Scan :
IP :192.168.1.10 answered and the MAC address is a4:83:e7:2c:19:5f
Starting stealth port scan of 192.168.1.10
No answer from port 20
No answer from port 21
SynAck answer received from port 22
SynAck answer received from port 80
No answer from port 88
Starting ping sweep:
Received answer from 192.168.1.10
```

---

## Status

This is a **proof of concept**, written as a learning project rather than as a finished
product. It is a V1: scans run sequentially, the port list is hardcoded, the target is only
given through the interactive prompt, and results are printed to the terminal only.

The limitations are known and accepted for now — the goal was to understand and write the
code myself, not to compete with `nmap`.

---

## What I learned building this

The Python and networking ground this project covers:

* **Classes and instance state** — `myscanner` holds the target, the expanded host list and
  the port list as member variables shared across every scan method.
* **Input validation with exceptions** — a `while True` loop around `ipaddress.IPv4Network()`
  catching `ValueError`, so the prompt only exits on valid input.
* **The standard library `ipaddress` module** — parsing an address or a CIDR block, and using
  `strict=False` so a plain host address is accepted as well as a network.
* **Third-party libraries** — `subnetcalc` to expand a network into its usable host addresses.
* **Scapy layer stacking** — building packets with the `/` operator (`Ether()/ARP()`,
  `IP()/TCP()`, `IP()/ICMP()`) and reading fields back off the answers (`psrc`, `hwsrc`, `flags`).
* **The difference between `srp()` and `sr1()`** — sending at layer 2 versus layer 3, and
  handling answered versus unanswered packet lists.
* **TCP at the flag level** — what a `SYN` / `SYN-ACK` exchange looks like on the wire, and
  why answering with `RST` instead of `ACK` leaves no completed connection behind.
* **f-strings, list building, and control flow** — the everyday Python that ties it together.

---

*Note: all of the code in this repository was written manually, as a Python learning exercise.
This README is the only file that was produced with AI assistance.*
