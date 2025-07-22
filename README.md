 ## eBPF-Based Kernel Packet Logger

A lightweight Linux kernel-level packet logging and threat detection tool using eBPF and Python. Developed as part of a college cybersecurity project to demonstrate low-level observability and anomaly detection via suspicious port activity.

---

##  Features

- Attaches an eBPF `kprobe` to `tcp_sendmsg`
- Captures source/destination IPs, ports, and PID
- Alerts on traffic to suspicious ports (defined in JSON)
- Writes detailed logs to a file
- Designed for Linux (not WSL)

---

## How It Works

1. eBPF attaches to the `tcp_sendmsg` kernel function.
2. On each packet send, it extracts:
   - Source IP
   - Destination IP
   - Ports
   - Process ID
3. Sends this data to user space via a `perf buffer`.
4. Python handles alerts, filtering, and logging.

---

## Setup

```bash
# Dependencies (for Debian/Kali)
sudo apt install bpfcc-tools cmake libclang-dev llvm-dev libelf-dev zlib1g-dev libfl-dev python3-pip
pip3 install bcc
