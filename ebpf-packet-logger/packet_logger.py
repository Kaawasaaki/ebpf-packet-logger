
from bcc import BPF
from socket import inet_ntoa
from struct import pack
import json
import os
import time

with open("suspicious_ports.json") as f:
    PORTS = set(json.load(f)["ports"])

with open("packet_filter.c") as f:
    bpf_source = f.read()

b = BPF(text=bpf_source)
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

print("[+] Monitoring TCP traffic at kernel level...")
print("[+] Suspicious ports:", PORTS)
print("")

def callback(cpu, data, size):
    event = b["events"].event(data)
    src_ip = inet_ntoa(pack("I", event.src_ip))
    dst_ip = inet_ntoa(pack("I", event.dst_ip))
    line = f"[{time.strftime('%H:%M:%S')}] {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} (PID {event.pid})"

    if event.dst_port in PORTS:
        print("⚠️  Suspicious traffic:", line)
        with open("logs/alert_log.txt", "a") as log:
            log.write(line + "\n")
    else:
        print("   Normal traffic:", line)

b["events"].open_perf_buffer(callback)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[+] Stopped packet monitoring.")
