
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/ip.h>

struct data_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 pid;
};

BPF_PERF_OUTPUT(events);

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 dport = 0;
    u32 saddr = 0, daddr = 0;
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        dport = sk->__sk_common.skc_dport;
        saddr = sk->__sk_common.skc_rcv_saddr;
        daddr = sk->__sk_common.skc_daddr;

        struct data_t data = {};
        data.src_ip = saddr;
        data.dst_ip = daddr;
        data.src_port = sk->__sk_common.skc_num;
        data.dst_port = ntohs(dport);
        data.pid = bpf_get_current_pid_tgid() >> 32;

        events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
