#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

BPF_HASH(blocklist, u32, u32);

int xdp_drop_ips(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)(ip + 1) > data_end) {
            return XDP_PASS;
        }

        u32 src_ip = ip->saddr;

        u32 *is_blocked = blocklist.lookup(&src_ip);
        if (is_blocked) {
            return XDP_DROP; 
        }
    }
    return XDP_PASS;
}
