/*
 * GoodbyeDPI — Passive DPI blocker and Active DPI circumvention utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <ws2tcpip.h>
#include "windivert.h"
#include "goodbyedpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "fakepackets.h"

// Declaration for inet_pton function
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);

#define GOODBYEDPI_VERSION "v0.2.3rc3"

#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4

// Filter strings
#define FILTER_NO_LOCALNETS \
    "((ip.DstAddr != 127.0.0.1 and ip.DstAddr != 127.255.255.255 and " \
    "ip.DstAddr != 10.0.0.0 and ip.DstAddr != 10.255.255.255 and " \
    "ip.DstAddr != 192.168.0.0 and ip.DstAddr != 192.168.255.255 and " \
    "ip.DstAddr != 172.16.0.0 and ip.DstAddr != 172.31.255.255 and " \
    "ip.DstAddr != 169.254.0.0 and ip.DstAddr != 169.254.255.255)" \
    ")"

#define FILTER_STRING_TEMPLATE \
    "(tcp and !impostor and !loopback and ((inbound and (tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack) or " \
    "(outbound and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack)))"

#define FILTER_PASSIVE_BLOCK_QUIC \
    "outbound and !impostor and !loopback and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 " \
    "and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01"

#define HOST_MAXLEN 256

static int exiting = 0;
static HANDLE filters[MAX_FILTERS];
static int filter_num = 0;
static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static struct option long_options[] = {
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"blacklist",   required_argument, 0,  'b' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex", required_argument, 0,  'u' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  't' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {0,             0,                 0,   0  }
};

static char *filter_string = NULL;

static inline void *optimized_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (!needlelen || haystacklen < needlelen)
        return NULL;
    const unsigned char *haystack_ptr = haystack;
    const unsigned char *needle_ptr = needle;
    const unsigned char *end = haystack_ptr + haystacklen - needlelen + 1;
    for (; haystack_ptr < end; ++haystack_ptr) {
        if (*haystack_ptr == *needle_ptr && !memcmp(haystack_ptr, needle_ptr, needlelen))
            return (void *)haystack_ptr;
    }
    return NULL;
}

static inline unsigned short atousi(const char *str, const char *msg) {
    unsigned long res = strtoul(str, NULL, 10);
    if (res > UINT16_MAX) {
        puts(msg);
        exit(EXIT_FAILURE);
    }
    return (unsigned short)res;
}

static HANDLE init(char *filter, UINT64 flags) {
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD errorcode = GetLastError();
        printf("Error opening filter: %d\n", errorcode);
        return NULL;
    }
    return handle;
}

static int deinit(HANDLE handle) {
    if (handle) {
        WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle);
        return TRUE;
    }
    return FALSE;
}

void deinit_all() {
    for (int i = 0; i < filter_num; i++) {
        deinit(filters[i]);
    }
}

static void sigint_handler(int sig) {
    exiting = 1;
    deinit_all();
    exit(EXIT_SUCCESS);
}

static inline void mix_case(char *pktdata, unsigned int pktlen) {
    for (unsigned int i = 1; i < pktlen; i += 2) {
        pktdata[i] = toupper((unsigned char)pktdata[i]);
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0) {
        if (optimized_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            optimized_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static PVOID find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    for (size_t i = 0; i < sizeof(http_methods) / sizeof(*http_methods); i++) {
        size_t method_len = strlen(http_methods[i]);
        if (memcmp(pkt, http_methods[i], method_len) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)(pkt + method_len - 1);
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag, method_len - http_frag) == 0) {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)(pkt + method_len - http_frag - 1);
        }
    }
    return NULL;
}

static void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
    char *packet, UINT packetLen, PVOID packet_data,
    UINT packet_dataLen, int packet_v6,
    PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
    PWINDIVERT_TCPHDR ppTcpHdr,
    unsigned int fragment_size, int step) {

    char packet_bak[MAX_PACKET_SIZE];
    memcpy(packet_bak, packet, packetLen);
    UINT orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    if (step == 0) {
        if (ppIpHdr)
            ppIpHdr->Length = htons(ntohs(ppIpHdr->Length) - packet_dataLen + fragment_size);
        else if (ppIpV6Hdr)
            ppIpV6Hdr->Length = htons(ntohs(ppIpV6Hdr->Length) - packet_dataLen + fragment_size);
        packetLen = packetLen - packet_dataLen + fragment_size;
    } else if (step == 1) {
        if (ppIpHdr)
            ppIpHdr->Length = htons(ntohs(ppIpHdr->Length) - fragment_size);
        else if (ppIpV6Hdr)
            ppIpV6Hdr->Length = htons(ntohs(ppIpV6Hdr->Length) - fragment_size);
        memmove(packet_data,
                (char*)packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;
        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
    }

    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;
    WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
    WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
    memcpy(packet, packet_bak, orig_packetLen);
}

int main(int argc, char *argv[]) {
    enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;

    int opt;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    char packet[MAX_PACKET_SIZE];
    PVOID packet_data;
    UINT packetLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    PWINDIVERT_UDPHDR ppUdpHdr;

    int do_passivedpi = 0, do_block_quic = 0, do_fragment_http = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_host_mixedcase = 0, do_fake_packet = 0,
        do_native_frag = 0, do_reverse_frag = 0;
    unsigned int http_fragment_size = 0;
    unsigned int https_fragment_size = 0;
    unsigned int current_fragment_size = 0;
    char *host_addr;
    unsigned int host_len;

    SetDllDirectory("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);

    if (filter_string == NULL)
        filter_string = strdup(FILTER_STRING_TEMPLATE);

    printf("GoodbyeDPI " GOODBYEDPI_VERSION ": Passive DPI blocker and Active DPI circumvention utility\n");

    if (argc == 1) {
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fake_packet = 1;
        do_block_quic = 1;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:n", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9': // +7+8
                do_block_quic = 1;
                // fall through
            case '8': // +7
                do_wrong_seq = 1;
                // fall through
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'q':
                do_block_quic = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'z': // --port
                /* i is used as a temporary variable here */
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                if (i != 80 && i != 443)
                    add_filter_str(IPPROTO_TCP, i);
                i = 0;
                break;
            case 'i': // --ip-id
                /* i is used as a temporary variable here */
                i = atousi(optarg, "IP ID parameter error!\n");
                add_ip_id_str(i);
                i = 0;
                break;
            case 'd': // --dns-addr
                if ((inet_pton(AF_INET, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv4_redirect)
                {
                    do_dnsv4_redirect = 1;
                    if (inet_pton(AF_INET, optarg, &dnsv4_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V4_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V4_ADDR);
                break;
            case '!': // --dnsv6-addr
                if ((inet_pton(AF_INET6, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv6_redirect)
                {
                    do_dnsv6_redirect = 1;
                    if (inet_pton(AF_INET6, optarg, dnsv6_addr.s6_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V6_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V6_ADDR);
                break;
            case 'g': // --dns-port
                if (!do_dnsv4_redirect) {
                    puts("--dns-port should be used with --dns-addr!\n"
                        "Make sure you use --dns-addr and pass it before "
                        "--dns-port");
                    exit(ERROR_DNS_V4_PORT);
                }
                dnsv4_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv4_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv4_port);
                }
                dnsv4_port = htons(dnsv4_port);
                break;
            case '@': // --dnsv6-port
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-port should be used with --dnsv6-addr!\n"
                        "Make sure you use --dnsv6-addr and pass it before "
                        "--dnsv6-port");
                    exit(ERROR_DNS_V6_PORT);
                }
                dnsv6_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv6_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv6_port);
                }
                dnsv6_port = htons(dnsv6_port);
                break;
            case 'v':
                do_dns_verb = 1;
                do_tcp_verb = 1;
                break;
            case 'b': // --blacklist
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case ']': // --allow-no-sni
                do_allow_no_sni = 1;
                break;
            case '>': // --frag-by-sni
                do_fragment_by_sni = 1;
                break;
            case '$': // --set-ttl
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[': // --min-ttl
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+': // --auto-ttl
                do_fake_packet = 1;
                do_auto_ttl = 1;

                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];

                if (optarg) {
                    char *autottl_copy = strdup(optarg);
                    char *autottl_save;
                    if (strchr(autottl_copy, '-')) {
                        // token "-" found, start X-Y parser
                        char *autottl_current = strtok_r(autottl_copy, "-", &autottl_save);
                        auto_ttl_1 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok_r(NULL, "-", &autottl_save);
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_2 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok_r(NULL, "-", &autottl_save);
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_max = atoub(autottl_current, "Set Auto TTL parameter error!");
                    }
                    else {
                        // single digit parser
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%': // --wrong-chksum
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case ')': // --wrong-seq
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*': // --native-frag
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '(': // --reverse-frag
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '|': // --max-payload
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case 'u': // --fake-from-hex
                if (fake_load_from_hex(optarg)) {
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                }
                break;
            case 'j': // --fake-gen
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 't': // --fake-resend
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                if (fakes_resend == 1)
                    puts("WARNING: fake-resend is 1, no resending is in place!");
                else if (!fakes_resend)
                    puts("WARNING: fake-resend is 0, fake packet mode is disabled!");
                else if (fakes_resend > 100)
                    puts("WARNING: fake-resend value is a little too high, don't you think?");
                break;
            case 'x': // --debug-exit
                debug_exit = true;
                break;
            default:
                puts("Usage: goodbyedpi.exe [OPTION...]\n"
                " -p          block passive DPI\n"
                " -q          block QUIC/HTTP3\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI (enables -s, may break sites)\n"
                " -m          mix Host header case (test.com -> tEsT.cOm)\n"
                " -f <value>  set HTTP fragmentation to value\n"
                " -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value\n"
                " -n          do not wait for first segment ACK when -k is enabled\n"
                " -e <value>  set HTTPS fragmentation to value\n"
                " -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)\n"
                " --port        <value>    additional TCP port to perform fragmentation on (and HTTP tricks with -w)\n"
                " --ip-id       <value>    handle additional IP ID (decimal, drop redirects and TCP RSTs with this ID).\n"
                " --dns-addr    <value>    redirect UDPv4 DNS requests to the supplied IPv4 address (experimental)\n"
                " --dns-port    <value>    redirect UDPv4 DNS requests to the supplied port (53 by default)\n"
                " --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address (experimental)\n"
                " --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)\n"
                " --dns-verb               print verbose DNS redirection messages\n"
                " --blacklist   <txtfile>  perform circumvention tricks only to host names and subdomains from\n"
                "                          supplied text file (HTTP Host/TLS SNI).\n"
                "                          This option can be supplied multiple times.\n"
                " --allow-no-sni           perform circumvention if TLS SNI can't be detected with --blacklist enabled.\n"
                " --frag-by-sni            if SNI is detected in TLS packet, fragment the packet right before SNI value.\n"
                " --set-ttl     <value>    activate Fake Request Mode and send it with supplied TTL value.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --auto-ttl    [a1-a2-m]  activate Fake Request Mode, automatically detect TTL and decrease\n"
                "                          it based on a distance. If the distance is shorter than a2, TTL is decreased\n"
                "                          by a2. If it's longer, (a1; a2) scale is used with the distance as a weight.\n"
                "                          If the resulting TTL is more than m(ax), set it to m.\n"
                "                          Default (if set): --auto-ttl 1-4-10. Also sets --min-ttl 3.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --min-ttl     <value>    minimum TTL distance (128/64 - TTL) for which to send Fake Request\n"
                "                          in --set-ttl and --auto-ttl modes.\n"
                " --wrong-chksum           activate Fake Request Mode and send it with incorrect TCP checksum.\n"
                "                          May not work in a VM or with some routers, but is safer than set-ttl.\n"
                "                          Could be combined with --set-ttl\n"
                " --wrong-seq              activate Fake Request Mode and send it with TCP SEQ/ACK in the past.\n"
                " --native-frag            fragment (split) the packets by sending them in smaller packets, without\n"
                "                          shrinking the Window Size. Works faster (does not slow down the connection)\n"
                "                          and better.\n"
                " --reverse-frag           fragment (split) the packets just as --native-frag, but send them in the\n"
                "                          reversed order. Works with the websites which could not handle segmented\n"
                "                          HTTPS TLS ClientHello (because they receive the TCP flow \"combined\").\n"
                " --fake-from-hex <value>  Load fake packets for Fake Request Mode from HEX values (like 1234abcDEF).\n"
                "                          This option can be supplied multiple times, in this case each fake packet\n"
                "                          would be sent on every request in the command line argument order.\n"
                " --fake-gen <value>       Generate random-filled fake packets for Fake Request Mode, value of them\n"
                "                          (up to 30).\n"
                " --fake-resend <value>    Send each fake packet value number of times.\n"
                "                          Default: 1 (send each packet once).\n"
                " --max-payload [value]    packets with TCP payload data more than [value] won't be processed.\n"
                "                          Use this option to reduce CPU usage by skipping huge amount of data\n"
                "                          (like file transfers) in already established sessions.\n"
                "                          May skip some huge HTTP requests from being processed.\n"
                "                          Default (if set): --max-payload 1200.\n"
                "\n");
                puts("LEGACY modesets:\n"
                " -1          -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode)\n"
                " -2          -p -r -s -f 2 -k 2 -n -e 40 (better speed for HTTPS yet still compatible)\n"
                " -3          -p -r -s -e 40 (better speed for HTTP and HTTPS)\n"
                " -4          -p -r -s (best speed)"
                "\n"
                "Modern modesets (more stable, more compatible, faster):\n"
                " -5          -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
                " -6          -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
                " -7          -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
                " -8          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
                " -9          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (this is the default)\n\n"
                "Note: combination of --wrong-seq and --wrong-chksum generates two different fake packets.\n"
                );
                exit(ERROR_DEFAULT);
        }
    }

    if (!http_fragment_size)
        http_fragment_size = 2;
    if (!https_fragment_size)
        https_fragment_size = 2;
    if (!auto_ttl_1)
        auto_ttl_1 = 1;
    if (!auto_ttl_2)
        auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops)
            ttl_min_nhops = 3;
        if (!auto_ttl_max)
            auto_ttl_max = 10;
    }

    printf("Block passive: %d\n"                    /* 1 */
           "Block QUIC/HTTP3: %d\n"                 /* 1 */
           "Fragment HTTP: %u\n"                    /* 2 */
           "Fragment persistent HTTP: %u\n"         /* 3 */
           "Fragment HTTPS: %u\n"                   /* 4 */
           "Fragment by SNI: %u\n"                  /* 5 */
           "Native fragmentation (splitting): %d\n" /* 6 */
           "Fragments sending in reverse: %d\n"     /* 7 */
           "hoSt: %d\n"                             /* 8 */
           "Host no space: %d\n"                    /* 9 */
           "Additional space: %d\n"                 /* 10 */
           "Mix Host: %d\n"                         /* 11 */
           "HTTP AllPorts: %d\n"                    /* 12 */
           "HTTP Persistent Nowait: %d\n"           /* 13 */
           "DNS redirect: %d\n"                     /* 14 */
           "DNSv6 redirect: %d\n"                   /* 15 */
           "Allow missing SNI: %d\n"                /* 16 */
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"  /* 17 */
           "Fake requests, wrong checksum: %d\n"    /* 18 */
           "Fake requests, wrong SEQ/ACK: %d\n"     /* 19 */
           "Fake requests, custom payloads: %d\n"   /* 20 */
           "Fake requests, resend: %d\n"            /* 21 */
           "Max payload size: %hu\n",               /* 22 */
           do_passivedpi, do_block_quic,                          /* 1 */
           (do_fragment_http ? http_fragment_size : 0),           /* 2 */
           (do_fragment_http_persistent ? http_fragment_size : 0),/* 3 */
           (do_fragment_https ? https_fragment_size : 0),         /* 4 */
           do_fragment_by_sni,    /* 5 */
           do_native_frag,        /* 6 */
           do_reverse_frag,       /* 7 */
           do_host,               /* 8 */
           do_host_removespace,   /* 9 */
           do_additional_space,   /* 10 */
           do_host_mixedcase,     /* 11 */
           do_http_allports,      /* 12 */
           do_fragment_http_persistent_nowait, /* 13 */
           do_dnsv4_redirect,                  /* 14 */
           do_dnsv6_redirect,                  /* 15 */
           do_allow_no_sni,                    /* 16 */
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),  /* 17 */
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum, /* 18 */
           do_wrong_seq,    /* 19 */
           fakes_count,     /* 20 */
           fakes_resend,    /* 21 */
           max_payload_size /* 22 */
          );


    filters[filter_num] = init(filter_string, 0);
    w_filter = filters[filter_num];
    filter_num++;

    if (w_filter == NULL)
        die();

    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);

    while (1) {
        if (WinDivertRecv(w_filter, packet, sizeof(packet), &packetLen, &addr)) {
            int should_reinject = 1;
            int should_recalc_checksum = 0;
            ppIpHdr = NULL;
            ppIpV6Hdr = NULL;
            ppTcpHdr = NULL;
            ppUdpHdr = NULL;
            int packet_v4 = 0, packet_v6 = 0;
            packet_type = unknown;

            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr, &packet_data, &packet_dataLen,
                NULL, NULL)) {
                if (ppIpHdr) {
                    packet_v4 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv4_tcp;
                        if (packet_data) {
                            packet_type = ipv4_tcp_data;
                        }
                    }
                } else if (ppIpV6Hdr) {
                    packet_v6 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv6_tcp;
                        if (packet_data) {
                            packet_type = ipv6_tcp_data;
                        }
                    }
                }
            }

            if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) {
                if (!addr.Outbound && packet_dataLen > 16) {
                    if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        should_reinject = 0;
                    }
                } else if (addr.Outbound && packet_dataLen > 16 && ppTcpHdr->DstPort == htons(80) &&
                    find_http_method_end(packet_data, (do_fragment_http ? http_fragment_size : 0), NULL)) {

                    char *hdr_name_addr, *hdr_value_addr;
                    unsigned int hdr_value_len;

                    if (optimized_memmem(packet_data, packet_dataLen, http_host_find, sizeof(http_host_find) - 1)) {
                        hdr_name_addr = (char *)optimized_memmem(packet_data, packet_dataLen, http_host_find, sizeof(http_host_find) - 1);
                        hdr_value_addr = hdr_name_addr + sizeof(http_host_find) - 1;
                        hdr_value_len = packet_dataLen - ((char *)hdr_value_addr - (char *)packet_data);

                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;

                        if (do_native_frag) {
                            should_recalc_checksum = 1;
                        }

                        if (do_host_mixedcase) {
                            mix_case(host_addr, host_len);
                            should_recalc_checksum = 1;
                        }

                        if (do_host) {
                            memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                            should_recalc_checksum = 1;
                        }
                    }
                }

                if (should_reinject && should_recalc_checksum && do_native_frag) {
                    current_fragment_size = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        current_fragment_size = http_fragment_size;
                    } else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        current_fragment_size = https_fragment_size;
                    }

                    if (current_fragment_size) {
                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, do_reverse_frag);

                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, !do_reverse_frag);
                        continue;
                    }
                }
            }

            if (should_reinject) {
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
                }
                WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
            }
        } else {
            if (!exiting)
                printf("Error receiving packet!\n");
            break;
        }
    }
}