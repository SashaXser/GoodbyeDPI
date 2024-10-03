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
                do_passivedpi = do_host = do_host_removespace = do_fragment_http = do_fragment_https = 1;
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
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                http_fragment_size = atousi(optarg, "Fragment size error\n");
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size error\n");
                break;
            case '*':
                do_native_frag = 1;
                break;
            case '(':
                do_reverse_frag = 1;
                break;
            default:
                printf("Usage: goodbyedpi.exe [OPTION...]\n");
                exit(EXIT_FAILURE);
        }
    }

    printf("Settings:\n");
    printf("Block passive DPI: %d\n", do_passivedpi);
    printf("Block QUIC: %d\n", do_block_quic);
    printf("Fragment HTTP: %u\n", http_fragment_size);
    printf("Fragment HTTPS: %u\n", https_fragment_size);
    printf("hoSt: %d\n", do_host);
    printf("Host no space: %d\n", do_host_removespace);
    printf("Additional space: %d\n", do_additional_space);
    printf("Mix Host: %d\n", do_host_mixedcase);
    printf("Native fragmentation: %d\n", do_native_frag);
    printf("Reverse fragmentation: %d\n", do_reverse_frag);

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