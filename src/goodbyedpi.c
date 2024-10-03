#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include "windivert.h"
#include "goodbyedpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "fakepackets.h"
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);
#define GOODBYEDPI_VERSION "v0.2.3rc3"
#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)
#define MAX_FILTERS 4
#define DIVERT_NO_LOCALNETSv4_DST "(" \
                       "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                       "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                       "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                       "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                       "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)" \
                       ")"
#define DIVERT_NO_LOCALNETSv4_SRC "(" \
                       "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                       "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                       "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                       "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                       "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255)" \
                       ")"
#define DIVERT_NO_LOCALNETSv6_DST "(" \
                       "(ipv6.DstAddr > ::1) and " \
                       "(ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and " \
                       "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and " \
                       "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and " \
                       "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0)" \
                       ")"
#define DIVERT_NO_LOCALNETSv6_SRC "(" \
                       "(ipv6.SrcAddr > ::1) and " \
                       "(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and " \
                       "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and " \
                       "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and " \
                       "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0)" \
                       ")"
#define IPID_TEMPLATE "#IPID#"
#define MAXPAYLOADSIZE_TEMPLATE "#MAXPAYLOADSIZE#"
#define FILTER_STRING_TEMPLATE \
            "(tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
            "((inbound and (" \
             "(" \
              "(" \
               "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) " IPID_TEMPLATE \
               ") and " \
               "tcp.SrcPort == 80 and tcp.Ack" \
              ") or " \
              "((tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn)" \
             ")" \
             " and (" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC "))) or " \
            "(outbound and " \
             "(tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack and " \
             "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST "))" \
            "))"
#define FILTER_PASSIVE_BLOCK_QUIC "outbound and !impostor and !loopback and udp " \
            "and udp.DstPort == 443 and udp.PayloadLength >= 1200 " \
            "and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01"
#define FILTER_PASSIVE_STRING_TEMPLATE "inbound and ip and tcp and " \
            "!impostor and !loopback and " \
            "(true " IPID_TEMPLATE ") and " \
            "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and " \
            DIVERT_NO_LOCALNETSv4_SRC
#define SET_HTTP_FRAGMENT_SIZE_OPTION(fragment_size) do { \
        if (!http_fragment_size) { \
            http_fragment_size = (uint32_t)fragment_size; \
        } \
        else if (http_fragment_size != (uint32_t)fragment_size) { \
            printf( \
                "WARNING: HTTP fragment size is already set to %u, not changing.\n", \
                http_fragment_size \
            ); \
        } \
    } while (0)
#define TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() \
        if ((packet_v4 && tcp_handle_outgoing(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr, \
                            ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                            &tcp_conn_info, 0)) \
            || \
            (packet_v6 && tcp_handle_outgoing(ppIpV6Hdr->SrcAddr, ppIpV6Hdr->DstAddr, \
                            ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                            &tcp_conn_info, 1)))
#define TCP_HANDLE_OUTGOING_FAKE_PACKET(func) do { \
        should_send_fake = 1; \
        if (do_auto_ttl || ttl_min_nhops) { \
            TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() { \
                if (do_auto_ttl) { \
                    ttl_of_fake_packet = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2, \
                                                          ttl_min_nhops, auto_ttl_max); \
                    if (do_tcp_verb) { \
                        printf("Connection TTL = %d, Fake TTL = %d\n", tcp_conn_info.ttl, ttl_of_fake_packet); \
                    } \
                } \
                else if (ttl_min_nhops) { \
                    if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0)) { \
                        should_send_fake = 0; \
                    } \
                } \
            } \
        } \
        if (should_send_fake) \
            func(w_filter, &addr, packet, packetLen, packet_v6, \
                 ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq); \
    } while (0)
enum ERROR_CODE{
    ERROR_DEFAULT = 1,
    ERROR_PORT_BOUNDS,
    ERROR_DNS_V4_ADDR,
    ERROR_DNS_V6_ADDR,
    ERROR_DNS_V4_PORT,
    ERROR_DNS_V6_PORT,
    ERROR_BLACKLIST_LOAD,
    ERROR_AUTOTTL,
    ERROR_ATOUSI,
    ERROR_AUTOB
};
static int running_from_service = 0;
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
static char *filter_passive_string = NULL;
static void add_filter_str(int proto, uint16_t port) {
    const char *udp = " or (udp and !impostor and !loopback and " \
                      "(udp.SrcPort == %u or udp.DstPort == %u))";
    const char *tcp = " or (tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
                      "(tcp.SrcPort == %u or tcp.DstPort == %u))";
    char *current_filter = filter_string;
    size_t new_filter_size = strlen(current_filter) +
            (proto == IPPROTO_UDP ? strlen(udp) : strlen(tcp)) + 16;
    char *new_filter = malloc(new_filter_size);
    strcpy(new_filter, current_filter);
    if (proto == IPPROTO_UDP)
        sprintf(new_filter + strlen(new_filter), udp, port, port);
    else
        sprintf(new_filter + strlen(new_filter), tcp, port, port);
    filter_string = new_filter;
    free(current_filter);
}
static void add_ip_id_str(uint16_t id) {
    char *newstr;
    const char *ipid = " or ip.Id == %u";
    char *addfilter = malloc(strlen(ipid) + 16);
    sprintf(addfilter, ipid, id);
    newstr = repl_str(filter_string, IPID_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;
    newstr = repl_str(filter_passive_string, IPID_TEMPLATE, addfilter);
    free(filter_passive_string);
    filter_passive_string = newstr;
}
static void add_maxpayloadsize_str(uint16_t maxpayload) {
    char *newstr;
    const char *maxpayloadsize_str =
        "and (tcp.PayloadLength ? tcp.PayloadLength < %hu " \
          "or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 " \
          "or (tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03): true)";
    char *addfilter = malloc(strlen(maxpayloadsize_str) + 16);
    sprintf(addfilter, maxpayloadsize_str, maxpayload);
    newstr = repl_str(filter_string, MAXPAYLOADSIZE_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;
}
static void finalize_filter_strings() {
    char *newstr, *newstr2;
    newstr2 = repl_str(filter_string, IPID_TEMPLATE, "");
    newstr = repl_str(newstr2, MAXPAYLOADSIZE_TEMPLATE, "");
    free(filter_string);
    free(newstr2);
    filter_string = newstr;
    newstr = repl_str(filter_passive_string, IPID_TEMPLATE, "");
    free(filter_passive_string);
    filter_passive_string = newstr;
}
static inline char* dumb_memmem(const char* haystack, size_t hlen,
                         const char* needle, size_t nlen)
{
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) {
            return (char*)(haystack + i);
        }
    }
    return NULL;
}
static inline uint16_t atousi(const char *str, const char *msg) {
    uint32_t res = strtoul(str, NULL, 10);
    if (res > UINT16_MAX) {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    return (uint16_t)res;
}
static inline uint8_t atoub(const char *str, const char *msg) {
    uint32_t res = strtoul(str, NULL, 10);
    if (res > UINT8_MAX) {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    return (uint8_t)res;
}
static HANDLE init(char *filter, uint64_t flags) {
    LPTSTR errormessage = NULL;
    DWORD errorcode = 0;
    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
    if (handle != INVALID_HANDLE_VALUE)
        return handle;
    errorcode = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)&errormessage, 0, NULL);
    printf("Error opening filter: %d %s\n", errorcode, errormessage);
    LocalFree(errormessage);
    if (errorcode == 2)
        printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
    else if (errorcode == 654)
        printf("An incompatible version of the WinDivert driver is currently loaded.\n"
               "Please unload it with the following commands ran as administrator:\n\n"
               "sc stop windivert\n"
               "sc delete windivert\n"
               "sc stop windivert14"
               "sc delete windivert14\n");
    else if (errorcode == 1275)
        printf("This error occurs for various reasons, including:\n"
               "the WinDivert driver is blocked by security software; or\n"
               "you are using a virtualization environment that does not support drivers.\n");
    else if (errorcode == 1753)
        printf("This error occurs when the Base Filtering Engine service has been disabled.\n"
               "Enable Base Filtering Engine service.\n");
    else if (errorcode == 577)
        printf("Could not load driver due to invalid digital signature.\n"
               "Windows Server 2016 systems must have secure boot disabled to be \n"
               "able to load WinDivert driver.\n"
               "Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
               "https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
               "WARNING! If you see this error on Windows 7, it means your system is horribly "
               "outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
               "Most probably, you don't have security patches installed and anyone in you LAN or "
               "public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
               "You should install updates IMMEDIATELY.\n");
    return NULL;
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
static inline unsigned char my_toupper(unsigned char c) {
    if (c >= 'a' && c <= 'z')
        return c - ('a' - 'A');
    return c;
}
static inline void mix_case(char *pktdata, size_t pktlen) {
    for (size_t i = 1; i < pktlen; i += 2) {
        pktdata[i] = my_toupper((unsigned char)pktdata[i]);
    }
}
static int is_passivedpi_redirect(const char *pktdata, size_t pktlen) {
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0)
    {
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}
static int find_header_and_get_info(const char *pktdata, size_t pktlen,
                    const char *hdrname,
                    char **hdrnameaddr,
                    char **hdrvalueaddr, size_t *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;
    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;
    hdr_begin = dumb_memmem(pktdata, pktlen,
                hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;
    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);
    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (uintptr_t)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (uintptr_t)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}
static int extract_sni(const char *pktdata, size_t pktlen,
                        char **hostnameaddr, size_t *hostnamelen) {
    size_t ptr = 0;
    const unsigned char *d = (const unsigned char *)pktdata;
    const unsigned char *hnaddr = 0;
    int hnlen = 0;
    while (ptr + 8 < pktlen) {
        if (d[ptr] == 0 && d[ptr+1] == 0 && d[ptr+2] == 0 &&
            d[ptr+4] == 0 && d[ptr+6] == 0 && d[ptr+7] == 0 &&
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
        {
            if (ptr + 8 + d[ptr+8] > pktlen) {
                return FALSE;
            }
            hnaddr = &d[ptr+9];
            hnlen = d[ptr+8];
            if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                return FALSE;
            }
            for (int i = 0; i < hnlen; i++) {
                if (!((hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                     (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                     hnaddr[i] == '.' || hnaddr[i] == '-'))
                {
                    return FALSE;
                }
            }
            *hostnameaddr = (char*)hnaddr;
            *hostnamelen = (size_t)hnlen;
            return TRUE;
        }
        ptr++;
    }
    return FALSE;
}
static inline void change_window_size(const PWINDIVERT_TCPHDR ppTcpHdr, uint32_t size) {
    if (size >= 1 && size <= 0xFFFFu) {
        ppTcpHdr->Window = htons((uint16_t)size);
    }
}
static PVOID find_http_method_end(const char *pkt, uint32_t http_frag, int *is_fragmented) {
    for (size_t i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0
           )
        {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}
static void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                            char *packet, UINT packetLen, PVOID packet_data,
                            UINT packet_dataLen, int packet_v4, int packet_v6,
                            PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                            PWINDIVERT_TCPHDR ppTcpHdr,
                            uint32_t fragment_size, int step) {
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
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) -
                packet_dataLen + fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) -
                packet_dataLen + fragment_size
            );
        packetLen = packetLen - packet_dataLen + fragment_size;
    }
    else if (step == 1) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) - fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) - fragment_size
            );
        memmove(packet_data,
                (char*)packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;
        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
    }
    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;
    WinDivertHelperCalcChecksums(
        packet, packetLen, &addr, 0
    );
    WinDivertSend(
        w_filter, packet,
        packetLen,
        NULL, &addr
    );
    memcpy(packet, packet_bak, orig_packetLen);
}
int main(int argc, char *argv[]) {
    static enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    bool debug_exit = false;
    int i, should_reinject = 1, should_recalc_checksum = 0;
    int sni_ok = 0;
    int opt;
    int packet_v4 = 0, packet_v6 = 0;
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
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;
    int do_passivedpi = 0, do_block_quic = 0,
        do_fragment_http = 0,
        do_fragment_http_persistent = 0,
        do_fragment_http_persistent_nowait = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_http_allports = 0,
        do_host_mixedcase = 0,
        do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
        do_dns_verb = 0, do_tcp_verb = 0, do_blacklist = 0,
        do_allow_no_sni = 0,
        do_fragment_by_sni = 0,
        do_fake_packet = 0,
        do_auto_ttl = 0,
        do_wrong_chksum = 0,
        do_wrong_seq = 0,
        do_native_frag = 0, do_reverse_frag = 0;
    uint32_t http_fragment_size = 0;
    uint32_t https_fragment_size = 0;
    uint32_t current_fragment_size = 0;
    uint16_t max_payload_size = 0;
    uint8_t should_send_fake = 0;
    uint8_t ttl_of_fake_packet = 0;
    uint8_t ttl_min_nhops = 0;
    uint8_t auto_ttl_1 = 0;
    uint8_t auto_ttl_2 = 0;
    uint8_t auto_ttl_max = 0;
    uint32_t dnsv4_addr = 0;
    struct in6_addr dnsv6_addr = {0};
    struct in6_addr dns_temp_addr = {0};
    uint16_t dnsv4_port = htons(53);
    uint16_t dnsv6_port = htons(53);
    char *host_addr, *useragent_addr, *method_addr;
    size_t host_len, useragent_len;
    int http_req_fragmented;
    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    size_t hdr_value_len;
    SetDllDirectory("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
    if (!running_from_service) {
        running_from_service = 1;
        if (service_register(argc, argv)) {
            return 0;
        }
        running_from_service = 0;
    }
    if (filter_string == NULL)
        filter_string = strdup(FILTER_STRING_TEMPLATE);
    if (filter_passive_string == NULL)
        filter_passive_string = strdup(FILTER_PASSIVE_STRING_TEMPLATE);
    printf(
        "GoodbyeDPI " GOODBYEDPI_VERSION
        ": Passive DPI blocker and Active DPI circumvention utility\n"
        "https://github.com/ValdikSS/GoodbyeDPI\n\n"
    );
    if (argc == 1) {
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
    }
    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:n", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace = do_fragment_http = do_fragment_https = do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace = do_fragment_http = do_fragment_https = do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace = do_fragment_https = 1;
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
            case '9':
                do_block_quic = 1;
            case '8':
                do_wrong_seq = 1;
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
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'z':
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                if (i != 80 && i != 443)
                    add_filter_str(IPPROTO_TCP, (uint16_t)i);
                i = 0;
                break;
            case 'i':
                i = atousi(optarg, "IP ID parameter error!\n");
                add_ip_id_str((uint16_t)i);
                i = 0;
                break;
            case 'd':
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
            case '!':
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
            case 'g':
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
            case '@':
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
            case 'b':
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case ']':
                do_allow_no_sni = 1;
                break;
            case '>':
                do_fragment_by_sni = 1;
                break;
            case '$':
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[':
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+':
                do_fake_packet = 1;
                do_auto_ttl = 1;
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg) {
                    char *autottl_copy = strdup(optarg);
                    char *autottl_save;
                    if (strchr(autottl_copy, '-')) {
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
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%':
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case ')':
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*':
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '(':
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '|':
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case 'u':
                if (fake_load_from_hex(optarg)) {
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                }
                break;
            case 'j':
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 't':
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                if (fakes_resend == 1)
                    puts("WARNING: fake-resend is 1, no resending is in place!");
                else if (!fakes_resend)
                    puts("WARNING: fake-resend is 0, fake packet mode is disabled!");
                else if (fakes_resend > 100)
                    puts("WARNING: fake-resend value is a little too high, don't you think?");
                break;
            case 'x':
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
    printf("Block passive: %d\n"
           "Block QUIC/HTTP3: %d\n"
           "Fragment HTTP: %u\n"
           "Fragment persistent HTTP: %u\n"
           "Fragment HTTPS: %u\n"
           "Fragment by SNI: %u\n"
           "Native fragmentation (splitting): %d\n"
           "Fragments sending in reverse: %d\n"
           "hoSt: %d\n"
           "Host no space: %d\n"
           "Additional space: %d\n"
           "Mix Host: %d\n"
           "HTTP AllPorts: %d\n"
           "HTTP Persistent Nowait: %d\n"
           "DNS redirect: %d\n"
           "DNSv6 redirect: %d\n"
           "Allow missing SNI: %d\n"
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"
           "Fake requests, wrong checksum: %d\n"
           "Fake requests, wrong SEQ/ACK: %d\n"
           "Fake requests, custom payloads: %d\n"
           "Fake requests, resend: %d\n"
           "Max payload size: %hu\n",
           do_passivedpi, do_block_quic,
           (do_fragment_http ? http_fragment_size : 0),
           (do_fragment_http_persistent ? http_fragment_size : 0),
           (do_fragment_https ? https_fragment_size : 0),
           do_fragment_by_sni,
           do_native_frag,
           do_reverse_frag,
           do_host,
           do_host_removespace,
           do_additional_space,
           do_host_mixedcase,
           do_http_allports,
           do_fragment_http_persistent_nowait,
           do_dnsv4_redirect,
           do_dnsv6_redirect,
           do_allow_no_sni,
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum,
           do_wrong_seq,
           fakes_count,
           fakes_resend,
           max_payload_size
          );
    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag) {
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    }
    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }
    if (max_payload_size)
        add_maxpayloadsize_str(max_payload_size);
    finalize_filter_strings();
    puts("\nOpening filter");
    filter_num = 0;
    if (do_passivedpi) {
        filters[filter_num] = init(
            filter_passive_string,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }
    if (do_block_quic) {
        filters[filter_num] = init(
            FILTER_PASSIVE_BLOCK_QUIC,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }
    filters[filter_num] = init(filter_string, 0);
    w_filter = filters[filter_num];
    filter_num++;
    for (i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }
    if (debug_exit) {
        printf("Debug Exit\n");
        exit(EXIT_SUCCESS);
    }
    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    while (1) {
        if (WinDivertRecv(w_filter, packet, sizeof(packet), &packetLen, &addr)) {
            should_reinject = 1;
            should_recalc_checksum = 0;
            sni_ok = 0;
            ppIpHdr = NULL;
            ppIpV6Hdr = NULL;
            ppTcpHdr = NULL;
            ppUdpHdr = NULL;
            packet_v4 = packet_v6 = 0;
            packet_type = unknown;
            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr, &packet_data, &packet_dataLen,
                NULL, NULL))
            {
                if (ppIpHdr) {
                    packet_v4 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv4_tcp;
                        if (packet_data) {
                            packet_type = ipv4_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv4_udp_data;
                    }
                }
                else if (ppIpV6Hdr) {
                    packet_v6 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv6_tcp;
                        if (packet_data) {
                            packet_type = ipv6_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv6_udp_data;
                    }
                }
            }
            if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) {
                if (!addr.Outbound && packet_dataLen > 16) {
                    if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        if (packet_v4) {
                            should_reinject = 0;
                        }
                        else if (packet_v6 && WINDIVERT_IPV6HDR_GET_FLOWLABEL(&ppIpV6Hdr) == 0x0) {
                                should_reinject = 0;
                        }
                    }
                }
                else if (addr.Outbound &&
                        ((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
                         packet_dataLen > 16) &&
                         ppTcpHdr->DstPort != htons(80) &&
                         (do_fake_packet || do_native_frag)
                        )
                {
                    if ((packet_dataLen == 2 && memcmp(packet_data, "\x16\x03", 2) == 0) ||
                        (packet_dataLen >= 3 && ( memcmp(packet_data, "\x16\x03\x01", 3) == 0 || memcmp(packet_data, "\x16\x03\x03", 3) == 0 )))
                    {
                        if (do_blacklist || do_fragment_by_sni) {
                            sni_ok = extract_sni(packet_data, packet_dataLen,
                                        &host_addr, &host_len);
                        }
                        if (
                             (do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len)
                             ) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (!do_blacklist)
                           )
                        {
                            if (do_fake_packet) {
                                TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
                            }
                            if (do_native_frag) {
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                }
                else if (addr.Outbound && 
                        packet_dataLen > 16 &&
                        (do_http_allports ? 1 : (ppTcpHdr->DstPort == htons(80))) &&
                        find_http_method_end(packet_data,
                                             (do_fragment_http ? http_fragment_size : 0u),
                                             &http_req_fragmented) &&
                        (do_host || do_host_removespace ||
                        do_host_mixedcase || do_fragment_http_persistent ||
                        do_fake_packet))
                {
                    if (find_header_and_get_info(packet_data, packet_dataLen,
                        http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                        hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                        (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
                    {
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;
                        if (do_native_frag) {
                            should_recalc_checksum = 1;
                        }
                        if (do_fake_packet) {
                            TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_http_request);
                        }
                        if (do_host_mixedcase) {
                            mix_case(host_addr, host_len);
                            should_recalc_checksum = 1;
                        }
                        if (do_host) {
                            memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                            should_recalc_checksum = 1;
                        }
                        if (do_additional_space && do_host_removespace) {
                            method_addr = find_http_method_end(packet_data,
                                                            (do_fragment_http ? http_fragment_size : 0),
                                                            NULL);
                            if (method_addr) {
                                memmove(method_addr + 1, method_addr,
                                        (size_t)(host_addr - method_addr - 1));
                                should_recalc_checksum = 1;
                            }
                        }
                        else if (do_host_removespace) {
                            if (find_header_and_get_info(packet_data, packet_dataLen,
                                                        http_useragent_find, &hdr_name_addr,
                                                         &hdr_value_addr, &useragent_len))
                            {
                                useragent_addr = hdr_value_addr;
                                useragent_len = useragent_len;
                                if (useragent_addr && useragent_len > 0) {
                                    if (useragent_addr > host_addr) {
                                        memmove(host_addr - 1, host_addr,
                                                (size_t)(useragent_addr + useragent_len - host_addr));
                                        host_addr -= 1;
                                        *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                        should_recalc_checksum = 1;
                                    }
                                    else {
                                        memmove(useragent_addr + useragent_len + 1,
                                                useragent_addr + useragent_len,
                                                (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                        *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                        should_recalc_checksum = 1;
                                    }
                                }
                            }
                        }
                    }
                }
                if (should_reinject && should_recalc_checksum && do_native_frag)
                {
                    current_fragment_size = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        current_fragment_size = http_fragment_size;
                    }
                    else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        if (do_fragment_by_sni && sni_ok) {
                            current_fragment_size = (void*)host_addr - packet_data;
                        } else {
                            current_fragment_size = https_fragment_size;
                        }
                    }
                    if (current_fragment_size) {
                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen,packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, do_reverse_frag);
                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen, packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, !do_reverse_frag);
                        continue;
                    }
                }
            }
            else if (packet_type == ipv4_tcp || packet_type == ipv6_tcp) {
                if (!addr.Outbound &&
                    ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1) {
                    if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                        if (!((packet_v4 && tcp_handle_incoming(ppIpHdr->SrcAddr, ppIpHdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        0, ppIpHdr->TTL))
                            ||
                            (packet_v6 && tcp_handle_incoming(ppIpV6Hdr->SrcAddr,
                                        ppIpV6Hdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        1, ppIpV6Hdr->HopLimit)))) {
                            if (do_tcp_verb)
                                puts("[TCP WARN] Can't add TCP connection record.");
                        }
                    }

                    if (!do_native_frag) {
                        if (do_fragment_http && ppTcpHdr->SrcPort == htons(80)) {
                            change_window_size(ppTcpHdr, http_fragment_size);
                            should_recalc_checksum = 1;
                        }
                        else if (do_fragment_https && ppTcpHdr->SrcPort != htons(80)) {
                            change_window_size(ppTcpHdr, https_fragment_size);
                            should_recalc_checksum = 1;
                        }
                    }
                }
            }
            else if ((do_dnsv4_redirect && (packet_type == ipv4_udp_data)) ||
                     (do_dnsv6_redirect && (packet_type == ipv6_udp_data))) {
                if (!addr.Outbound) {
                    if ((packet_v4 && dns_handle_incoming(ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 0))
                        ||
                        (packet_v6 && dns_handle_incoming(ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 1))) {
                        if (packet_v4)
                            ppIpHdr->SrcAddr = dns_conn_info.dstip[0];
                        else if (packet_v6)
                            ipv6_copy_addr(ppIpV6Hdr->SrcAddr, dns_conn_info.dstip);
                        ppUdpHdr->DstPort = dns_conn_info.srcport;
                        ppUdpHdr->SrcPort = dns_conn_info.dstport;
                        should_recalc_checksum = 1;
                    }
                    else {
                        if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
                            should_reinject = 0;

                        if (do_dns_verb && !should_reinject) {
                            printf("[DNS] Error handling incoming packet: srcport=%hu, dstport=%hu\n",
                               ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                        }
                    }
                }
                else if (addr.Outbound) {
                    if ((packet_v4 && dns_handle_outgoing(ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
                                        ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen, 0))
                        ||
                        (packet_v6 && dns_handle_outgoing(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
                                        ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen, 1))) {
                        if (packet_v4) {
                            ppIpHdr->DstAddr = dnsv4_addr;
                            ppUdpHdr->DstPort = dnsv4_port;
                        }
                        else if (packet_v6) {
                            ipv6_copy_addr(ppIpV6Hdr->DstAddr, (uint32_t*)dnsv6_addr.s6_addr);
                            ppUdpHdr->DstPort = dnsv6_port;
                        }
                        should_recalc_checksum = 1;
                    }
                    else {
                        if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
                            should_reinject = 0;

                        if (do_dns_verb && !should_reinject) {
                            printf("[DNS] Error handling outgoing packet: srcport=%hu, dstport=%hu\n",
                               ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                        }
                    }
                }
            }

            if (should_reinject) {
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
            }
        }
        else {
            if (!exiting)
                printf("Error receiving packet!\n");
            break;
        }
    }
}