/*
 * toothrot - log source of packets matching a pcap filter expression to syslog
 *
 * (c) by Alexander Neumann <alexander@bumpern.de>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <err.h>
#include <stdint.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <pcap/pcap.h>

#include "version.h"
#ifndef VERSION
#define VERSION "(unknown, compiled from git)"
#endif

#ifdef LINKTYPE_ETHERNET
#error "LINKTYPE_ETHERNET already defined!"
#else
#define LINKTYPE_ETHERNET 1
#define OFFSET_ETHERNET 14
#define ETH_TYPE_IP4 0x0008
#endif

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN   0xffffffff
#endif

/* define macros for verbose output */
#define LOG(level, format, args...) { \
        if (opts.verbose >= level) printf(format, ## args); \
        syslog(LOG_DAEMON | LOG_NOTICE, format, ## args); \
    }

typedef struct {
    /* ethernet */
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;

    /* ip4 */
    uint8_t version_and_len;
    uint8_t dsf;
    uint16_t len;
    uint16_t id;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
} eth_hdr_ip4_t;

/* global options */
typedef struct {
    int verbose;
    char *filter;
    char *interface;
    bool promisc;
    unsigned int snap;
    int offset;
} options_t;

options_t opts;

#define DEFAULT_FILTER "ip and igmp and igmp[0] = 0x11 and not src 137.226.144.1"
#define DEFAULT_INTERFACE "eth0"

static void print_help(FILE *output) {
    fprintf(output, "USAGE: toothrotd [OPTIONS]\n"
                    "  -i    --interface    set listen interface\n"
                    "  -f    --filter       set filter expression\n"
                    "                       (default: " DEFAULT_FILTER ")\n"
                    "  -p    --no-promisc   disable promiscuous mode\n"
                    "                       (default: on)\n"
                    "  -s    --snaplen      set snaplen in byte\n"
                    "                       (default: 100)\n"
                    "  -v    --verbose      set verbosity level\n"
                    "  -V    --version      print program version\n"
                    "  -h    --help         print this help\n");
}

static void exit_handler(int sig) {
    LOG(0, "signal %d received, exiting\n", sig);
    exit(0);
}

int main(int argc, char *argv[]) {
    const struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"interface", required_argument, 0, 'i'},
        {"filter", required_argument, 0, 'f'},
        {"snaplen", required_argument, 0, 's'},
        { NULL, 0, 0, 0 }
    };

    /* init options */
    opts.promisc = true;
    opts.interface = DEFAULT_INTERFACE;
    opts.filter = DEFAULT_FILTER;
    opts.snap = 100;

    /* parse options */
    int c;
    while ((c = getopt_long(argc, argv, "hvVi:f:ps:", longopts, 0)) != -1) {
        switch (c) {
            case 'h': print_help(stdout);
                      exit(0);
                      break;
            case 'v': opts.verbose++;
                      break;
            case 'V': printf("toothrotd " VERSION ", compiled at " __DATE__ " " __TIME__ "\n");
                      exit(0);
                      break;
            case 'i': opts.interface = optarg;
                      break;
            case 'f': opts.filter = optarg;
                      break;
            case 's': opts.snap = atoi(optarg);
                      break;
            case '?': print_help(stderr);
                      exit(1);
                      break;
        }
    }

    if (optind < argc) {
        print_help(stderr);
        exit(1);
    }

    /* initialize syslog */
    openlog("toothrotd", LOG_PID, LOG_USER);

    /* trap sigint and sigterm */
    signal(SIGQUIT, exit_handler);
    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);

    LOG(1, "listening on interface \"%s\" with filter \"%s\"\n", opts.interface, opts.filter);

    pcap_t *handle;
    struct bpf_program filter;
    char *errbuf = malloc(PCAP_ERRBUF_SIZE);

    if (errbuf == NULL) {
        LOG(0, "malloc() error\n");
        exit(1);
    }

    /* open device */
    if ((handle = pcap_open_live(opts.interface, opts.snap,
                                 opts.promisc, 1000, errbuf)) == NULL) {
        LOG(0, "unable to open device %s for capture: %s", opts.interface, errbuf);
        exit(2);
    }

    /* check data line type */
    int linktype;
    switch (linktype = pcap_datalink(handle)) {
        case LINKTYPE_ETHERNET:
            opts.offset = OFFSET_ETHERNET;
            break;

        default:
            LOG(0, "unknown link type %d\n", linktype);
            exit(1);
    }

    /* compile filter */
    if ((pcap_compile(handle, &filter, opts.filter, 0, PCAP_NETMASK_UNKNOWN)) < 0) {
        LOG(0, "error compiling filter expression \"%s\": %s\n", opts.filter, pcap_geterr(handle));
        exit(3);
    }

    /* activate filter */
    if (pcap_setfilter(handle, &filter) < 0) {
        LOG(0, "error activating filter: %s\n", opts.filter);
        exit(4);
    }

    struct pcap_pkthdr *header = malloc(sizeof(struct pcap_pkthdr));
    if (header == NULL) {
        LOG(0, "malloc() error\n");
        exit(1);
    }

    const unsigned char *packet;

    /* capture packets */
    while(1) {
        int ret;
        if ( (ret = pcap_next_ex(handle, &header, &packet)) < 0) {
            LOG(0, "error receiving packet: %s\n", pcap_geterr(handle));
            exit(5);
        }

        if (ret == 0) {
            /* timeout */
            continue;
        }

        eth_hdr_ip4_t *ip_packet = (eth_hdr_ip4_t *)packet;
        char line[1000];

        snprintf(line, sizeof(line),
            "rogue packet received: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
            ip_packet->src_mac[0],
            ip_packet->src_mac[1],
            ip_packet->src_mac[2],
            ip_packet->src_mac[3],
            ip_packet->src_mac[4],
            ip_packet->src_mac[5],
            ip_packet->dst_mac[0],
            ip_packet->dst_mac[1],
            ip_packet->dst_mac[2],
            ip_packet->dst_mac[3],
            ip_packet->dst_mac[4],
            ip_packet->dst_mac[5]);

        if (ip_packet->type == ETH_TYPE_IP4) {
            snprintf(&line[strlen(line)], sizeof(line)-strlen(line),
                ", IPv4: %d.%d.%d.%d -> %d.%d.%d.%d\n",
                ip_packet->src[0],
                ip_packet->src[1],
                ip_packet->src[2],
                ip_packet->src[3],
                ip_packet->dst[0],
                ip_packet->dst[1],
                ip_packet->dst[2],
                ip_packet->dst[3]);
        } else {
            snprintf(&line[strlen(line)], sizeof(line)-strlen(line), "\n");
        }
        LOG(0, line);
    }
}
