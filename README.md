Introduction
============

This daemon logs packets that match a bpf (libpcap) filter expression to stdout
and syslog. It can, for example, be used to detect rogue IGMP querier devices
on the network attached to eth0 when called as follows:

    # ./toothrotd -i eth0 -f "ip and igmp and igmp[0] = 0x11 and not src 137.226.144.1"

New connections can be logged like this:

    # ./toothrotd -i eth0 -f "tcp and tcp[tcpflags] == tcp-syn"

Compile
=======

Prerequisites:
 * libpcap-dev

Compile the code by calling `make`:

    $ make
    cc -g -Wall -std=gnu99 -O2   -c -o toothrotd.o toothrotd.c


