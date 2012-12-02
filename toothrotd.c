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
#include <getopt.h>

#include "version.h"
#ifndef VERSION
#define VERSION "(unknown, compiled from git)"
#endif

/* global options */
typedef struct {
    unsigned int verbose;
} options_t;

options_t opts;

static void print_help(FILE *output) {
    fprintf(output, "USAGE: toothrotd [OPTIONS]\n"
                    "  -v    --verbose      set verbosity level\n"
                    "  -V    --version      print program version\n"
                    "  -h    --help         print this help\n");
}

int main(int argc, char *argv[]) {
    const struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        { NULL, 0, 0, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "hvV", longopts, 0)) != -1) {
        switch (c) {
            case 'h': print_help(stdout);
                      exit(0);
                      break;
            case 'v': opts.verbose++;
                      break;
            case 'V': printf("toothrotd " VERSION ", compiled at " __DATE__ " " __TIME__ "\n");
                      exit(0);
                      break;
            case '?': print_help(stderr);
                      exit(1);
                      break;
        }
    }

}
