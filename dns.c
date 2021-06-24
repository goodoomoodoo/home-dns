/*******************************************************************************
 * dns.c
 *
 * Handles DNS packets
 *
 ******************************************************************************/

#include "dns.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define DEBUG

int handle_packet(char * request, dns_res_t * response)
{
    dns_hdr_t * raw_dns_hdr = (dns_hdr_t *) request;
    dns_hdr_t * h_dns_hdr = (dns_hdr_t *)malloc(sizeof(dns_hdr_t));

    h_dns_hdr->id = ntohs(raw_dns_hdr->id);
    h_dns_hdr->flag.field = ntohs(raw_dns_hdr->flag.field);
    h_dns_hdr->total_qtn = ntohs(raw_dns_hdr->total_qtn);
    h_dns_hdr->total_ans = ntohs(raw_dns_hdr->total_ans);
    h_dns_hdr->total_auth = ntohs(raw_dns_hdr->total_auth);
    h_dns_hdr->total_add = ntohs(raw_dns_hdr->total_add);

#if defined (DEBUG)
    printPacket(h_dns_hdr);
#endif

    return 0;
}

void printPacket(dns_hdr_t * h_dns_hdr) {
    dns_flag_t *flag = malloc(sizeof(dns_flag_t));
    flag->field = h_dns_hdr->flag.field;

    fprintf(stdout, "DNS ID: %x\n", h_dns_hdr->id);
    fprintf(stdout, "DNS Query/Response: %u\n", flag->bits.qr);
    fprintf(stdout, "DNS OpCode: %u\n", flag->bits.opcode);
    fprintf(stdout, "AA: %u, TC: %u, RD: %u, RA: %u, AD: %u, CD: %u, Z: %u\n",
            flag->bits.auth_ans, flag->bits.truncated, flag->bits.rd,
            flag->bits.ra, flag->bits.ad, flag->bits.cd, flag->bits.z);
    fprintf(stdout, "DNS Return Code: %u\n", flag->bits.ret_code);
    fprintf(stdout, "DNS Total Questions: %d\n", h_dns_hdr->total_qtn);
    fprintf(stdout, "DNS Total Answers: %hu\n", h_dns_hdr->total_ans);
    fprintf(stdout, "DNS Total Authority: %hu\n", h_dns_hdr->total_auth);
    fprintf(stdout, "DNS Total Additional: %hu\n", h_dns_hdr->total_add);
}