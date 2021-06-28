/*******************************************************************************
 * dns.c
 *
 * Handles DNS packets
 *
 ******************************************************************************/

#include "dns.h"
#include "util.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define DEBUG

int init(char * table_fname, char * tld_fname, dns_is_t * instance)
{
    FILE * table_fp, * tld_fp;
    char * line;
    size_t len = 0;

    table_fp = fopen(table_fname, "r");
    tld_fp = fopen(tld_fname, "r");

    if (table_fp == NULL) 
    {
        perror("domain name table file not found.");
        exit(EXIT_FAILURE);
    }

    if (tld_fp == NULL) 
    {
        perror("tld config file not found.");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Domain Name Table\n");

    /* Read file and create domain name table */
    while (getline(&line, &len, table_fp) != -1)
    {
        char ** dname_pair = str_split(line, ',');
        fprintf(stdout, "%s\t%s", dname_pair[0], dname_pair[1]);
    }

    fclose(table_fp);
    fclose(tld_fp);

    return 0;
}

int handle_packet(char * request, dns_res_t * response)
{
    dns_hdr_t * raw_dns_hdr = (dns_hdr_t *) request;

    /* Create host discernible packet */
    dns_hdr_t * h_dns_hdr = (dns_hdr_t *)malloc(sizeof(dns_hdr_t));
    h_dns_hdr->id = ntohs(raw_dns_hdr->id);
    h_dns_hdr->flag.field = ntohs(raw_dns_hdr->flag.field);
    h_dns_hdr->total_qtn = ntohs(raw_dns_hdr->total_qtn);
    h_dns_hdr->total_ans = ntohs(raw_dns_hdr->total_ans);
    h_dns_hdr->total_auth = ntohs(raw_dns_hdr->total_auth);
    h_dns_hdr->total_add = ntohs(raw_dns_hdr->total_add);

#if defined (DEBUG)
    print_packet(h_dns_hdr);
#endif

    /* Ignore DNS message if QR is set */
    if (h_dns_hdr->flag.bits.qr == 1)
    {
        return 0;
    }

    /* Read query question */
    char * qtn_head = request + sizeof(dns_hdr_t);

    for (uint8_t i = 0; i < h_dns_hdr->total_qtn; i++) {
        dns_query_t * dq = (dns_query_t *)qtn_head;
        
    }

    return 0;
}

void print_packet(dns_hdr_t * h_dns_hdr) {
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