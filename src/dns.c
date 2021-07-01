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
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DEBUG

/**
 * Initialize DNS instance with the given file pointers
 */
int init(char * table_fname, char * tld_fname, dns_is_t * instance)
{
    FILE * table_fp, * tld_fp;

    /* Buffer config files */
    table_fp = fopen(table_fname, "r");
    tld_fp = fopen(tld_fname, "r");

    if (table_fp == NULL) 
    {
        perror("domain name table file not found");
        exit(EXIT_FAILURE);
    }

    if (tld_fp == NULL) 
    {
        perror("tld config file not found");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "Domain Name Table\n");

    /* Create DNS table */
    if (create_table(table_fp, instance) != 0)
    {
        fprintf(stderr, "Error: fail to create DNS table");
        exit(EXIT_FAILURE);
    }

    if (instance->table.list == NULL)
    {
        fprintf(stderr, "Error: DNS table is empty");
        exit(EXIT_FAILURE);
    }

    /* Debug print*/
    dname_entry_t * head = instance->table.list;
    while (head != NULL)
    {
        fprintf(stdout, "%s\n", head->name);
        head = head->next;
    }

    /* Load TLD name */
    if (load_tld_name(tld_fp, instance) != 0)
    {
        fprintf(stderr, "Error: fail to load TLD server name");
        exit(EXIT_FAILURE);
    }

    /* Debug print TLD name */
    fprintf(stdout, "TLD server name: %s\n", instance->name);

    fclose(table_fp);
    fclose(tld_fp);

    return 0;
}

/**
 * Create DNS table with given file pointer to static table
 */
int create_table(FILE * table_fp, dns_is_t * instance)
{
    char * line;
    size_t len = 0;
    uint8_t first_flag = 1;
    instance->table.len = 0;
    instance->table.list = NULL;

    /* Read file and create domain name table */
    while (getline(&line, &len, table_fp) != -1)
    {
        char ** dname_pair = str_split(line, ',');
        fprintf(stdout, "%s\t%s", dname_pair[0], dname_pair[1]);

        /* Skip the first line of CSV file */
        if (first_flag)
        {
            first_flag = 0;
            continue;
        }

        /* Create entry */
        dname_entry_t * new_entry = 
            (dname_entry_t *)malloc(sizeof(dname_entry_t));

        /* Copy the name */
        uint32_t name_len = strlen(dname_pair[0]);
        new_entry->name = (char *)malloc(name_len + 1);        
        memcpy(new_entry->name, dname_pair[0], name_len + 1);

        /* Convert string IP to unsigned int */
        str_trim(dname_pair[1]);

        if (inet_pton(AF_INET, dname_pair[1], &new_entry->ip_addr) != 1)
        {
            perror("DNS IP format error");
            exit(EXIT_FAILURE);
        }

        /* Insert new entry */
        new_entry->next = instance->table.list;
        instance->table.list = new_entry;
        instance->table.len++;
    }

    free(line);

    return 0;
}

/**
 * Load the TLD server name from the given TLD file pointer
 */
int load_tld_name(FILE * tld_fp, dns_is_t * instance)
{    
    /* Load TLD name */
    char * line;
    size_t len = 0;

    if (getline(&line, &len, tld_fp) != -1)
    {
        str_trim(line);
        len = strlen(line);
        instance->name = (char *)malloc(len + 1);
        memcpy(instance->name, line, len + 1);
    }
    else
    {
        perror("TLD name file read error");
        exit(EXIT_FAILURE);
    }

    free(line);

    return 0;
}

int handle_packet(dns_is_t * instance, char * request, dns_res_t * response)
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
    if (h_dns_hdr->flag.bits.qr == 1) return 0;

    /* Read query question */
    char * qtn_head = request + sizeof(dns_hdr_t);
    dname_table_t ** res_table_list = (dname_table_t **)\
        malloc(sizeof(dname_table_t *) * h_dns_hdr->total_qtn);

    for (uint8_t i = 0; i < h_dns_hdr->total_qtn; i++) {
        /* Get dname in the queries */
        char * dname = ((char *)qtn_head) + 1; /* Skip tab */
        char * dname_end = strchr(dname, '\03');
        *dname_end = '\0'; /* Replace with null char temporarily */ 
        char * tld_name = dname_end + 1;

        fprintf(stdout, "Query dname: %s.%s\n", dname, tld_name);

        /* Check if the tld query is meant for this instance */
        if (tldcmp(tld_name, instance) == 0)
        {
            /* Find dname matches */
            res_table_list[i] = match_hname(dname, instance);
        }
        else
        {
            /* Respond nothing */
        }

        /* Return null char */
        *dname_end = '\03';
    }

    /* Write response packet */


    return 0;
}

dns_hdr_t * create_res_packet(dns_hdr_t * og_dns_hdr,
                              char * data,
                              dname_table_t ** res_list)
{
    uint32_t total_ans = 0;
    uint32_t og_size = DNS_HEADER_SIZE;

    /* Count total answers and original packet length */
    for (uint32_t i = 0; i < og_dns_hdr->total_qtn; i++)
    {
        if (res_list[i]->len > 0) total_ans++;

        og_size += strlen(data) + 4; /* 4 bytes of type and class */
        data += strlen(data) + 4; /* Iterates */
    }

    fprintf(stdout, "Original packet length: %u\n", og_size);

    /* Calculate new packet length */
    uint32_t size = og_size + total_ans * sizeof(dns_rr_t);

    return 0;
}

/**
 * Compare input tld name to instance tld name
 */
uint8_t tldcmp(char * tld_name, dns_is_t * instance)
{
    uint32_t len = strlen(instance->name);
    
    if (len == strlen(tld_name))
        return strncmp(instance->name, tld_name, len);

    return 1;
}

/**
 * Lookup given dname in the DNS table
 * @param char * dname
 * @param dns_is_t * instance
 * @return List of dname entries
 */
dname_table_t * match_hname(char * dname, dns_is_t * instance)
{
    dname_entry_t * head = instance->table.list;
    dname_table_t * result = (dname_table_t *)malloc(sizeof(dname_table_t));
    result->list = NULL;
    result->len = 0;

    /* Lookup */
    while (head != NULL)
    {
        uint32_t len = strlen(head->name);
        uint32_t dname_len = strlen(dname);

        if (len != dname_len) 
        {
            head = head->next;
            continue;
        }

        if (strncmp(dname, head->name, len) == 0)
        {
            /* Create a copy of the entry if matches */
            dname_entry_t * new_entry =
                (dname_entry_t *)malloc(sizeof(dname_entry_t));

            new_entry->ip_addr = head->ip_addr;
            new_entry->name = head->name;
            new_entry->next = result->list;

            /* Insert */
            result->list = new_entry;
        }

        head = head->next;
    }

    return result;
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