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

    for (uint16_t i = 0; i < h_dns_hdr->total_qtn; i++)
    {
        /* Initialize response table */
        res_table_list[i] = NULL;

        /* Get dname in the queries */
        uint8_t * dname_len = (uint8_t *)qtn_head;

        /* Check if the query name is root */
        if (*dname_len == 0)
        {
            qtn_head++;
            continue;
        }
        
        char * temp = qtn_head + 1; /* Skip length */
        char * dname = (char *)malloc(*dname_len + 1);
        
        /* Copy string and add terminator */
        memcpy(dname, temp, *dname_len);
        dname[*dname_len] = '\0';

        /* Get TLD name */
        temp += *dname_len; /* Move pointer to next length */
        uint8_t * tld_len = (uint8_t *)temp;
        temp++; /* Move over the length */
        char * tld_name = (char *)malloc(*tld_len + 1);

        /* Copy string and add terminator */
        memcpy(tld_name, temp, *tld_len);
        tld_name[*tld_len + 1] = '\0';

        fprintf(stdout, "Query dname: %s.%s\n", dname, tld_name);

        /* Check if the tld query is meant for this instance */
        if (tldcmp(tld_name, instance) == 0)
        {
            /* Find dname matches */
            res_table_list[i] = match_hname(dname, instance);

            /* Assign query offset */
            res_table_list[i]->offset = (qtn_head - request);
        }
        else
        {
            /* Respond nothing */
        }

        /* Iterate to next data */
        qtn_head += (strlen(qtn_head) + 1) + 4; /* 4 bytes of type and class */
    }

    /* Write response packet */
    create_res_packet(h_dns_hdr, request + sizeof(dns_hdr_t), res_table_list,
                      response);

    /* TODO: delete table */
    return 0;
}

/**
 * Create response packet, returns packet by writing into the dns_res_t pointer
 * @param dns_hdr_t * og_dns_hdr Original Header
 * @param char * og_data Original Data Section
 * @param dname_table_t ** res_list List of matching domain name
 * @param dns_res_t * response Output Pointer
 */
void create_res_packet(dns_hdr_t * og_dns_hdr,
                       char * og_data,
                       dname_table_t ** res_list,
                       dns_res_t * response) {
    uint32_t total_ans = 0;
    uint32_t og_size = 0;
    uint8_t * temp_len;

    /* Count total answers and original packet length */
    char * queries = og_data;

    for (uint32_t i = 0; i < og_dns_hdr->total_qtn; i++) {
        /* Skip if the table is empty */
        if (res_list[i] != NULL && res_list[i]->len > 0) total_ans++;

        /* Iterates through query name */
        while (*queries != '\0') {
            temp_len = (uint8_t *)queries;
            og_size += *temp_len + 1;
            queries += *temp_len + 1;
        }

        og_size += (4 + 1); /* 4 bytes of type and class and 1 null char */
        queries += (4 + 1); /* Iterates */
    }

    fprintf(stdout, "Original packet length: %u\n", og_size + DNS_HEADER_SIZE);

    /* Calculate new packet length */
    uint32_t size = DNS_HEADER_SIZE + og_size + total_ans * sizeof(dns_rr_t);

    fprintf(stdout, "Response packet length: %u\n", size);

    /* New packet */
    response->packet = (char *)malloc(size);
    response->length = size;
    dns_hdr_t *new_hdr = (dns_hdr_t *)response->packet;

    new_hdr->id = htons(og_dns_hdr->id);
    new_hdr->flag.field = 0; /* Clear field */
    new_hdr->flag.bits.qr = 1; /* Set response */
    new_hdr->flag.field = htons(new_hdr->flag.field); /* Convert to net */
    new_hdr->total_qtn = htons(og_dns_hdr->total_qtn);
    new_hdr->total_auth = 0; /* Clear field */
    new_hdr->total_ans = htons(total_ans);
    new_hdr->total_add = 0; /* Clear field */

    /* Copy data */
    memcpy(response->packet + DNS_HEADER_SIZE, og_data, og_size);

    char *ans_rr_ptr = response->packet + DNS_HEADER_SIZE + og_size;

    /* Copy answers */
    for (uint32_t i = 0; i < og_dns_hdr->total_qtn; i++) {
        dname_table_t *curr = res_list[i];

        /* Skip if table is empty */
        if (curr != NULL) {
        /* Create struct */
        dns_rr_t new_rr = {
            .pointer = htons(curr->offset | PTR_MASK),
            .type = htons(A_TYPE),
            .nclass = htons(IN_CLASS),
            .ttl = htonl(300), /* Time to live 5 minutes */
            .rdata_len = htons(sizeof(in_addr_t)),
            .ip_addr = curr->list->ip_addr,
        };

        print_rr(&new_rr);

        /* Copy to answer section */
        memcpy(ans_rr_ptr, &new_rr, size);
        }
    }
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
            result->len++;
            result->list = new_entry;
        }

        head = head->next;
    }

    return result;
}

void print_packet(dns_hdr_t * h_dns_hdr) {
    dns_flag_t * flag = malloc(sizeof(dns_flag_t));
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

    free(flag);
}

/**
 * Print resource records that are in net format
 * @param dns_rr_t * rr
 */
void print_rr(dns_rr_t * rr)
{
    uint32_t ip_string_size = 16;
    char * ip_addr = (char *)malloc(ip_string_size);
    inet_ntop(AF_INET, &rr->ip_addr, ip_addr, ip_string_size);

    fprintf(stdout, "RR Pointer: %x\n", htons(rr->pointer));
    fprintf(stdout, "RR Type: %x\n", htons(rr->type));
    fprintf(stdout, "RR Class: %x\n", htons(rr->nclass));
    fprintf(stdout, "RR TTL: %u\n", htons(rr->ttl));
    fprintf(stdout, "RR Rdata Length: %u\n", htons(rr->rdata_len));
    fprintf(stdout, "RR IP: %s\n", ip_addr);

    free(ip_addr);
}