#ifndef DNS_C
#define DNS_C

#include <stdint.h>
#include <stdio.h>

#define DNS_HEADER_SIZE 12 /* 12 bytes */

/* Little Endian for Linux */
union dns_flag {
    struct {
        uint16_t ret_code: 4;
        uint16_t cd: 1; /* Checking disabled */
        uint16_t ad: 1; /* Authenticated data */
        uint16_t ra: 1; /* Recursion available */
        uint16_t z: 1;
        uint16_t rd: 1; /* Recursion desired */
        uint16_t truncated: 1;
        uint16_t auth_ans: 1;
        uint16_t opcode: 4;
        uint16_t qr: 1;
    } __attribute__ ((packed)) bits;
    uint16_t field;
};
typedef union dns_flag dns_flag_t;

/* DNS header structure according to RFC sourcebook */
struct dns_hdr {
    uint16_t id;
    dns_flag_t flag;
    uint16_t total_qtn; /* Total questions returned */
    uint16_t total_ans; /* Total answers in resource record list */
    uint16_t total_auth; /* Total authority in resource record list */
    uint16_t total_add; /* Total addition in resource record list */
} __attribute__ ((packed));
typedef struct dns_hdr dns_hdr_t; 

/* DNS query structure according to RFC sourcebook */
struct dns_query {
    uint16_t name;
    uint8_t type;
    uint8_t ip_class;
} __attribute__ ((packed));
typedef struct dns_query dns_query_t;

/* DNS responds structure according to RFC sourcebook */
struct dns_res {
    char * packet;
    uint16_t length;
} __attribute__ ((packed));
typedef struct dns_res dns_res_t;

/* Domain Name Entry */
struct dname_entry {
    char * name;
    uint32_t ip_addr;
    struct dname_entry * next;
};
typedef struct dname_entry dname_entry_t;

/* DNS instance */
struct dns_is {
    char * name; /* TLD name */
    dname_entry_t * dname_table;
};
typedef struct dns_is dns_is_t;

int init(char *, char *, dns_is_t *);
int create_table(FILE *, dns_is_t *);
int load_tld_name(FILE *, dns_is_t *);
int handle_packet(char * request, dns_res_t * response);
void print_packet(dns_hdr_t *);

#endif