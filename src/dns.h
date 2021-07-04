#ifndef DNS_C
#define DNS_C

#include <stdint.h>
#include <stdio.h>

#define DNS_HEADER_SIZE 12 /* 12 bytes */
#define PTR_MASK 0xC000 /* Leading 2 bits are 1s */
#define A_TYPE 1 /* DNS IPv4 type code */
#define IN_CLASS 1 /* DNS class code */

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

/* Resource Record structure according to RFC sourcebook */
struct dns_rr {
    uint16_t pointer;
    uint16_t type;
    uint16_t nclass;
    uint32_t ttl;
    uint16_t rdata_len;
    uint32_t ip_addr;
} __attribute__((packed));
typedef struct dns_rr dns_rr_t;

/* DNS response structure */
struct dns_res {
    char * packet;
    uint16_t length;
};
typedef struct dns_res dns_res_t;

/* Domain Name Entry */
struct dname_entry {
    char * name;
    uint32_t ip_addr;
    struct dname_entry * next;
};
typedef struct dname_entry dname_entry_t;

/* Domain Name Table */
struct dname_table{
    size_t len;
    uint16_t offset; /* Offset of the corresponding query */
    dname_entry_t * list;
};
typedef struct dname_table dname_table_t;

/* DNS instance */
struct dns_is {
    char * name; /* TLD name */
    dname_table_t table; /* This table */
};
typedef struct dns_is dns_is_t;

int init(char *, char *, dns_is_t *);
int create_table(FILE *, dns_is_t *);
int load_tld_name(FILE *, dns_is_t *);
int handle_packet(dns_is_t *, char * request, dns_res_t * response);
void create_res_packet(dns_hdr_t *, char *, dname_table_t **, dns_res_t *);
uint8_t tldcmp(char *, dns_is_t *);
dname_table_t * match_hname(char * dname, dns_is_t *);
void print_rr(dns_rr_t *);
void print_packet(dns_hdr_t *);

#endif