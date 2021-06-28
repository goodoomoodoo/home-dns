#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>

void str_trim(char *);
char ** str_split(char *, char);
uint32_t str_count(char *, char);

#endif