#include "util.h"
#include <stdint.h>
#include <stdlib.h>

char ** str_split(char * str, char delimiter)
{
    uint32_t arr_len;
    char ** str_arr;

    arr_len = str_count(str, delimiter);

    /* Create array */
    if (arr_len > 0) 
        str_arr = malloc(sizeof(char **) * arr_len);
    else
        return NULL; /* Nothing to split */

    /* Spliting */
    uint32_t arr_idx = 0;
    str_arr[arr_idx] = str;

    for (uint32_t i = 0; str[i] != '\0'; i++)
    {
        if (str[i] == delimiter)
        {
            str[i] = '\0';
            str_arr[++arr_idx] = &str[i + 1];
        }
    }

    return str_arr;
}

/**
 * Count the number of character c in the given string
 * @param char * str - Given
 * @param char c - Target
 * @return Number of character c in the string 
 */
uint32_t str_count(char * str, char c)
{
    uint32_t count = 0;

    for (uint32_t i = 0; str[i] != '\0'; i++)
    {
        if (str[i] == c) count++;
    }

    return count;
}