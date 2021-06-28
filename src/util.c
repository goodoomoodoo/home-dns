#include "util.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

void str_trim(char * str)
{
    uint8_t start_flag, end_flag;
    int len;

    start_flag = end_flag = 0;

    /* Remove leading spaces and count string length */
    for (uint32_t i = 0; str[i] != '\0'; i++)
    {
        if (start_flag)
            len++;
        else
        {
            if (isspace(str[i]) == 0)
                start_flag = 1;
            else
                str++; /* Count string length */
        }
    }

    /* Remove tailing spaces */
    for (int i = len; i >= 0 && isspace(str[i]) != 0; i--)
    {
        str[i] = '\0';
    }
}

/**
 * Create an array of string by spliting the given string by the delimiter
 * @param char * str
 * @param char delimiter
 * @return Array of string
 */
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