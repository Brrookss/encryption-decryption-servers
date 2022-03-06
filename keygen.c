#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "libotp.h"
#include "keygen.h"

/**
 * Creates a secret key based on the length argument and the allowed character
 * set before sending it to stdout
 */
int main(int argc, char* argv[]) {
    if (argc != 2 || atoi(argv[1]) <= 0) {
        fprintf(stderr, "Usage: %s <length>\n", argv[0]);
        return 1;
    }

    int len;
    char *key;

    len = atoi(argv[1]);
    key = generateKey(len);
    printf("%s", key);

    free(key);
    key = NULL;
    return 0;
}

/**
 * Creates a secret key of size len composed of characters from the allowed
 * character set, each chosen using rand(), followed by a newline character
 */
char* generateKey(int len) {
    if (len <= 0) {
        fprintf(stderr, "generateKey(): Insufficient key length\n");
        return NULL;
    }

    char c, *buffer;
    int i, num;

    srand(time(NULL));
    buffer = (char*)calloc(len + 2, sizeof(char));
    i = 0;
    
    while (i < len) {
        num = rand() % sizeof(ALLOWED_CHARS);
        c = ALLOWED_CHARS[num];
        buffer[i++] = c;
    }
    buffer[i] = '\n';
    return buffer;
}