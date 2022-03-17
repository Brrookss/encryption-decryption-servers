#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dec_client.h"
#include "libotp.h"

/**
 * Driver for decryption client. Arguments are first verified before an attempt to connect 
 * to the server is made. Once connection is authenticated, ciphertext and key are sent to
 * be decrypted. The resulting plaintext is then sent to stdout
 */
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ciphertext file> <key file> <port>\n", argv[0]);
        exit(1);
    }

    char* cwd;
    char* ciphertext;
    char* ciphertext_sep;
    char* key;
    char* auth;
    char* message;
    char* message_term;
    char* plaintext;
    int ciphertext_fd;
    int key_fd;
    int sock_fd;
    struct sockaddr_in server_address;

    cwd = (char*)calloc(PATH_BUFFER_SIZE, sizeof(char));
    getcwd(cwd, PATH_BUFFER_SIZE);

    ciphertext_fd = getFileDesc(cwd, argv[1]);
    key_fd = getFileDesc(cwd, argv[2]);

    free(cwd);
    cwd = NULL;

    if (!locatedFile(ciphertext_fd) || !locatedFile(key_fd))
        exit(1);

    ciphertext = getFileData(ciphertext_fd);
    key = getFileData(key_fd);

    if (!allowedChars(ciphertext) || !allowedChars(key) || !sufficientLength(key, strlen(ciphertext))) {
        free(ciphertext);
        ciphertext = NULL;
        free(key);
        key = NULL;
        exit(1);
    }

    initAddressStruct(&server_address, LOCALHOST, atoi(argv[3]));
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    auth = concatenate(DEC_AUTH_MESSAGE, MESSAGE_SEPERATOR);

    if (!makeSocketConnection(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) || !sendMessage(sock_fd, auth) || !authenticated(sock_fd, auth)) {
        free(ciphertext);
        ciphertext = NULL;
        free(key);
        key = NULL;
        free(auth);
        auth = NULL;
        exit(2);
    }

    ciphertext_sep = concatenate(ciphertext, MESSAGE_SEPERATOR);
    message = concatenate(ciphertext_sep, key);
    message_term = concatenate(message, MESSAGE_TERMINATOR);
    sendMessage(sock_fd, message_term);

    plaintext = getResponse(sock_fd);
    close(sock_fd);
    puts(plaintext);

    free(ciphertext);
    ciphertext = NULL;
    free(ciphertext_sep);
    ciphertext_sep = NULL;
    free(key);
    key = NULL;
    free(message);
    message = NULL;
    free(message_term);
    message_term = NULL;
    free(auth);
    auth = NULL;
    free(plaintext);
    plaintext = NULL;
    exit(0);
}