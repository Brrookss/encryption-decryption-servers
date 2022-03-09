#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "enc_client.h"
#include "libotp.h"

/**
 * Driver for encryption client. Arguments are first verified before an attempt to connect 
 * to the server is made. Once connection is authenticated, plaintext and key are sent to
 * be encrypted. The resulting ciphertext is then sent to stdout
 */
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <plaintext file> <key file> <port>\n", argv[0]);
        exit(1);
    }

    char *cwd, *plaintext, *plaintext_sep, *key, *auth, *message, *message_term, *ciphertext;
    int plaintext_fd, key_fd, sock_fd;
    struct sockaddr_in server_address;

    cwd = (char*)calloc(PATH_BUFFER_SIZE, sizeof(char));
    getcwd(cwd, PATH_BUFFER_SIZE);

    plaintext_fd = getFileDesc(cwd, argv[1]);
    key_fd = getFileDesc(cwd, argv[2]);

    free(cwd);
    cwd = NULL;

    if (!locatedFile(plaintext_fd) || !locatedFile(key_fd))
        exit(1);

    plaintext = getFileData(plaintext_fd);
    key = getFileData(key_fd);

    if (!allowedChars(plaintext) || !allowedChars(key) || !sufficientLength(key, strlen(plaintext))) {
        free(plaintext); plaintext = NULL;
        free(key); key = NULL;
        exit(1);
    }

    initAddressStruct(&server_address, LOCALHOST, atoi(argv[3]));
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    auth = concatenate(ENC_AUTH_MESSAGE, MESSAGE_SEPERATOR);

    if (!makeSocketConnection(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) || !sendMessage(sock_fd, auth) || !authenticated(sock_fd, auth)) {
        free(plaintext); plaintext = NULL;
        free(key); key = NULL;
        free(auth); auth = NULL;
        exit(2);
    }

    plaintext_sep = concatenate(plaintext, MESSAGE_SEPERATOR);
    message = concatenate(plaintext_sep, key);
    message_term = concatenate(message, MESSAGE_TERMINATOR);
    sendMessage(sock_fd, message_term);

    ciphertext = getResponse(sock_fd);
    close(sock_fd);
    puts(ciphertext);

    free(plaintext); plaintext = NULL;
    free(plaintext_sep); plaintext_sep = NULL;
    free(key); key = NULL;
    free(message); message = NULL;
    free(message_term); message_term = NULL;
    free(auth); auth = NULL;
    free(ciphertext); ciphertext = NULL;
    exit(0);
}