#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "dec_server.h"
#include "libotp.h"

/**
 * Driver for decryption server.
 * 
 * Server is started up by binding and listening at the given port for
 * connection attempts which are then handed off to child processes for client
 * authentication, message reception, and decryption.
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    int sock_fd;
    int client_sock_fd;
    int num_processes;
    struct sockaddr_in address, client_address;
    socklen_t client_address_size;
    pid_t pid;

    initAddressStruct(&address, LOCALHOST, atoi(argv[1]));
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    client_address_size = sizeof(client_address);
    num_processes = 0;

    if (!connectSocket(sock_fd, (struct sockaddr*)&address))
        exit(2);
    
    while (1) {
        do {
            if (waitpid(-1, NULL, WNOHANG) > 0)
                num_processes--;
        } while (num_processes > MAX_CONCURRENT_PROCESSES);

        client_sock_fd = connectClient(
            sock_fd, (struct sockaddr*)&address, &client_address_size
        );
        if (connected(client_sock_fd)) {
            pid = fork();
            switch (pid) {
                case -1:
                    perror("fork()");
                    break;
                case 0:
                    handleConnection(client_sock_fd);
                    break;
                default:
                    num_processes++;
                    break;
            }
        }
    }
    close(sock_fd);
    exit(0);
}

/**
 * Combines ciphertext and key to create a decrypted message.
 */
char* decryptMessage(const char* ciphertext, const char* key, char* buffer) {
    int i;
    int j;
    int k;
    int deciphered;

    i = 0;
    while (ciphertext[i]) {
        // 26 is space character in ALLOWED_CHARS
        j = (ciphertext[i] != ' ') ? ciphertext[i] - 65 : 26;
        k = (key[i] != ' ') ? key[i] - 65 : 26;
        deciphered = (j - k < 0) ? j - k + sizeof(ALLOWED_CHARS) : j - k;
        deciphered %= sizeof(ALLOWED_CHARS);
        buffer[i++] = ALLOWED_CHARS[deciphered];
    }
    return buffer;
}

/**
 * Handles client connection.
 * 
 * Client is first authenticated before getting response message composed of
 * ciphertext and key to be used for decryption; resulting plaintext message is
 * sent back to client and socket connection is closed.
 */
void handleConnection(int sock_fd) {
    char* auth;
    char* response;
    char* ciphertext;
    char* key;
    char* plaintext;
    char* plaintext_term;
    int ciphertext_len;
    int key_len;

    if (!authenticate(sock_fd, DEC_AUTH_MESSAGE)) {
        auth = concatenate(NAK, MESSAGE_TERMINATOR);
        sendMessage(sock_fd, auth);
        close(sock_fd);

        free(auth);
        auth = NULL;
        _exit(2);
    }
    auth = concatenate(ACK, MESSAGE_SEPERATOR);
    sendMessage(sock_fd, auth);

    response = getResponse(sock_fd);
    ciphertext_len = getTextLength(response);
    ciphertext = (char*)calloc(ciphertext_len + 1, sizeof(char));
    getText(response, ciphertext);

    key_len = getKeyLength(response);
    key = (char*)calloc(key_len + 1, sizeof(char));
    getKey(response, key);

    plaintext = (char*)calloc(ciphertext_len + 1, sizeof(char));
    decryptMessage(ciphertext, key, plaintext);
    plaintext_term = concatenate(plaintext, MESSAGE_TERMINATOR);
    sendMessage(sock_fd, plaintext_term);
    close(sock_fd);

    free(ciphertext);
    ciphertext = NULL;
    free(key);
    key = NULL;
    free(plaintext);
    plaintext = NULL;
    free(plaintext_term);
    plaintext_term = NULL;
    _exit(0);
}