#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "enc_server.h"
#include "libotp.h"

/**
 * Driver for encryption server. Server is started up by binding and listening at the given port for
 * connection attempts which are then handed off to child processes for client authentication, message
 * reception, and encryption
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    int sock_fd, client_sock_fd, num_processes;
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

        client_sock_fd = connectClient(sock_fd, (struct sockaddr*)&address, &client_address_size);
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
 * Combines plaintext and key to create an encrypted message and stores in buffer
 */
char* encryptMessage(const char* plaintext, const char* key, char* buffer) {
    int i, j, k, ciphered;

    i = 0;
    while (plaintext[i]) {
        j = (plaintext[i] != ' ') ? plaintext[i] - 65 : 26;  // 26 is space character in ALLOWED_CHARS
        k = (key[i] != ' ') ? key[i] - 65 : 26;
        ciphered = (j + k) % sizeof(ALLOWED_CHARS);
        buffer[i++] = ALLOWED_CHARS[ciphered];
    }
    return buffer;
}

/**
 * Client is first authenticated before getting response message composed of plaintext and key to be used
 * for encryption; resulting encrypted message is sent back to client and socket connection is closed
 */
void handleConnection(int sock_fd) {
    char *auth, *response, *plaintext, *key, *ciphertext, *ciphertext_term;
    int plaintext_len, key_len;

    if (!authenticate(sock_fd, ENC_AUTH_MESSAGE)) {
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
    plaintext_len = getTextLength(response);
    plaintext = (char*)calloc(plaintext_len + 1, sizeof(char));
    getText(response, plaintext);

    key_len = getKeyLength(response);
    key = (char*)calloc(key_len + 1, sizeof(char));
    getKey(response, key);

    ciphertext = (char*)calloc(plaintext_len + 1, sizeof(char));
    encryptMessage(plaintext, key, ciphertext);
    ciphertext_term = concatenate(ciphertext, MESSAGE_TERMINATOR);
    sendMessage(sock_fd, ciphertext_term);
    close(sock_fd);

    free(plaintext); plaintext = NULL;
    free(key); key = NULL;
    free(ciphertext); ciphertext = NULL;
    free(ciphertext_term); ciphertext_term = NULL;
    _exit(0);
}