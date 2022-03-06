#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "constants.h"
#include "enc_server.h"

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
        } while (num_processes > 5);

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
 * Determines if correct authentication message is received from client
 */
int authenticate(int sock_fd) {
    char buffer[AUTH_BUFFER_SIZE];
    int i, received;

    memset(buffer, '\0', sizeof(buffer));
    i = 0;
    while ((received = recv(sock_fd, &buffer[i], 1, 0)) > 0 && strcmp(&buffer[i], MESSAGE_SEPERATOR) != 0)
        i += received;
    buffer[i] = '\0';
    
    if (received == -1) {
        perror("recv()");
        return 0;
    }

    if (strcmp(buffer, ENC_AUTH_MESSAGE) != 0) {
        fprintf(stderr, "authenticate(): Failed to authenticate client\n");
        return 0;
    }
    return 1;
}

/**
 * Concatenates two character arrays in the order in which they are passed
 */
char* concatenate(const char* s1, const char* s2) {
    int len;
    char* buffer;

    len = strlen(s1) + strlen(s2);
    buffer = (char*)calloc(len + 1, sizeof(char));
    strcpy(buffer, s1);
    strcat(buffer, s2);
    return buffer;
}

/**
 * Determines if socket connection attempt is succesful
 */
int connected(int sock_fd) {
    return sock_fd >= 0;
}

/**
 * Attempts to accept client socket connection
 */
int connectClient(int sock_fd, struct sockaddr* address, socklen_t* client_size) {
    int client_sock_fd;

    client_sock_fd = accept(sock_fd, address, client_size);
    if (!connected(client_sock_fd))
        perror("accept()");
    return client_sock_fd;
}

/**
 * Attempts to start up server by binding and listening at socket determined by the socket file descriptor
 */
int connectSocket(int sock_fd, struct sockaddr* address) {
    if (bind(sock_fd, address, sizeof(*address)) < 0) {
        perror("bind()");
        return 0;
    } else if (listen(sock_fd, MAX_QUEUE_SIZE) < 0) {
        perror("listen()");
        return 0;
    }
    return 1;
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
 * Gets key section of response message and stores in buffer
 */
char* getKey(const char* response, char* buffer) {
    int i, start;

    start = strcspn(response, MESSAGE_SEPERATOR) + 1;
    i = 0;
    while (response[start])
        buffer[i++] = response[start++];
    buffer[i] = '\0';
    return buffer;
}

/**
 * Gets length of key section of response message
 */
int getKeyLength(const char* response) {
    int len, start;

    start = strcspn(response, MESSAGE_SEPERATOR) + 1;
    len = 0;
    while (response[start++])
        len++;
    return len;
}

/**
 * Gets plaintext section of response message and stores in buffer
 */
char* getPlaintext(const char* response, char* buffer) {
    int i;

    i = strcspn(response, MESSAGE_SEPERATOR);
    strncpy(buffer, response, i);
    buffer[i + 1] = '\0';
    return buffer;
}

/**
 * Gets length of plaintext section of response message
 */
int getPlaintextLength(const char* response) {
    return strcspn(response, MESSAGE_SEPERATOR);
}

/**
 * Attempts to store response message in buffer using the connection determined by the socket file descriptor
 */
char* getResponse(int sock_fd) {
    int i, bytes, size;
    char* buffer;

    size = DATA_BUFFER_SIZE;
    buffer = (char*)calloc(size, sizeof(char));
    i = 0;
    while ((bytes = recv(sock_fd, &buffer[i], 1, 0)) > 0 && strcmp(&buffer[i], MESSAGE_TERMINATOR) != 0) {
        i += bytes;
        if (reachedThreshold(i, size))
            buffer = resize(buffer, size *= 2);
    }
    buffer[i] = '\0';

    if (bytes == -1)
        perror("recv()");
    return buffer;
}

/**
 * Client is first authenticated before getting response message composed of plaintext and key to be used
 * for encryption; resulting encrypted message is sent back to client and socket connection is closed
 */
void handleConnection(int sock_fd) {
    char *auth, *response, *plaintext, *key, *encrypted, *encrypted_term;
    int plaintext_len, key_len;

    if (!authenticate(sock_fd)) {
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
    plaintext_len = getPlaintextLength(response);
    plaintext = (char*)calloc(plaintext_len + 1, sizeof(char));
    getPlaintext(response, plaintext);

    key_len = getKeyLength(response);
    key = (char*)calloc(key_len + 1, sizeof(char));
    getKey(response, key);

    encrypted = (char*)calloc(plaintext_len + 1, sizeof(char));
    encryptMessage(plaintext, key, encrypted);
    encrypted_term = concatenate(encrypted, MESSAGE_TERMINATOR);
    sendMessage(sock_fd, encrypted_term);
    close(sock_fd);

    free(plaintext); plaintext = NULL;
    free(key); key = NULL;
    free(encrypted); encrypted = NULL;
    free(encrypted_term); encrypted_term = NULL;
    _exit(0);
}

/**
 * Initializes a sockaddr_in structure to be used in the socket connection
 */
void initAddressStruct(struct sockaddr_in* address, char* host, int port) {
    memset((char*)address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    inet_aton(host, &address->sin_addr);
}

/**
 * Determines if size is at or beyond target threshold
 */
int reachedThreshold(int size, int target) {
    return size >= target * BUFFER_THRESHOLD;
}

/**
 * Creates array of new size after copying old data; passed array is deallocated
 */
char* resize(char* old, int size) {
    char* new;

    new = (char*)calloc(size, sizeof(char));
    strcpy(new, old);

    free(old);
    old = NULL;
    return new;
}

/**
 * Attempts to send message over the connection determined by the socket file descriptor
 */
int sendMessage(int sock_fd, const char* message) {
    int i, sent;

    i = 0;
    while (message[i] && (sent = send(sock_fd, &message[i], 1, 0)) > 0)
        i += sent;
    
    if (sent == -1) {
        perror("send()");
        return 0;
    } else if (i < strlen(message)) {
        fprintf(stderr, "sendMessage(): Incomplete message sent\n");
        return 0;
    }
    return 1;
}