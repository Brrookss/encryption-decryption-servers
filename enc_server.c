#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

    int sock_fd, client_sock_fd;
    struct sockaddr_in address, client_address;
    socklen_t client_address_size;
    pid_t pid;

    initAddressStruct(&address, atoi(argv[1]));
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    client_address_size = sizeof(client_address);

    if (!connectSocket(sock_fd, (struct sockaddr*)&address))
        exit(2);
    
    while (1) {
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
                    break;
            }
        }
    }
    close(sock_fd);
    exit(0);
}

/**
 * Creates a new character array after appending message seperator; passed array is deallocated
 */
char* appendMessageSeperator(char* message) {
    char* buffer;
    int len;

    len = strlen(message) + strlen(MESSAGE_SEPERATOR);
    buffer = (char*)calloc(len + 1, sizeof(char));
    strcpy(buffer, message);
    strcat(buffer, MESSAGE_SEPERATOR);

    free(message);
    message = NULL;
    return buffer;
}

/**
 * Determines if correct authentication message is received from client
 */
int authenticate(int sock_fd) {
    char buffer[256];
    int received;

    memset(buffer, '\0', sizeof(buffer));
    received = recv(sock_fd, &buffer, sizeof(buffer) - 1, 0);
    if (received == -1) {
        perror("recv()");
        return 0;
    }

    buffer[strcspn(buffer, MESSAGE_SEPERATOR)] = '\0';
    if (strcmp(buffer, ENC_AUTH_MESSAGE) != 0) {
        fprintf(stderr, "authenticate(): Failed to authenticate client\n");
        return 0;
    }
    return 1;
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
 * Gets null-terminated authentication confirmation message to be sent to client
 */
char* getAuthConfirmMessage(void) {
    char* buffer;

    buffer = (char*)calloc(strlen(ACK) + 1, sizeof(char));
    strcpy(buffer, ACK);
    return buffer;
}

/**
 * Gets key section of response message and stores in buffer
 */
char* getKey(const char* response, char* buffer) {
    int i, start;

    start = strcspn(response, MESSAGE_SEPERATOR) + 1;
    i = 0;
    while (strcmp(&response[start], MESSAGE_SEPERATOR) != 0)
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
    while (strcmp(&response[start++], MESSAGE_SEPERATOR) != 0)
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
int getResponse(int sock_fd, char* buffer, int size) {
    int received;

    received = recv(sock_fd, buffer, size - 1, 0);
    if (received == -1)
        perror("recv()");
    return received;
}

/**
 * Client is first authenticated before getting response message composed of plaintext and key to be used
 * for encryption; resulting encrypted message is sent back to client and socket connection is closed
 */
void handleConnection(int sock_fd) {
    char *auth, *response, *plaintext, *key, *encrypted;
    int plaintext_len, key_len;

    if (!authenticate(sock_fd)) {
        sendMessage(sock_fd, NAK);
        close(sock_fd);
        _exit(2);
    }
    auth = appendMessageSeperator(getAuthConfirmMessage());
    sendMessage(sock_fd, auth);

    response = (char*)calloc(MESSAGE_BUFFER_SIZE, sizeof(char));
    getResponse(sock_fd, response, MESSAGE_BUFFER_SIZE * sizeof(char));

    plaintext_len = getPlaintextLength(response);
    plaintext = (char*)calloc(plaintext_len + 1, sizeof(char));
    getPlaintext(response, plaintext);
    
    key_len = getKeyLength(response);
    key = (char*)calloc(key_len + 1, sizeof(char));
    getKey(response, key);

    encrypted = (char*)calloc(plaintext_len + 1, sizeof(char));
    encrypted = encryptMessage(plaintext, key, encrypted);
    sendMessage(sock_fd, encrypted);
    close(sock_fd);

    free(plaintext); plaintext = NULL;
    free(key); key = NULL;
    free(encrypted); encrypted = NULL;
    _exit(0);
}

/**
 * Initializes a sockaddr_in structure to be used in the socket connection; localhost is assumed
 */
void initAddressStruct(struct sockaddr_in* address, int port) {
    memset((char*)address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    inet_aton("127.0.0.1", &address->sin_addr);
}

/**
 * Attempts to send message over the connection determined by the socket file descriptor
 */
int sendMessage(int sock_fd, const char* message) {
    int sent;
    
    sent = send(sock_fd, message, strlen(message), 0);
    if (sent == -1) {
        perror("send()");
        return 0;
    } else if (sent < strlen(message)) {
        fprintf(stderr, "sendMessage(): Incomplete message sent\n");
        return 0;
    }
    return 1;
}