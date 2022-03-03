#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "constants.h"
#include "enc_client.h"

/**
 * Driver function for encryption client. Arguments are first verified before an attempt to
 * connect to the server is made. Once connection is authenticated, plaintext and key are sent
 * to be encrypted. The resulting ciphertext is then sent to stdout
 */
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <plaintext file> <key file> <port>\n", argv[0]);
        exit(1);
    }

    char *cwd, *plaintext, *key, *auth, *msg, *encrypted;
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

    plaintext = (char*)calloc(PATH_BUFFER_SIZE, sizeof(char));
    getData(plaintext_fd, plaintext, PATH_BUFFER_SIZE);
    key = (char*)calloc(PATH_BUFFER_SIZE, sizeof(char));
    getData(key_fd, key, PATH_BUFFER_SIZE);

    if (!allowedChars(plaintext) || !sufficientKey(key, strlen(plaintext))) {
        free(plaintext); plaintext = NULL;
        free(key); key = NULL;
        exit(1);
    }

    initAddressStruct(&server_address, atoi(argv[3]));
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    auth = appendMessageTerm(getAuthMessage());

    if (!makeSocketConnection(sock_fd, (struct sockaddr*)&server_address, sizeof(server_address)) || !sendMessage(sock_fd, auth) || !authenticated(sock_fd)) {
        free(plaintext); plaintext = NULL;
        free(key); key = NULL;
        free(auth); auth = NULL;
        exit(2);
    }

    plaintext = appendMessageTerm(plaintext);
    key = appendMessageTerm(key);
    msg = concatenate(plaintext, key);
    sendMessage(sock_fd, msg);

    encrypted = (char*)calloc(strlen(plaintext), sizeof(char));
    getResponse(sock_fd, encrypted, sizeof(encrypted));
    close(sock_fd);
    puts(encrypted);

    free(plaintext); plaintext = NULL;
    free(key); key = NULL;
    free(msg); msg = NULL;
    free(auth); auth = NULL;
    free(encrypted); encrypted = NULL;
    exit(0);
}

/**
 * Determines if string is composed exclusively of characters in the allowed character set
 */
int allowedChars(char* s) {
    int *allowed, i, num, stat;

    allowed = createAllowedCharsHash();
    i = 0;
    stat = 1;

    while (s[i] != '\0' && stat == 1) {
        num = s[i++];
        if (!allowed[num]) {
            fprintf(stderr, "allowedChars()\n");
            stat = 0;
        }
    }
    free(allowed);
    allowed = NULL;
    return stat;
}

/**
 * Creates a new character array after appending message terminator. Passed
 * array is deallocated
 */
char* appendMessageTerm(char* msg) {
    char* buffer;

    buffer = (char*)calloc(strlen(msg) + strlen(MESSAGE_TERM) + 1, sizeof(char));
    strcpy(buffer, msg);
    strcat(buffer, MESSAGE_TERM);

    free(msg);
    msg = NULL;
    return buffer;
}

/**
 * Determines if authentication message was received
 */
int authenticated(int sock_fd) {
    char buffer[256];
    int received;

    memset(buffer, '\0', sizeof(buffer));
    received = recv(sock_fd, &buffer, sizeof(buffer), 0);
    if (received == -1) {
        perror("recv()");
        return 0;
    }

    buffer[strcspn(buffer, MESSAGE_TERM)] = '\0';
    if (strcmp(buffer, ENC_AUTH_MESSAGE) != 0) {
        fprintf(stderr, "authenticated()\n");
        return 0;
    }
    return 1;
}

/**
 * Concatenates two character arrays
 */
char* concatenate(const char* s1, const char* s2) {
    int len;
    char* buffer;

    len = strlen(s1) + strlen(s2) + 1;
    buffer = (char*)calloc(len, sizeof(char));
    strcpy(buffer, s1);
    strcat(buffer, s2);
    return buffer;
}

/**
 * Creates a hash table representing the allowed characters where each bucket is
 * represented by the ASCII numeric representation. 1 represents the character
 * being part of the allowed character set, whereas 0 represents the character being omitted
 */
int* createAllowedCharsHash(void) {
    int *hash, i, num;

    hash = (int*)calloc(NUM_ASCII_CHARS, sizeof(int));
    i = 0;
    while (i < sizeof(ALLOWED_CHARS)) {
        num = ALLOWED_CHARS[i++];
        hash[num] = 1;
    }
    return hash;
}

/**
 * Creates a character array representing the absolute path to target in directory dir
 */
char* createPath(char* dir, char* target) {
    if (dir == NULL || target == NULL) {
        fprintf(stderr, "createPath()\n");
        return NULL;
    }

    char *buffer, fwd_slash[] = "/";
    int len;

    len = strlen(dir) + strlen(target) + strlen(fwd_slash);
    buffer = (char*)calloc(len + 1, sizeof(char));
    strcpy(buffer, dir);
    strcat(buffer, fwd_slash);
    strcat(buffer, target);
    return buffer;
}

/**
 * Gets message to be sent to the server for authentication
 */
char* getAuthMessage(void) {
    char* buffer;

    buffer = (char*)calloc(strlen(ENC_AUTH_MESSAGE) + 1, sizeof(char));
    strcpy(buffer, ENC_AUTH_MESSAGE);
    return buffer;
}

/**
 * Stores bytes from file pointed to by fd into buffer with the number of bytes read
 * determined by size. Last (non-null terminator) character is assumed to b a newline
 * and is replaced with a null terminator
 */
int getData(int fd, char* buffer, int size) {
    int bytes;

    bytes = read(fd, buffer, size);
    buffer[bytes - 1] = '\0';
    return bytes;
}

/**
 * Gets file descriptor for target in the directory dir
 */
int getFileDesc(char* dir, char* target) {
    char *abs;
    int fd;

    abs = createPath(dir, target);
    fd = open(abs, O_RDONLY);
    
    free(abs);
    abs = NULL;
    return fd;
}

/**
 * Attempts to store response in buffer using the connection determined by the socket file descriptor
 */
int getResponse(int sock_fd, char* buffer, int size) {
    int received, i;

    received = i = 0;
    while ((received = recv(sock_fd, &buffer[i], sizeof(buffer) - i, 0)) > 0)
        i += received;

    if (received == -1)
        perror("recv()");
    return received;
}

/**
 * Initializes a sockaddr_in structure to be used in the socket connection. Host
 * is assumed to be localhost, so DNS lookup is omitted
 * Code is based off example from:
 * https://canvas.oregonstate.edu/courses/1884946/pages/exploration-client-server-communication-via-sockets?module_item_id=21836005
 */
void initAddressStruct(struct sockaddr_in* address, int port) {
    memset((char*)address, '\0', sizeof(*address));

    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    inet_aton("127.0.0.1", &address->sin_addr);
}

/**
 * Determines validity of file descriptor
 */
int locatedFile(int fd) {
    if (fd == -1) {
        fprintf(stderr, "located()\n");
        return 0;
    }
    return 1;
}

/**
 * Attempts to make a connection based on the socket file descriptor
 */
int makeSocketConnection(int sock_fd, struct sockaddr* address, int address_size) {
    if (connect(sock_fd, address, address_size) < 0) {
        perror("connect()");
        return 0;
    }
    return 1;
}

/**
 * Attempts to send message over the connection determined by the socket file descriptor
 */
int sendMessage(int sock_fd, const char* msg) {
    int sent, i;
    
    sent = i = 0;
    while ((sent = send(sock_fd, &msg[i], sizeof(msg) - i, 0)) != -1 && sent < sizeof(msg))
        i += sent;

    if (sent == -1) {
        perror("send()");
        return 0;
    } else if (sent < sizeof(msg)) {
        fprintf(stderr, "sendMessage()\n");
        return 0;
    }
    return 1;
}

/**
 * Determines if key is composed exclusively of characters in the allowed character set
 * and is at least as long as len
 */
int sufficientKey(char* key, int len) {
    if (!allowedChars(key) || strlen(key) < len) {
        fprintf(stderr, "sufficientKey()\n");
        return 0;
    }
    return 1;
}