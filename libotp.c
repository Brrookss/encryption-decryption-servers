#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "libotp.h"

/**
 * Determines if correct authentication message is received from client
 */
int authenticate(int sock_fd, char* message) {
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

    if (strcmp(buffer, message) != 0) {
        fprintf(stderr, "authenticate(): Failed to authenticate client\n");
        return 0;
    }
    return 1;
}

/**
 * Determines if authentication confirmation message is received from server
 */
int authenticated(int sock_fd, char* auth) {
    char buffer[AUTH_BUFFER_SIZE];
    int i, received;

    memset(buffer, '\0', sizeof(buffer));
    i = 0;
    while ((received = recv(sock_fd, &buffer[i], 1, 0)) > 0 && strcmp(&buffer[i], MESSAGE_SEPERATOR) != 0 && strcmp(&buffer[i], MESSAGE_TERMINATOR) != 0)
        i += received;
    buffer[i] = '\0';
    
    if (received == -1) {
        perror("recv()");
        return 0;
    }

    if (strcmp(buffer, ACK) != 0) {
        fprintf(stderr, "authenticated(): Failed to be authenticated by server\n");
        return 0;
    }
    return 1;
}

/**
 * Determines if string is composed exclusively of characters in the allowed character set
 */
int allowedChars(char* s) {
    int *allowed, i, num, ret;

    allowed = createAllowedCharsHash();
    i = 0;
    ret = 1;
    while (s[i] && ret) {
        num = s[i++];
        if (!allowed[num]) {
            fprintf(stderr, "allowedChars(): Invalid character(s)\n");
            ret = 0;
        }
    }
    free(allowed);
    allowed = NULL;
    return ret;
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
 * Creates a hash table representing the allowed characters where each bucket is
 * represented by the ASCII numeric representation. 1 represents the character
 * being part of the allowed character set; 0 represents the character being omitted
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
    char *buffer, seperator[] = "/";
    int len;

    len = strlen(dir) + strlen(seperator) + strlen(target);
    buffer = (char*)calloc(len + 1, sizeof(char));
    strcpy(buffer, dir);
    strcat(buffer, seperator);
    strcat(buffer, target);
    return buffer;
}

/**
 * Stores bytes from file pointed to by fd into dynamically sized buffer with the number of bytes read
 * determining its size. Last (non-null terminator) character is assumed to be a newline and is replaced
 * with a null terminator
 */
char* getFileData(int fd) {
    int i, bytes, size;
    char* buffer;

    size = DATA_BUFFER_SIZE;
    buffer = (char*)calloc(size, sizeof(char));
    i = 0;
    while ((bytes = read(fd, &buffer[i], 1)) > 0 && strcmp(&buffer[i], FILE_TERMINATOR) != 0) {
        i += bytes;
        if (reachedThreshold(i, size))
            buffer = resize(buffer, size *= 2);
    }
    buffer[i] = '\0';
    return buffer;
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
 * Gets text section of response message and stores in buffer
 */
char* getText(const char* response, char* buffer) {
    int i;

    i = strcspn(response, MESSAGE_SEPERATOR);
    strncpy(buffer, response, i);
    buffer[i + 1] = '\0';
    return buffer;
}

/**
 * Gets length of text section of response message
 */
int getTextLength(const char* response) {
    return strcspn(response, MESSAGE_SEPERATOR);
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
 * Determines validity of file descriptor
 */
int locatedFile(int fd) {
    if (fd < 0) {
        fprintf(stderr, "locatedFile(): File not found\n");
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

/**
 * Determines if s is at least as long as len
 */
int sufficientLength(const char* s, int len) {
    if (strlen(s) < len) {
        fprintf(stderr, "sufficientLength(): String is shorter than expected length\n");
        return 0;
    }
    return 1;
}