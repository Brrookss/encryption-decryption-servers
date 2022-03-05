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
 * Driver for encryption client. Arguments are first verified before an attempt to connect 
 * to the server is made. Once connection is authenticated, plaintext and key are sent to
 * be encrypted. The resulting ciphertext is then sent to stdout
 */
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <plaintext file> <key file> <port>\n", argv[0]);
        exit(1);
    }

    char *cwd, *plaintext, *plaintext_sep, *key, *auth, *message, *message_term, *encrypted;
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

    initAddressStruct(&server_address, atoi(argv[3]));
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

    encrypted = getResponse(sock_fd);
    close(sock_fd);
    puts(encrypted);

    free(plaintext); plaintext = NULL;
    free(plaintext_sep); plaintext_sep = NULL;
    free(key); key = NULL;
    free(message); message = NULL;
    free(message_term); message_term = NULL;
    free(auth); auth = NULL;
    free(encrypted); encrypted = NULL;
    exit(0);
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
 * Concatenates two character arrays in the order in which they are passed
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
 * Initializes a sockaddr_in structure to be used in the socket connection; localhost is assumed
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
 * Determines if size is beyond target threshold
 */
int reachedThreshold(int size, int target) {
    return size > target * BUFFER_THRESHOLD;
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