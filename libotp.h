#ifndef __LIBOTP_H__
#define __LIBOTP_H__

#include <netinet/in.h>
#include <sys/socket.h>

#define ACK "\6"
#define AUTH_BUFFER_SIZE 32
#define BUFFER_THRESHOLD 0.9
#define DATA_BUFFER_SIZE 2048
#define DEC_AUTH_MESSAGE "$dec"
#define ENC_AUTH_MESSAGE "$enc"
#define FILE_TERMINATOR "\n"
#define LOCALHOST "127.0.0.1"
#define MAX_QUEUE_SIZE 10
#define MESSAGE_SEPERATOR "\17"
#define MESSAGE_TERMINATOR "$"
#define NAK "\15"
#define NUM_ASCII_CHARS 128
#define PATH_BUFFER_SIZE 256

static const char ALLOWED_CHARS[] = { 'A', 'B', 'C', 'D', 'E',
                                      'F', 'G', 'H', 'I', 'J',
                                      'K', 'L', 'M', 'N', 'O',
                                      'P', 'Q', 'R', 'S', 'T',
                                      'U', 'V', 'W', 'X', 'Y',
                                      'Z', ' ' };

int authenticate(int, char*);
int authenticated(int, char*);
int allowedChars(char*);
char* concatenate(const char*, const char*);
int connected(int);
int connectClient(int, struct sockaddr*, socklen_t*);
int connectSocket(int, struct sockaddr*);
int* createAllowedCharsHash(void);
char* createPath(char*, char*);
char* getFileData(int);
int getFileDesc(char*, char*);
char* getKey(const char*, char*);
int getKeyLength(const char*);
char* getResponse(int);
char* getText(const char*, char*);
int getTextLength(const char*);
void initAddressStruct(struct sockaddr_in*, char*, int);
int locatedFile(int);
int makeSocketConnection(int, struct sockaddr*, int);
int reachedThreshold(int, int);
char* resize(char*, int);
int sendMessage(int, const char*);
int sufficientLength(const char*, int);

#endif /* __LIBOTP_H__ */