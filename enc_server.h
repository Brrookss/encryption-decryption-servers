#ifndef ENC_SERVER_H
#define ENC_SERVER_H

#define ENC_AUTH_MESSAGE "$enc"
#define MAX_QUEUE_SIZE 10

char* appendMessageSeperator(char*);
int authenticate(int);
int connected(int);
int connectClient(int, struct sockaddr*, socklen_t*);
int connectSocket(int, struct sockaddr*);
char* encryptMessage(const char*, const char*, char*);
char* getAuthConfirmMessage(void);
char* getKey(const char*, char*);
int getKeyLength(const char*);
char* getPlaintext(const char*, char*);
int getPlaintextLength(const char*);
int getResponse(int, char*, int);
void handleConnection(int);
void initAddressStruct(struct sockaddr_in*, int);
int sendMessage(int, const char*);

#endif /* ENC_SERVER_H */