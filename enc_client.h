#ifndef ENC_CLIENT_H
#define ENC_CLIENT_H

#define ENC_AUTH_MESSAGE "$enc"
#define FILE_TERMINATOR "\n"

int allowedChars(char*);
int authenticated(int, char*);
char* concatenate(const char*, const char*);
int* createAllowedCharsHash(void);
char* createPath(char*, char*);
char* getFileData(int);
int getFileDesc(char*, char*);
char* getResponse(int);
void initAddressStruct(struct sockaddr_in*, char*, int);
int locatedFile(int);
int makeSocketConnection(int, struct sockaddr*, int);
int reachedThreshold(int, int);
char* resize(char*, int);
int sendMessage(int, const char*);
int sufficientLength(const char*, int);

#endif /* ENC_CLIENT_H */