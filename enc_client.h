#ifndef ENC_CLIENT_H
#define ENC_CLIENT_H

#define ENC_AUTH_MESSAGE "$enc"
#define MESSAGE_TERM "\n"

int allowedChars(char*);
char* appendMessageTerm(char*);
int authenticated(int);
char* concatenate(const char*, const char*);
int* createAllowedCharsHash(void);
char* createPath(char*, char*);
char* getAuthMessage(void);
int getData(int, char*, int);
int getFileDesc(char*, char*);
int getResponse(int, char*, int);
void initAddressStruct(struct sockaddr_in*, int);
int locatedFile(int);
int makeSocketConnection(int, struct sockaddr*, int);
int sendMessage(int, const char*);
int sufficientKey(char*, int);

#endif /* ENC_CLIENT_H */