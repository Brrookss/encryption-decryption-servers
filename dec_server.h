#ifndef __DEC_SERVER_H__
#define __DEC_SERVER_H__

char* decryptMessage(const char*, const char*, char*);
void handleConnection(int);

#endif /* __DEC_SERVER_H__ */