#ifndef __ENC_SERVER_H__
#define __ENC_SERVER_H__

char* encryptMessage(const char*, const char*, char*);
void handleConnection(int);

#endif /* __ENC_SERVER_H__ */