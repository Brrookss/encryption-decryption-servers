#ifndef CONSTANTS_H
#define CONSTANTS_H

#define ACK "\6"
#define AUTH_BUFFER_SIZE 32
#define BUFFER_THRESHOLD 0.9
#define DATA_BUFFER_SIZE 2048
#define LOCALHOST "127.0.0.1"
#define MESSAGE_SEPERATOR "\17"
#define MESSAGE_TERMINATOR "$"
#define NAK "\15"
#define NUM_ASCII_CHARS 128
#define PATH_BUFFER_SIZE 256

const char ALLOWED_CHARS[] = { 'A', 'B', 'C', 'D', 'E',
                               'F', 'G', 'H', 'I', 'J',
                               'K', 'L', 'M', 'N', 'O',
                               'P', 'Q', 'R', 'S', 'T',
                               'U', 'V', 'W', 'X', 'Y',
                               'Z', ' ' };

#endif /* CONSTANTS_H */