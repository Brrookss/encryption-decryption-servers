# encryption-decryption servers

## Description

This is a series of programs that encrypt and decrypt text using sockets.

Specifically, the programs correspond to:
1. Encryption server
2. Decryption server
3. Key generation utility
4. Client A
5. Client B

Some functionalities include:
1. Concurrent servers:
    - Both servers support five concurrent socket connections through the use
    of child processes
2. Client authentication:
    - Encryption server verifies connection is with encryption client.
    Conversely, decryption server verifies connection is with decryption client
3. Encryption is accomplished using a technique similar to a one-time pad:
    - A combination of modular addition and a pseudorandom number generator is
    used

## Getting started

### Dependencies

- GNU Compiler Collection (GCC)

### Installing

1. Compile and create executables using Makefile via ```make```

### Executing programs

1. Start the encryption server listening on *enc_port* in the background:

```./enc_server enc_port &```

2. Start the decryption server listening on *dec_port* in the background:

```./dec_server dec_port &```

3. Create a *plaintext* file composed exclusively of characters in the allowed
character set (see the Notes section) to be encrypted:

```echo "HELLO WORLD" > plaintext```

4. Create the *key* file of *keylength* associated with the plaintext (see the
Notes section):

```keygen keylength > key```

5. Encrypt the *plaintext* using the *key* by connecting to the encryption
server listening on *enc_port* to be saved at *encryptedtext*:

```./enc_client plaintext key enc_port > encryptedtext```

6. Verify encryption:

```cat encryptedtext```

7. Using the *key*, decrypt *encryptedtext* by connecting to the decryption
server listening on *dec_port* to be saved at *decryptedtext*:

```./dec_client encryptedtext key dec_port > decryptedtext```

8. Verify decryption matches plaintext:

```cat decryptedtext```

## Notes

- The plaintext file to be encrypted must **only** contain the 26 capital
letters and the space character.

- The key must be **at least the same length** as the plaintext it is be used
on.

- It is recommended to use port numbers of at least 50000 to prevent conflicts.

## Authors

[Brooks Burns](https://github.com/Brrookss)