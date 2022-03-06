main:
	gcc -std=gnu99 -c libotp.c
	gcc -std=gnu99 -Wall -g -o dec_client dec_client.c libotp.o
	gcc -std=gnu99 -Wall -g -o dec_server dec_server.c libotp.o
	gcc -std=gnu99 -Wall -g -o enc_client enc_client.c libotp.o
	gcc -std=gnu99 -Wall -g -o enc_server enc_server.c libotp.o
	gcc -std=gnu99 -Wall -g -o keygen keygen.c libotp.o

clean:
	rm -f *.o
	rm -f dec_client
	rm -f dec_server
	rm -f enc_client
	rm -f enc_server
	rm -f libotp
	rm -f keygen