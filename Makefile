main:
	gcc -std=gnu99 -Wall -g -o enc_client enc_client.c
	gcc -std=gnu99 -Wall -g -o enc_server enc_server.c
	gcc -std=gnu99 -Wall -g -o keygen keygen.c

clean:
	rm -f enc_client
	rm -f enc_server
	rm -f keygen