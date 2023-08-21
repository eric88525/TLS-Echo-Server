all:  myserver myclient mthread_server

CC = gcc

myserver: server.c
	$(CC) -Wall -o server server.c -L/usr/lib -lssl -lcrypto

myclient: client.c
	$(CC) -Wall -o client client.c -L/usr/lib -lssl -lcrypto

mthread_server: mthread_server.c
	$(CC) -Wall -o mserver mthread_server.c -L/usr/lib -lssl -lcrypto -lpthread

clean:
	rm server client mserver