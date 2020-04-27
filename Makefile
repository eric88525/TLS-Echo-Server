all:  myserver myclient

CC = gcc

myserver: myServer.c
	$(CC) -Wall -o myServer myServer.c -L/usr/lib -lssl -lcrypto	

myclient: myClient.c
	$(CC) -Wall -o myClient myClient.c -L/usr/lib -lssl -lcrypto