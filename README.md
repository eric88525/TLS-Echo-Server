# TLS Echo Server

A simple TLS-based echo server and client for demonstrating secure communication.

## Demo

![](/demo.png)

## Features

**Server**

The server receives messages from clients and echoes them back.

**Client**

The client sends messages to the server until the user inputs `exit`.

**Compilation**

To compile the server, client, and multithread server executables, simply run:
```
make
```

**Create Certificates**
```
sh create_ca.sh
```

## Execution

**Run Server**

To run the server, use the following command:

```
./server {port}
```

**Run Multithread Server**

For the multithreaded server version, execute:
```
./mserver {port}
```
**Run Client**

To launch the client, execute:

```
./client {port}
```
