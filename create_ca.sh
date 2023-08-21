#!bin/bash

# Create a CA certificate
mkdir ca
openssl genpkey -algorithm RSA -out ca/ca-private.key
openssl req -new -key ca-private.key -x509 -days 365 -out ca-cert.pem


# Create a server certificate
mkdir server
openssl genpkey -algorithm RSA -out server/server-private.key
openssl req -new -key server/server-private.key -out server/server.csr

# Sign the server certificate with the CA
openssl x509 -req -in server/server.csr -CA ca/ca-cert.pem -CAkey ca/ca-private.key -CAcreateserial -out server/server-cert.pem -days 365


# Create a client certificate
mkdir client
openssl genpkey -algorithm RSA -out client/client-private.key
openssl req -new -key client/client-private.key -out client/client.csr

# Sign the client certificate with the CA
openssl x509 -req -in client/client.csr -CA ca/ca-cert.pem -CAkey ca/ca-private.key -CAcreateserial -out client/client-cert.pem -days 365