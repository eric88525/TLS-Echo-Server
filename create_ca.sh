#!bin/bash

mkdir certificates
cd certificates

# Create a CA certificate
openssl genpkey -algorithm RSA -out ca-private.key
openssl req -new -key ca-private.key -x509 -days 365 -out ca-cert.pem


# Create a server certificate
openssl genpkey -algorithm RSA -out server-private.key
openssl req -new -key server-private.key -out server.csr

# Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-private.key -CAcreateserial -out server-cert.pem -days 365


# Create a client certificate
openssl genpkey -algorithm RSA -out client-private.key
openssl req -new -key client-private.key -out client.csr

# Sign the client certificate with the CA
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-private.key -CAcreateserial -out client-cert.pem -days 365