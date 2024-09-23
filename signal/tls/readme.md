# Creating domain.crt and domain.key
1. openssl req -newkey rsa:2048 -keyout domain.key -out domain.csr -nodes
2. openssl req -x509 -sha256 -days 9999 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt -nodes
3. Create domain.txt
4. openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 9999 -CAcreateserial -extfile domain.txt
5. openssl x509 -text -noout -in domain.crt
https://github.com/hyperium/tonic/blob/master/examples/src/tls/server.rs

# Root
openssl genrsa -out rootCA.key 2048

openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt \
    -subj "/C=US/ST=California/L=SanFrancisco/O=MyCompany/OU=IT/CN=MyRootCA"

# Server
openssl genrsa -out server.key 2048

openssl req -new -key server.key -out server.csr -config server_cert_ext.cnf

openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server_cert_ext.cnf -extensions v3_req


# Client
openssl genrsa -out client.key 2048

openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=California/L=SanFrancisco/O=MyCompany/OU=IT/CN=client"

openssl x509 -req -in client.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
    -out client.crt -days 3650 -sha256

# Verify
openssl verify -CAfile rootCA.crt server.crt

openssl verify -CAfile rootCA.crt client.crt








# server.pem server.key

openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.pem




openssl req -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr
openssl x509 -signkey localhost.key -in localhost.csr -req -days 365 -out localhost.crt
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt

# Server
openssl genrsa 2048 > ca-key.pem

openssl req -new -x509 -nodes -days 365000 \
-key ca-key.pem \
-out ca-cert.pem

openssl req -newkey rsa:2048 -nodes -days 365000 \
-keyout server-key.pem \
-out server-req.pem

openssl x509 -req -days 365000 -set_serial 01 \
-in server-req.pem \
-out server-cert.pem \
-CA ca-cert.pem \
-CAkey ca-key.pem

# Client
